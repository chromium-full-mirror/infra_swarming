# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Integration with webapp2."""

import json
import logging
import os
import webapp2

from google.appengine.api import oauth
from google.appengine.api import users

from . import api
from . import model
from . import tokens

__all__ = [
  'AuthenticatingHandler',
  'AuthenticationMethod',
  'configure',
  'CookieAuthentication',
  'OAuthAuthentication',
  'ServiceToServiceAuthentication',
]


class XSRFToken(tokens.Token):
  """XSRF token parameters."""
  kind = 'xsrf_token'
  expiration_sec = 2 * 3600
  secret_key = api.SecretKey('xsrf_token', scope='local')


class AuthenticatingHandlerMetaclass(type):
  """Ensures that 'get', 'post', etc. are marked with @require or @public."""

  def __new__(cls, name, bases, attributes):
    for method in webapp2.WSGIApplication.allowed_methods:
      func = attributes.get(method.lower())
      if func and callable(func) and not api.is_decorated(func):
        raise AssertionError(
            'Method \'%s\' of \'%s\' is not protected by @require or @public '
            'decorator' % (method.lower(), name))
    return type.__new__(cls, name, bases, attributes)


class AuthenticatingHandler(webapp2.RequestHandler):
  """Base class for request handlers that use ACL system."""

  # Checks that all 'get', 'post', etc. are marked with @require or @public.
  __metaclass__ = AuthenticatingHandlerMetaclass

  # List of HTTP methods that trigger XSRF token validation.
  xsrf_token_enforce_on = ('DELETE', 'POST', 'PUT')
  # Header to use when searching for XSRF token.
  xsrf_token_header = 'X-XSRF-Token'
  # Request parameter (GET or POST) to use when searching for XSRF token.
  xsrf_token_request_param = 'xsrf_token'
  # Embedded data extracted from current xsrf_token.
  xsrf_token_data = None

  def dispatch(self):
    """Extracts and verifies Identity."""
    # Extract Identity, check credentials.
    identity = model.Anonymous
    is_admin = False
    for method_cls in _auth_method_classes:
      if method_cls.is_applicable(self.request):
        try:
          identity, is_admin = method_cls.authenticate(self.request)
          assert isinstance(identity, model.Identity)
          assert is_admin in (True, False)
          assert not is_admin or (is_admin and identity.is_user)
          break
        except api.AuthenticationError as err:
          logging.error('Authentication error.\n%s', err)
          self.authentication_error(err)
          return

    # Successfully extracted and validated an identity, put it in the cache.
    api.get_request_cache().set_current_identity(identity, is_admin)

    try:
      # Verify XSRF token if required.
      self.xsrf_token_data = {}
      if self.request.method in self.xsrf_token_enforce_on:
        self.xsrf_token_data = self.verify_xsrf_token()

      # All other ACL checks will be performed by corresponding handlers
      # manually or via '@required' decorator.
      return super(AuthenticatingHandler, self).dispatch()
    except api.AuthorizationError as err:
      logging.error('Authorization error.\n%s', err)
      self.authorization_error(err)

  def generate_xsrf_token(self, xsrf_token_data=None):
    """Returns new XSRF token that embeds |xsrf_token_data|."""
    return XSRFToken.generate(
        api.get_current_identity().to_bytes(), xsrf_token_data)

  def verify_xsrf_token(self):
    """Ensures XSRF token is correct, extracts |xsrf_token_data|.

    Raises AuthorizationError if token is missing or incorrect.
    """
    # Get token value from header or request parameter.
    token = None
    if self.xsrf_token_header:
      token = self.request.headers.get(self.xsrf_token_header)
    if not token and self.xsrf_token_request_param:
      token = self.request.get(self.xsrf_token_request_param)
    if not token:
      raise api.AuthorizationError('XSRF token is missing')
    # And check that it was generated for same identity.
    try:
      if isinstance(token, unicode):
        token = token.encode('ascii')
      return XSRFToken.validate(token, api.get_current_identity().to_bytes())
    except tokens.InvalidTokenError as err:
      raise api.AuthorizationError(str(err))

  def authentication_error(self, error):
    """Called when authentication fails.

    Authentication error means that some credentials are provided but they are
    invalid. If no credentials provided at all, no authentication is attempted
    and current identity is set to 'anonymous:anonymous'.

    Args:
      error: instance of AuthenticationError subclass.
    """
    self.abort(401, detail=str(error))

  def authorization_error(self, error):
    """Called when authentication succeeds, but access is denied.

    Called whenever request handler raises AuthorizationError exception.
    In particular this exception is raised by method decorated with @require if
    current identity doesn't have required permission.

    Args:
      error: instance of AuthorizationError subclass.
    """
    self.abort(403, detail=str(error))


class AuthenticationMethod(object):
  """Given Request can extract Identity information from it.

  Base class for concrete authentication methods. Given a list of authentication
  methods (as a list of subclasses of AuthenticationMethod),
  AuthenticatingHandler will try to apply them sequentially one by one by
  calling 'cls.is_applicable' until it returns True for some class.

  This class's 'authenticate' will then by used to extract identity
  from a request.
  """

  @classmethod
  def is_applicable(cls, request):
    """Returns True if this method can be used with given request."""
    raise NotImplementedError()

  @classmethod
  def authenticate(cls, request):
    """Returns (Identity associated with the request, is_admin).

    Will be called only if is_applicable is True for same request.

    Raises AuthenticationError if credentials are invalid.
    """
    raise NotImplementedError()


class CookieAuthentication(AuthenticationMethod):
  """AppEngine cookie based authentication."""

  @classmethod
  def is_applicable(cls, request):
    return bool(users.get_current_user())

  @classmethod
  def authenticate(cls, request):
    email = users.get_current_user().email()
    try:
      identity = model.Identity(model.IDENTITY_USER, email)
    except ValueError:
      raise api.AuthenticationError('Invalid email format: %s' % email)
    return identity, users.is_current_user_admin()


class OAuthAuthentication(AuthenticationMethod):
  """OAuth2 based authentication."""

  # OAuth2 scope token should have.
  oauth_scope = 'https://www.googleapis.com/auth/userinfo.email'

  @classmethod
  def is_applicable(cls, request):
    # api.oauth stub on dev server is useless, oauth.get_client_id() always
    # returns some phony value even if 'Authorization' header is not set.
    if 'Dev' in os.environ.get('SERVER_SOFTWARE', ''):
      return False
    try:
      return bool(oauth.get_client_id(cls.oauth_scope))
    except oauth.Error:
      return False

  @classmethod
  def authenticate(cls, request):
    auth_db = api.get_request_auth_db()
    client_id = oauth.get_client_id(cls.oauth_scope)
    if not auth_db.is_allowed_oauth_client_id(client_id):
      raise api.AuthenticationError('Invalid OAuth client_id: %s' % client_id)
    email = oauth.get_current_user(cls.oauth_scope).email()
    try:
      identity = model.Identity(model.IDENTITY_USER, email)
    except ValueError:
      raise api.AuthenticationError('Invalid email format: %s' % email)
    return identity, oauth.is_current_user_admin(cls.oauth_scope)


class ServiceToServiceAuthentication(AuthenticationMethod):
  """Used for AppEngine <-> AppEngine communication.

  Relies on X-Appengine-Inbound-Appid header set by AppEngine itself.
  """

  @classmethod
  def is_applicable(cls, request):
    return bool(request.headers.get('X-Appengine-Inbound-Appid', None))

  @classmethod
  def authenticate(cls, request):
    app_id = request.headers.get('X-Appengine-Inbound-Appid')
    try:
      identity = model.Identity(model.IDENTITY_SERVICE, app_id)
    except ValueError:
      raise api.AuthenticationError('Invalid app_id format: %s' % app_id)
    return identity, False


################################################################################
## Authentication methods configuration.


# Global list of default AuthenticationMethod classes to use for a request.
# Can be overridden by call to 'configure'. Order is important!
_auth_method_classes = [
  ServiceToServiceAuthentication,
  CookieAuthentication,
  OAuthAuthentication,
]


def configure(auth_methods):
  """Global library configuration."""
  global _auth_method_classes
  assert all(issubclass(cls, AuthenticationMethod) for cls in auth_methods)
  _auth_method_classes = list(auth_methods)
