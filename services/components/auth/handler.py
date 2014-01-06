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
  'XSRFToken', 'AuthenticatingHandler', 'AuthenticationMethod',
  'CookieAuthentication', 'OAuthAuthentication', 'bootstrap',
]


# OAuth2 service scope to use for authentication.
EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'


# Request header a client can use for XSRF token.
XSRF_TOKEN_HEADER = 'X-XSRF-Token'
# GET or POST parameters a client can use for XSRF token.
XSRF_TOKEN_REQUEST_PARAM = 'xsrf_token'


class XSRFToken(tokens.Token):
  """XSRF token generation parameters."""
  kind = 'xsrf'
  expiration_sec = 2 * 3600
  secret_key = api.SecretKey('xsrf_token', 'local')


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

  # List of HTTP methods that require valid XSRF token.
  enforce_xsrf_token = ('DELETE', 'POST', 'PUT')

  def dispatch(self):
    """Extracts and verifies Identity."""
    # Perform some initial checks before doing anything more involved.
    self.validate_request_format()

    # Extract Identity, check credentials.
    identity = model.Anonymous
    is_admin = False
    for method_cls in _authenticators:
      if method_cls.is_applicable(self.request):
        try:
          identity, is_admin = method_cls.authenticate(self.request)
          assert isinstance(identity, model.Identity)
          assert is_admin in (True, False)
          break
        except api.AuthenticationError as err:
          logging.error('Authentication error.\n%s', err)
          self.authentication_error(err)
          return

    # Successfully extracted and validated an identity, put it in the cache.
    api.get_request_cache().set_current_identity(identity, is_admin)

    try:
      # Verify XSRF token if required.
      if (method_cls.requires_xsrf_token and
          self.request.method in self.enforce_xsrf_token):
        self.verify_xsrf_token()

      # All other ACL checks will be performed by corresponding handlers
      # manually or via 'required' decorator.
      return super(AuthenticatingHandler, self).dispatch()
    except api.AuthorizationError as err:
      logging.error('Authorization error.\n%s', err)
      self.authorization_error(err)

  def generate_xsrf_token(self):
    """Returns new XSRF token."""
    return XSRFToken.generate([api.get_current_identity().to_bytes()])

  def verify_xsrf_token(self):
    """Ensures XSRF token is correct.

    Raises AuthorizationError if token is missing or incorrect.
    """
    token = (
        self.request.headers.get(XSRF_TOKEN_HEADER) or
        self.request.get(XSRF_TOKEN_REQUEST_PARAM))
    if token is None:
      raise api.AuthorizationError('XSRF token is missing')
    try:
      if isinstance(token, unicode):
        token = token.encode('ascii')
      XSRFToken.validate(token, [api.get_current_identity().to_bytes()])
    except tokens.InvalidTokenError as err:
      raise api.AuthorizationError(str(err))

  def validate_request_format(self):
    """Ensures request has all required headers, etc.

    Called before authentication.
    """

  def authentication_error(self, error):
    """Called when authentication fails.

    Authentication error means that some credentials are provided but they are
    invalid. If no credentials provided at all, no authentication is attempted
    and current identity is set to Anonymous.

    Args:
      error: instance of api.AuthenticationError subclass.
    """
    self.abort(401, detail=str(error))

  def authorization_error(self, error):
    """Called when authentication succeeds, but access is denied.

    Args:
      error: instance of AuthorizationError subclass.
    """
    self.abort(403, detail=str(error))


class AuthenticationMethod(object):
  """Knows how to authenticate webapp2 requests.

  Given Request can extract Identity information from it.
  """

  # If True AuthenticatingHandler will validate XSRF token.
  requires_xsrf_token = True

  @classmethod
  def is_applicable(cls, request):
    """Returns True if this authenticator can be used with given request."""
    raise NotImplementedError()

  @classmethod
  def authenticate(cls, request):
    """Returns (Identity associated with the request, is_admin).

    Will be called only if is_applicable is True for same request.

    Raises api.AuthenticationError if credentials are not valid.
    """
    raise NotImplementedError()


class CookieAuthentication(AuthenticationMethod):
  """AppEngine cookie based authentication."""

  requires_xsrf_token = True

  @classmethod
  def is_applicable(cls, request):
    return bool(users.get_current_user())

  @classmethod
  def authenticate(self, request):
    email = users.get_current_user().email()
    try:
      identity = model.Identity(model.IDENTITY_USER, email)
    except ValueError:
      raise api.AuthenticationError('Invalid email format: %s' % email)
    return identity, users.is_current_user_admin()


class OAuthAuthentication(AuthenticationMethod):
  """OAuth2 based authentication."""

  requires_xsrf_token = False

  @classmethod
  def is_applicable(cls, request):
    # api.oauth stub on dev server is not very good.
    if 'Dev' in os.environ.get('SERVER_SOFTWARE', ''):
      return False
    try:
      return bool(oauth.get_client_id(EMAIL_SCOPE))
    except oauth.Error:
      return False

  @classmethod
  def authenticate(self, request):
    auth_db = api.get_request_local_auth_db()
    client_id = oauth.get_client_id(EMAIL_SCOPE)
    if not auth_db.is_allowed_oauth_client_id(client_id):
      raise api.AuthenticationError('Invalid OAuth client_id: %s' % client_id)
    email = oauth.get_current_user(EMAIL_SCOPE).email()
    try:
      identity = model.Identity(model.IDENTITY_USER, email)
    except ValueError:
      raise api.AuthenticationError('Invalid email format: %s' % email)
    return identity, oauth.is_current_user_admin()



# Global list of AuthenticationMethod classes to use for all request.
_authenticators = [CookieAuthentication, OAuthAuthentication]


def bootstrap(authenticators=None):
  """Global auth library configuration."""
  global _authenticators
  if authenticators is not None:
    assert all(issubclass(cls, AuthenticationMethod) for cls in authenticators)
    _authenticators = list(authenticators)
  # Set up all necessary root entities.
  model.bootstrap()
  # Set up all initial secrets.
  model.AuthSecret.bootstrap(
      author=None,
      name=XSRFToken.secret_key.name,
      scope=XSRFToken.secret_key.scope,
      retention=5,
      lifetime_sec=3600)
