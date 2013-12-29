# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Integration with webapp2."""

import webapp2

from google.appengine.api import users

from . import cache
from . import decorators
from . import errors
from . import model

__all__ = [
  'AuthenticatingHandler', 'Authenticator', 'CookieBasedAuthenticator',
  'configure',
]


class AuthenticatingHandlerMetaclass(type):
  """Ensures that 'get', 'post', etc. are marked with ACL decorators."""

  def __new__(cls, name, bases, attributes):
    for method in webapp2.WSGIApplication.allowed_methods:
      func = attributes.get(method.lower())
      if func and callable(func) and not decorators.is_decorated(func):
        raise AssertionError(
            'Method \'%s\' of \'%s\' is not protected by @require or @public '
            'decorator.' % (method.lower(), name))
    return type.__new__(cls, name, bases, attributes)


class AuthenticatingHandler(webapp2.RequestHandler):
  """Base class for request handlers that use ACL system."""

  # Checks that all 'get', 'post', etc. are marked with @require or @public.
  __metaclass__ = AuthenticatingHandlerMetaclass

  # Set to False if custom processing is required. In that case, a call to
  # self.parse_xsrf_token() is required inside the post()/put() handler.
  enforce_xsrf_token = True

  # Data extracted from XSRF token.
  xsrf_token_data = None

  def dispatch(self):
    """Extracts and verifies Identity."""
    identity = model.Anonymous
    is_admin = False
    for authenticator_cls in _authenticators:
      if authenticator_cls.is_applicable(self.request):
        try:
          identity, is_admin = authenticator_cls.authenticate(self.request)
          assert isinstance(identity, model.Identity)
          assert is_admin in (True, False)
          break
        except errors.AuthenticationError as err:
          self.authentication_error(err)
          return

    # Successfully extracted and validated an identity, put it in the cache.
    request_cache = cache.get_request_cache(ensure_initialized=False)
    request_cache.initialize(identity, is_admin)

    try:
      """
      # Verify XSRF token if required by method handler.
      self.xsrf_token_data = None
      if self.request.method in ('POST', 'PUT') and self.enforce_xsrf_token:
        self.xsrf_token_data = self.parse_xsrf_token()
      """
      # All ACL checks will be performed by corresponding handlers.
      return webapp2.RequestHandler.dispatch(self)
    except errors.AuthorizationError as err:
      self.authorization_error(err)

  def authentication_error(self, error):
    """Called when authentication fails.

    Authentication error means that some credentials are provided but they are
    invalid. If no credentials provided at all, no authentication is attempted
    and current identity is set to Anonymous.

    Args:
      error: instance of errors.AuthenticationError subclass.
    """
    self.abort(401, detail=str(error))

  def authorization_error(self, error):
    """Called when authentication succeeds, but access is denied.

    Args:
      error: instance of AuthorizationError subclass.
    """
    self.abort(403, detail=str(error))


class Authenticator(object):
  """Knows how to authenticate webapp2 requests.

  Given Request can extract Identity information from it.
  """

  @classmethod
  def is_applicable(cls, request):
    """Returns True if this authenticator can be used with given request."""
    raise NotImplementedError()

  @classmethod
  def authenticate(cls, request):
    """Returns (Identity associated with the request, is_admin).

    Will be called only if is_applicable is True for same request.

    Raises errors.AuthenticationError if credentials are not valid.
    """
    raise NotImplementedError()


class CookieBasedAuthenticator(Authenticator):
  """AppEngine cookie based authentication."""

  @classmethod
  def is_applicable(cls, request):
    return bool(users.get_current_user())

  @classmethod
  def authenticate(self, request):
    email = users.get_current_user().email()
    try:
      identity = model.Identity(model.IDENTITY_USER, email)
    except ValueError:
      raise errors.AuthenticationError('Invalid email format: %s' % email)
    return identity, users.is_current_user_admin()


# Global list of Authenticator classes to use for all request.
_authenticators = [CookieBasedAuthenticator]


def configure(authenticators):
  """Global auth library configuration."""
  global _authenticators
  assert all(issubclass(auth_cls, Authenticator) for auth_cls in authenticators)
  _authenticators = authenticators
