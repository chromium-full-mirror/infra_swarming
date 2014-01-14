# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Main chunk of public API exposed by Auth component."""

import collections
import functools
import inspect
import logging
import os
import re
import threading
import time

from google.appengine.ext import ndb

from . import model

__all__ = [
  'AuthenticationError',
  'AuthorizationError',
  'Error',
  'get_current_identity',
  'get_secret',
  'has_permission',
  'is_decorated',
  'public',
  'require',
  'SecretKey',
]


# How soon process-global AuthDB cache expires.
PROCESS_CACHE_EXPIRATION_SEC = 15

# State for process-global Authentication DB cache.
_auth_db_lock = threading.Lock()
_auth_db = None
_auth_db_expiration = None
_auth_db_fetching_thread = None


class Error(Exception):
  """Base class for all exceptions raised by auth component."""

  def __init__(self, message=None):
    super(Error, self).__init__(message or self.__doc__)


class AuthenticationError(Error):
  """Provided credentials are invalid."""


class AuthorizationError(Error):
  """Access is denied."""


################################################################################
## Secret keys API.


# Identifies a secret. Can be service-local (scope == 'local') or global across
# all services (scope == 'global').
SecretKey = collections.namedtuple('SecretKey', ['name', 'scope'])


def get_secret(secret_key):
  """Given an instance of SecretKey returns a list of strings.

  First item in the list is current value of a secret key, all other values are
  previous values of the key.

  Creates a new secret if necessary.
  """
  return get_request_auth_db().get_secret(secret_key.name, secret_key.scope)


################################################################################
## Request Auth DB cache.


class RequestCache(object):
  """Holds authentication related information for the current request."""

  def __init__(self):
    self.current_identity = None
    self.auth_db = None
    self.is_admin = False

  def set_current_identity(self, current_identity, is_admin):
    """Called early during request processing to set current identity."""
    self.current_identity = current_identity
    self.is_admin = is_admin

  def close(self):
    """Helps GC to collect garbage faster."""
    self.current_identity = None
    self.auth_db = None


class _LocalState(threading.local):
  """Holds thread-local state that keeps RequestCache."""
  request_cache = None

_local_state = _LocalState()


def get_request_cache():
  """Returns instance of RequestCache associated with the current request.

  A new instance is created for each new HTTP request. We determine
  that we're in a new request by inspecting os.environ, which is reset
  at the start of each request. Also, each thread gets its own context.
  """
  # Properly close an object from previous request served by current thread.
  request_cache = _local_state.request_cache
  if not os.getenv('__AUTH_CACHE__') and request_cache is not None:
    request_cache.close()
    _local_state.request_cache = None
    request_cache = None
  # Make a new cache, put it in thread local state, flag os.environ.
  if request_cache is None:
    request_cache = RequestCache()
    _local_state.request_cache = request_cache
    os.environ['__AUTH_CACHE__'] = '1'
  return request_cache


@ndb.non_transactional
def get_cached_auth_db():
  """Returns instance of AuthDB from process global cache.

  Two subsequent calls may return different instances (if cache expires between
  the calls).
  """
  global _auth_db
  global _auth_db_expiration
  global _auth_db_fetching_thread

  known_auth_db = None
  known_auth_db_version = None

  with _auth_db_lock:
    # Cached copy is still fresh?
    if _auth_db and time.time() < _auth_db_expiration:
      return _auth_db

    # Fetching AuthDB for a first time ever? Do it under the lock because
    # there's nothing to return yet.
    if _auth_db is None:
      _auth_db = model.fetch_auth_db()
      _auth_db_expiration = time.time() + PROCESS_CACHE_EXPIRATION_SEC
      return _auth_db

    # Local cached copy has expired. Maybe some thread is already fetching it?
    # Don't block an entire process on this, return a little bit stale copy.
    if _auth_db_fetching_thread is not None:
      return _auth_db

    # No one is fetching AuthDB yet. Start the operation, release a lock so
    # other threads can figure this out and use a bit stale copies
    # instead of blocking on a lock.
    _auth_db_fetching_thread = threading.current_thread()
    known_auth_db = _auth_db
    known_auth_db_version = _auth_db.entity_group_version

  # Do it outside the lock.
  fresh_copy = model.fetch_auth_db(known_version=known_auth_db_version)
  if fresh_copy is None:
    # No changes, entity group versions match, reuse same object.
    fresh_copy = known_auth_db

  # Done. Update global state.
  with _auth_db_lock:
    assert _auth_db_fetching_thread == threading.current_thread()
    _auth_db = fresh_copy
    _auth_db_expiration = time.time() + PROCESS_CACHE_EXPIRATION_SEC
    _auth_db_fetching_thread = None
    return _auth_db


def get_request_auth_db():
  """Returns instance of AuthDB from request local cache.

  In a context of a single request this function always returns same
  instance of AuthDB. So as long as request runs, ACL rules stay consistent and
  don't change beneath your feet.
  """
  cache = get_request_cache()
  if cache.auth_db is None:
    cache.auth_db = get_cached_auth_db()
  return cache.auth_db


def get_current_identity():
  """Returns Identity associated with the current request."""
  return get_request_cache().current_identity


def has_permission(action, resource):
  """True if current identity can execute |action| against |resource|."""
  ident = get_current_identity()
  if get_request_auth_db().has_permission(ident, action, resource):
    return True
  # Escape hatch for admins to fix broken ACL rules. Should be used only in
  # exceptional circumstances, so add warning if used.
  if get_request_cache().is_admin:
    logging.warning(
        'Exercising admin superpowers: %s to %s %s', ident, action, resource)
    return True
  return False


################################################################################
## @public and @require decorators.


def is_decorated(func):
  """Return True if |func| is decorated by @public or @require decorators."""
  return hasattr(func, '__auth_public') or hasattr(func, '__auth_require')


def public(func):
  """Decorator that marks a function as available for anonymous access."""
  # @require decorator sets __auth_require attribute.
  if hasattr(func, '__auth_require'):
    raise TypeError('Can\'t use @public and @require on same function')
  func.__auth_public = True
  return func


def require(action, resource):
  """Decorator that ensures that current identity has a required permission.

  Note that if ACL rules explicitly allow 'anonymous:anonymous' to access
  |resource|, this decorator will happily allow it as well.
  """
  def decorator(func):
    # @public decorator sets __auth_public attribute.
    if hasattr(func, '__auth_public'):
      raise TypeError('Can\'t use @public and @require on same function')
    func.__auth_require = True

    # When nesting multiple decorators information about original function
    # gets lost. Explicitly preserve it in __wrapped__. It is also what
    # NDB does. So 'require' decorator plays nicely with ndb decorators.
    original = getattr(func, '__wrapped__', func)

    # Build a function that can substitute variable in resource template.
    # Do it once when decorating.
    resource_renderer = make_resource_renderer(func, resource)

    # functools.wraps propagates __auth_* from |func| to |wrapper|.
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
      if not has_permission(action, resource_renderer(*args, **kwargs)):
        raise AuthorizationError()
      return func(*args, **kwargs)

    # Store reference to original function.
    wrapper.__wrapped__ = original
    return wrapper

  return decorator


def make_resource_renderer(func, resource):
  """Returns a function that renders resource template into resource name.

  Returned function accepts positional and keyword arguments of invocation of
  decorated function, farms out values of variables used in |resource| template
  and renders that template using these values.

  For example:
    def func(arg, another=''):
      ...
    renderer = make_resource_renderer(func, 'test/{arg}/{another}')
    assert renderer(1, 2) == 'test/1/2'
    assert renderer(1) == 'test/1/'
  """
  # Convert |resource| template from {var} syntax to '%(var)s' syntax.
  def replacer(match):
    var = match.group(1)
    used_vars.add(var)
    return '%(' + var +')s'
  used_vars = set()
  template = re.sub(r'\{(.+)\}', replacer, resource)

  # Template that is just a predefined static resource name?
  # Don't bother trying to 'render' it.
  if not used_vars:
    return lambda *_args, **_kwargs: resource

  # Extract information about the function.
  func_name = func.__name__
  spec = inspect.getargspec(func)

  # Build dict with default values.
  defaults = {}
  if spec.defaults:
    defaults = dict((spec.args[-i-1], v) for i, v in enumerate(spec.defaults))

  # All template args should be among explicit positional arguments
  # of the function.
  for var in used_vars:
    if var not in spec.args:
      raise TypeError(
          'Referencing unknown variable \'%s\' in resource '
          'template \'%s\'' % (var, resource))

  # Renderer looks at function call argument and extracts values of variables
  # used in |resource| template.
  def renderer(*args, **kwargs):
    # Add all default argument values first.
    env = defaults.copy()
    # Override them with values passed via keyword parameters.
    env.update(kwargs)
    # And add positional parameters.
    env.update((spec.args[i], value) for i, value in enumerate(args))
    # Now verify that all required arguments are there and types are correct.
    for var in used_vars:
      if var not in env:
        raise TypeError(
            'Missing required argument \'%s\' in a call to \'%s\' when '
            'expanding \'%s\'' % (var, func_name, resource))
      if not isinstance(env[var], (str, unicode, int, long)):
        raise TypeError(
            'Invalid type of argument \'%s\' used in template \'%s\' when '
            'calling \'%s\': %s' % (var, resource, func_name, type(env[var])))
    return template % env

  return renderer
