# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Read-only ACL database and identity cache."""

import os
import threading
import time

from . import errors
from . import model


__all__ = [
  'get_current_identity', 'has_permission', 'ensure_permission',
]


# How soon process-global AuthDB cache expires.
PROCESS_CACHE_EXPIRATION_SEC = 60

# State for process-global AuthDB cache.
_auth_db_lock = threading.Lock()
_auth_db = None
_auth_db_expiration = None
_auth_db_fetching_thread = None


class RequestCache(object):
  """Holds authentication related information for current request."""

  def __init__(self):
    self.initialized = False
    self.current_identity = None
    self.auth_db = None

  def initialize(self, current_identity, is_admin):
    """Called early during request processing to assign an identity."""
    assert not self.initialized
    self.initialized = True
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


def get_request_cache(ensure_initialized):
  """Returns instance of RequestCache associated with current request.

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
  if ensure_initialized and not request_cache.initialized:
    raise errors.UninitializedError()
  return request_cache


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


def get_request_local_auth_db():
  """Returns instance of AuthDB from request local cache.

  In a context of a single request this function always returns same
  instance of AuthDB. So as long as request runs ACL rules stay consistent and
  doesn't change beneath your feet.
  """
  cache = get_request_cache(ensure_initialized=True)
  if cache.auth_db is None:
    cache.auth_db = get_cached_auth_db()
  return cache.auth_db


def get_current_identity():
  """Returns Identity associated with current request."""
  return get_request_cache(ensure_initialized=True).current_identity


def is_current_user_admin():
  """Return True if current request is running from an admin account."""
  return get_request_cache(ensure_initialized=True).is_admin


def check_identity_has_permission(identity, action, resource):
  """True if |identity| can execute |action| against |resource|."""
  return get_request_local_auth_db().check_identity_has_permission(
      identity, action, resource)


def has_permission(action, resource):
  """True if current identity can execute |action| against |resource|."""
  # Escape hatch for admins to fix broken ACL rules.
  if is_current_user_admin():
    return True
  return check_identity_has_permission(get_current_identity(), action, resource)


def ensure_permission(action, resource):
  """Ensures current identity can execute |action| against |resource|."""
  if not has_permission(action, resource):
    raise errors.AuthorizationError()
