# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Exceptions use by auth component."""


__all__ = [
  'Error', 'AuthenticationError', 'AuthorizationError', 'UninitializedError',
]


class Error(Exception):
  """Base class for all exceptions raised by auth component."""

  def __init__(self, message=None):
    super(Error, self).__init__(message or self.__doc__)


class AuthenticationError(Error):
  """Provided credentials are invalid."""


class AuthorizationError(Error):
  """Access is denied."""


class UninitializedError(Error):
  """Authentication context is not initialized."""
