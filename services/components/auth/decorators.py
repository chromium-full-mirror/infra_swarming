# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Helper decorators that perform authorization checks."""

import functools
import inspect
import re

from . import cache

__all__ = ['public', 'require']


# Types of vars allowed to be used in resource templates.
ALLOWED_TEMPLATE_VAR_TYPES = (str, unicode, int, long)


def public(func):
  """Explicitly marks function as available for Anonymous access."""
  # @require decorator sets __auth_require attribute.
  if hasattr(func, '__auth_require'):
    raise TypeError('Can\'t use @public and @require on same function')
  func.__auth_public = True
  return func


def require(action, resource):
  """Ensures that current identity has a required permission."""
  def decorator(func):
    # @public decorator sets __auth_public attribute.
    if hasattr(func, '__auth_public'):
      raise TypeError('Can\'t use @public and @require on same function')
    func.__auth_require = True

    # When nesting multiple decorators information about original function
    # signature gets lost. Explicitly preserve it in __auth_func_spec.
    spec = getattr(func, '__auth_func_spec', None)
    if not spec:
      spec = inspect.getargspec(func)
      func.__auth_func_spec = spec

    # Build a function that can substitute variable in resource template.
    # Do it once when decorating.
    resource_renderer = build_resource_renderer(func.__name__, spec, resource)

    # functools.wraps propagates __auth_* from |func| to |wrapper|.
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
      cache.ensure_permission(action, resource_renderer(*args, **kwargs))
      return func(*args, **kwargs)
    return wrapper

  return decorator


def is_decorated(func):
  """Return True if |func| is decorated by @public or @require."""
  return hasattr(func, '__auth_public') or hasattr(func, '__auth_require')


def build_resource_renderer(func_name, spec, resource):
  """Returns a function that renders resource template into resource name.

  Returned function accepts positional and keyword arguments of invocation of
  decorated function, farms out values of variables used in |resource| template
  and renders that template using these values.

  Args:
    func_name: Name of the decorated function, for error messages.
    spec: argspec of the decorated function.
    resource: resource template that uses variables from |spec|.
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
          'template \'%s\'.' % (var, resource))

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
            'expanding \'%s\'.' % (var, func_name, resource))
      if not isinstance(env[var], ALLOWED_TEMPLATE_VAR_TYPES):
        raise TypeError(
            'Invalid type of argument \'%s\' used in template \'%s\' when '
            'calling \'%s\': %s' % (var, resource, func_name, type(env[var])))
    return template % env

  return renderer
