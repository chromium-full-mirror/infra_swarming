# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Convert dicts with arbitrary types to JSONable ones and vice versa."""

import calendar
import contextlib
import datetime


class SchemaError(Exception):
  """Type mismatch when wrapping or unwrapping."""

  def __init__(self, msg):
    super(SchemaError, self).__init__(msg)
    self.stack = None


class KeysStack(object):
  """Holds an explicit dict keys stack during recursive wrapping\unwrapping.

  This stack is used in error reporting.
  """

  def __init__(self):
    self.stack = []

  @contextlib.contextmanager
  def call(self, key=None):
    if key:
      self.stack.append(key)
    try:
      yield
    except SchemaError as err:
      if err.stack is None:
        err.stack = self.stack[:]
      raise
    finally:
      if key:
        assert self.stack[-1] is key
        self.stack.pop()


class Element(object):
  """Abstract base class for schema definition.

  Can convert rich_type <-> simple_type with type and value verification.
  """

  # Type (or tuple of types) that this element can convert to |simple_type|.
  rich_type = None
  # Type (or tuple of types) that this element converts to.
  simple_type = None

  def to_rich(self, simple):
    """Unstructured dict -> rich dict."""
    stack = KeysStack()
    with stack.call():
      return self.unwrap(simple, stack)

  def to_simple(self, rich):
    """Rich dict -> unstructured dict."""
    stack = KeysStack()
    with stack.call():
      return self.wrap(rich, stack)

  def wrap(self, obj, stack):
    """Given unknown unwrapped object, verify its type and wrap it."""
    if not isinstance(obj, self.rich_type):
      raise SchemaError(
          'Expecting %s, got %s instead' % (self.rich_type, type(obj)))
    result = self.serialize(obj)
    assert isinstance(result, self.simple_type)
    return result

  def serialize(self, obj):
    """Verified unwrapped object -> wrapped object."""
    # Subclasses should override. Default implementation assumes
    # that |rich_type| and |simple_type| are compatible.
    assert isinstance(obj, self.simple_type)
    return obj

  def unwrap(self, obj, stack):
    """Given unknown wrapped object, verify its type, validate and unwrap it."""
    if not isinstance(obj, self.simple_type):
      raise SchemaError(
          'Expecting %s, got %s instead' % (self.simple_type, type(obj)))
    self.validate(obj)
    result = self.deserialize(obj)
    assert isinstance(result, self.rich_type)
    return result

  def validate(self, obj):
    """Given wrapped object check that its valid before unwrapping."""

  def deserialize(self, obj):
    """Validated wrapped object -> unwrapped object."""
    # Subclasses should override. Default implementation assumes
    # that |rich_type| and |simple_type| are compatible.
    assert isinstance(obj, self.rich_type)
    return obj


class StringSerializable(Element):
  """Rich types that provide to_string and from_string."""

  rich_type = None
  simple_type = basestring

  def __init__(self, rich_type, **kwargs):
    super(StringSerializable, self).__init__(**kwargs)
    self.rich_type = rich_type
    assert hasattr(rich_type, 'from_string')

  def serialize(self, obj):
    return obj.to_string()

  def deserialize(self, obj):
    return self.rich_type.from_string(obj)


class Integer(Element):
  """Unbounded integers."""

  rich_type = (int, long)
  simple_type = (int, long)


class DateTimeTimestamp(Element):
  """UTC Datetime <-> integer Unix timestamp."""

  rich_type = datetime.datetime
  simple_type = int

  def serialize(self, obj):
    return calendar.timegm(obj.utctimetuple())

  def deserialize(self, obj):
    return datetime.datetime.utcfromtimestamp(obj)


class String(Element):
  """String with regexp validator."""

  rich_type = basestring
  simple_type = basestring

  def __init__(self, regexp=None, **kwargs):
    super(String, self).__init__(**kwargs)
    if isinstance(regexp, basestring):
      self.regexp = re.compile(regexp)
    else:
      self.regexp = regexp

  def validate(self, obj):
    if self.regexp:
      match = self.regexp.match(obj)
      if not match:
        raise SchemaError('Invalid value: \'%s\'' % obj)


class Recursive(Element):
  """Element that implements 'wrap' and 'unwrap' in terms of single function."""

  def recurse(self, method, obj, stack):
    raise NotImplementedError()

  def wrap(self, obj, stack):
    wrapped = self.recurse('wrap', obj, stack)
    return self.serialize(wrapped)

  def unwrap(self, obj, stack):
    unwrapped = self.recurse('unwrap', obj, stack)
    self.validate(unwrapped)
    return self.deserialize(unwrapped)


class Dictionary(Recursive):
  """Dictionary with predefined rigid structure."""

  rich_type = dict
  simple_type = dict

  def __init__(self, structure, **kwargs):
    super(Dictionary, self).__init__(**kwargs)
    assert all(isinstance(x, Element) for x in structure.itervalues())
    self.structure = structure

  def recurse(self, method, obj, stack):
    if not isinstance(obj, dict):
      raise SchemaError('Expecting a dictionary, got %s instead' % type(obj))
    processed = {}
    for key, element in self.structure.iteritems():
      if key not in obj:
        raise SchemaError('Missing required dictionary key: %s' % key)
      with stack.call(key):
        processed[key] = getattr(element, method)(obj[key], stack)
    return processed

  def extend(self, structure, **kwargs):
    """Returns new Dictionary that is extension of this one."""
    extended = self.structure.copy()
    extended.update(structure)
    return self.__class__(extended, **kwargs)

  def narrow(self, *keys, **kwargs):
    """Returns new Dictionary that is narrowing of this one with only |keys|."""
    narrowed = {}
    for key in keys:
      assert key in self.structure, 'Missing key %s' % key
      narrowed[key] = self.structure[key]
    return self.__class__(narrowed, **kwargs)


class List(Recursive):
  """List of items of a same type."""

  rich_type = (list, tuple)
  simple_type = (list, tuple)

  def __init__(self, element, **kwargs):
    super(List, self).__init__(**kwargs)
    assert isinstance(element, Element)
    self.element = element

  def recurse(self, method, obj, stack):
    if not isinstance(obj, (list, tuple)):
      raise SchemaError('Expecting a list, got %s instead' % type(obj))
    processed = []
    method = getattr(self.element, method)
    for index, value in enumerate(obj):
      with stack.call('[%d]' % index):
        processed.append(method(value, stack))
    return processed
