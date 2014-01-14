# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""NDB related utilities."""

import datetime

from google.appengine.ext import ndb


# Use field only when converting entity to a simple dict.
READ_ONLY = 0
# Use field when converting entity to or from a simple dict.
WRITABLE = 1


class SerializableModel(ndb.Model):
  """Base class for entity that can serialize itself to simple dicts.

  A simple dictionary is a dictionary with string keys and values that are:
    * Scalar types: int, long, float.
    * String types: str, unicode.
    * Sequences: list, tuple.
    * Another simple dictionaries.

  A simple dict trivially converts to/from JSON.
  """

  @classmethod
  def get_serializable_fields(cls):
    """Returns dictionary: key name -> READ_ONLY or WRITABLE.

    It defines how to convert an entity to or from a simple dict.
    """
    return None

  def to_simple_dict(self, include=None, exclude=None, with_id_as=None):
    """Converts this entity to a simple dictionary."""
    conv = _ModelDictConverter(
        property_converters=_rich_to_simple_converters,
        allowed_field_modes=(READ_ONLY, WRITABLE))
    simple_dict = conv.convert_model_dict(
        self.__class__, self.to_dict(include=include, exclude=exclude))
    if with_id_as:
      assert isinstance(with_id_as, str)
      simple_dict[with_id_as] = self.key.string_id()
    return simple_dict

  @classmethod
  def convert_simple_dict(cls, simple_dict):
    """Converts simple dictionary to a dictionary with entity property values.

    It can then be used in entity constructor or in 'populate' method.
    """
    conv = _ModelDictConverter(
        property_converters=_simple_to_rich_converters,
        allowed_field_modes=(WRITABLE,))
    return conv.convert_model_dict(cls, simple_dict)


class _ModelDictConverter(object):
  """Uses |property_converters| to recursively convert dictionary values."""

  def __init__(self, property_converters, allowed_field_modes):
    self.property_converters = property_converters
    self.allowed_field_modes = allowed_field_modes

  def convert_model_dict(self, model_cls, model_dict):
    assert isinstance(model_dict, dict)
    allowed_fields = self.get_fields_whitelist(model_cls)
    result = {}
    for key, value in model_dict.iteritems():
      if allowed_fields is None or key in allowed_fields:
        result[key] = self.convert_property(model_cls._properties[key], value)
    return result

  def get_fields_whitelist(self, model_cls):
    if not issubclass(model_cls, SerializableModel):
      return None
    fields = model_cls.get_serializable_fields()
    if fields is None:
      return None
    return [
        field for field, mode in fields.iteritems()
        if mode in self.allowed_field_modes
    ]

  def convert_property(self, prop, value):
    converter = self.get_property_converter(prop)
    if prop._repeated:
      if value is None:
        return []
      assert isinstance(value, list)
      return [converter(prop, x) for x in value]
    else:
      if value is None:
        return None
      return converter(prop, value)

  def get_property_converter(self, prop):
    # For structured properties, recursively call convert_model_dict.
    if isinstance(prop, (ndb.StructuredProperty, ndb.LocalStructuredProperty)):
      return lambda prop, x: self.convert_model_dict(prop._modelclass, x)
    # For other properties consult the registry.
    for prop_cls, include_subclasses, conv in self.property_converters:
      if (include_subclasses and isinstance(prop, prop_cls) or
          not include_subclasses and type(prop) == prop_cls):
        return conv
    # Give up.
    raise TypeError('Don\'t know how to work with %s' % type(prop).__name__)


################################################################################
## Registry of property converters.


_rich_to_simple_converters = []
_simple_to_rich_converters = []

def register_converter(
    property_cls, include_subclasses, rich_to_simple, simple_to_rich):
  assert issubclass(property_cls, ndb.Property)
  _rich_to_simple_converters.append(
      (property_cls, include_subclasses, rich_to_simple))
  _simple_to_rich_converters.append(
      (property_cls, include_subclasses, simple_to_rich))


################################################################################
## Register trivial properties.


# Properties with values that look exactly the same in to_dict() and
# in to_simple_dict() representations.
SIMPLE_PROPERTIES = [
  ndb.BlobProperty,
  ndb.BooleanProperty,
  ndb.FloatProperty,
  ndb.IntegerProperty,
  ndb.JsonProperty,
  ndb.PickleProperty,
  ndb.StringProperty,
  ndb.TextProperty,
]


def _register_simple_converters():
  noop = lambda _prop, x: x
  for simple_prop_cls in SIMPLE_PROPERTIES:
    register_converter(
        property_cls=simple_prop_cls,
        include_subclasses=False,
        rich_to_simple=noop,
        simple_to_rich=noop)


_register_simple_converters()


################################################################################
## DateTime properties.


# UTC datetime corresponding to zero Unix timestamp.
_EPOCH = datetime.datetime.utcfromtimestamp(0)


def datetime_to_timestamp(value):
  """Converts UTC datetime to integer timestamp in milliseconds since epoch."""
  if value.tzinfo is not None:
    raise ValueError('Only UTC datetime is supported')
  dt = value - _EPOCH
  return dt.microseconds / 1000 + 1000 * (dt.seconds + 24 * 3600 * dt.days)


def timestamp_to_datetime(value):
  """Converts integer timestamp in milliseconds since epoch to UTC datetime."""
  return _EPOCH + datetime.timedelta(microseconds=value*1000)


# TODO(vadimsh): Add ndb.DateProperty if needed.
register_converter(
    property_cls=ndb.DateTimeProperty,
    include_subclasses=False,
    rich_to_simple=lambda _prop, x: datetime_to_timestamp(x),
    simple_to_rich=lambda _prop, x: timestamp_to_datetime(x))


################################################################################
## BytesSerializable properties.


class BytesSerializable(object):
  """Mixing class that defines to_bytes() and from_bytes() methods."""

  def to_bytes(self):
    raise NotImplementedError()

  @classmethod
  def from_bytes(cls, bytes):
    raise NotImplementedError()


class BytesSerializableProperty(ndb.BlobProperty):
  """BlobProperty that uses values's to_bytes/from_bytes methods.

  Property will use to_bytes() to serialize an object before storing it in
  DB and from_bytes() when fetching it from DB and validating.
  """

  # Should be set in subclasses.
  _value_type = None

  def _validate(self, value):
    if not isinstance(value, self._value_type):
      raise TypeError(
          'Expecting %s, got %r' % (self._value_type.__name__, value))

  def _to_base_type(self, value):
    result = value.to_bytes()
    assert isinstance(result, str)
    return result

  def _from_base_type(self, value):
    assert isinstance(value, str)
    result = self._value_type.from_bytes(value)
    assert isinstance(result, self._value_type)
    return result


# Handles all property classes inherited from BytesSerializableProperty.
register_converter(
    property_cls=BytesSerializableProperty,
    include_subclasses=True,
    rich_to_simple=lambda prop, value: value.to_bytes(),
    simple_to_rich=lambda prop, value: prop._value_type.from_bytes(value))


################################################################################
## JsonSerializable properties.


class JsonSerializable(object):
  """Mixing class that defines to_jsonish() and from_jsonish() methods."""

  def to_jsonish(self):
    raise NotImplementedError()

  @classmethod
  def from_jsonish(cls, obj):
    raise NotImplementedError()


class JsonSerializableProperty(ndb.JsonProperty):
  """JsonProperty that uses values's to_jsonish/from_jsonish methods.

  Property will use to_jsonish() to convert an object to simple JSONish value
  before storing it in DB as JSON and from_jsonish() when fetching it from
  DB and validating.
  """

  # Should be set in subclasses.
  _value_type = None

  def _validate(self, value):
    if not isinstance(value, self._value_type):
      raise TypeError(
          'Expecting %s, got %r' % (self._value_type.__name__, value))

  def _to_base_type(self, value):
    return value.to_jsonish()

  def _from_base_type(self, value):
    return self._value_type.from_jsonish(value)


# Handles all property classes inherited from JsonSerializableProperty.
register_converter(
    property_cls=JsonSerializableProperty,
    include_subclasses=True,
    rich_to_simple=lambda prop, value: value.to_jsonish(),
    simple_to_rich=lambda prop, value: prop._value_type.from_jsonish(value))
