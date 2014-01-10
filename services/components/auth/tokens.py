# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Functions to generate and validate tokens."""

import base64
import hashlib
import hmac
import json
import time

from . import api

__all__ = ['InvalidTokenError', 'BadSecretError', 'Token']


# Name -> (hash to use, how many bytes of digest to use).
MAC_ALGOS = {
  'hmac-sha256': (hashlib.sha256, 32),
}


class InvalidTokenError(ValueError):
  """Token validation failed."""


class BadSecretError(ValueError):
  """Secret key is missing."""


class Token(object):
  """Base class for token types.

  Usage:
    1) Define token class, configuring its kind, expiration name of a secret:
      class MyToken(Token):
        kind = 'my_token'
        expiration_sec = 3600
        secret_key = SecretKey('my_secret', scope='local')

    2) Use it to generate a token that embeds and\or signs some data:
      token = MyToken.generate('message to authenticate', {'data': 'public'})

    3) Validate token passed from elsewhere and extract embedded data:
      data = MyToken.validate(token, 'message to authenticate')
      assert data['data'] == 'public'

  Generated token expires after |expiration_sec| or when secret key expires.
  """

  # What algo to use for MAC tag.
  algo = 'hmac-sha256'
  # Will be added to tagged message so that tokens of different kinds always
  # have different tags (even if payload, secret, timestamp, etc. matches).
  kind = 'unknown'
  # Format version number that will be embedded into the token.
  version = 1
  # If set defines how long token can live.
  expiration_sec = None
  # Name of the secret key to use when generating and validating the token.
  # Must be an instance of SecretKey.
  secret_key = None

  @classmethod
  def generate(cls, message=None, embedded=None):
    """Generates a token that contains signature for |message|."""
    # Convert all 'unicode' to UTF-8 or ASCII strings, validate structure.
    message = normalize_message(message)
    embedded = normalize_embedded(embedded)

    # Fetch array of last secret values.
    secret = api.get_secret(cls.secret_key)
    if not secret:
      raise BadSecretError('Secret key is missing')

    # Append expiration timestamp.
    if cls.expiration_sec is not None:
      embedded['_x'] = str(int(time.time() * 1000 + cls.expiration_sec * 1000))

    # Encode token, use most recent secret value.
    return encode_token(
        cls.algo, cls.version, secret[0], [cls.kind] + message, embedded)

  @classmethod
  def validate(cls, token, message=None):
    """Validates token signature and extracts embedded data from token."""
    # Convert all 'unicode' to UTF-8 or ASCII.
    token = to_ascii(token)
    message = normalize_message(message)

    # Fetch array of last secret values.
    secret = api.get_secret(cls.secret_key)
    if not secret:
      raise BadSecretError('Secret key is missing')

    # Decode token, use any recent value of secret to validate MAC.
    version, embedded = decode_token(
        cls.algo, token, secret, [cls.kind] + message)

    # Versions should match.
    if version != cls.version:
      raise InvalidTokenError(
          'Bad token format version - '
          'expected %r, got %r' % (cls.version, version))

    # Check expiration.
    if cls.expiration_sec is not None:
      expiration_ts = embedded.pop('_x', None)
      if expiration_ts is None:
        raise InvalidTokenError('Bad token: expiration timestamp is missing')
      if time.time() * 1000 > int(expiration_ts):
        raise InvalidTokenError('Bad token: expired')

    return embedded


def to_ascii(string):
  """Unicode -> ASCII str."""
  if isinstance(string, str):
    return string
  elif isinstance(string, unicode):
    return string.encode('ascii')
  raise TypeError('Expecting str or unicode')


def to_utf8(string):
  """Unicode -> UTF-8 str."""
  if isinstance(string, str):
    return string
  elif isinstance(string, unicode):
    return string.encode('utf-8')
  raise TypeError('Expecting str or unicode')


def normalize_message(message):
  """Sequence of str or unicode -> new list of UTF-8 strings."""
  if message is None:
    return []
  if not isinstance(message, (list, tuple)):
    message = [message]
  return [to_utf8(chunk) for chunk in message]


def normalize_embedded(embedded):
  """Dict -> validated dict with ASCII keys and values."""
  out = {}
  for key, value in (embedded or {}).iteritems():
    if key.startswith('_'):
      raise ValueError('_<id> is reserved')
    out[to_ascii(key)] = to_ascii(value)
  return out


def base64_encode(data):
  """Binary -> URL safe base64."""
  # Borrowed from ndb's key.py. This is 3-4x faster than urlsafe_b64encode().
  assert isinstance(data, str)
  urlsafe = base64.b64encode(data)
  return urlsafe.rstrip('=').replace('+', '-').replace('/', '_')


def base64_decode(data):
  """URL safe base64 -> binary."""
  # Borrowed from ndb's key.py, _DecodeUrlSafe.
  assert isinstance(data, str)
  mod = len(data) % 4
  if mod:
    data += '=' * (4 - mod)
  # This is 3-4x faster than urlsafe_b64decode()
  return base64.b64decode(data.replace('-', '+').replace('_', '/'))


def compute_mac(algo, secret, chunks):
  """Secret string + list of arbitrary strings -> MAC."""
  assert isinstance(secret, str) and secret
  hash_algo, digest_size = MAC_ALGOS[algo]
  mac = hmac.new(secret, digestmod=hash_algo)
  for chunk in chunks:
    assert isinstance(chunk, str)
    mac.update(str(len(chunk)))
    mac.update(chunk)
  return mac.digest()[:digest_size]


def encode_token(algo, version, secret, message, embedded):
  """Wraps, tags and encodes a token.

  Anatomy of an encoded token:
    base64(<version byte> + payload json + mac(<version byte> + payload json))
  Where:
    <version byte> - one byte that defines version of a token format.
    payload json - compactly serialized json dict with token payload.
    mac - binary MAC tag of known size (may depend on version).
  """
  public = json.dumps(
      embedded, sort_keys=True, separators=(',', ':'), encoding='ascii')
  mac = compute_mac(algo, secret, [str(version), public] + message)
  return base64_encode(''.join([chr(version), public, mac]))


def decode_token(algo, token, possible_secrets, message):
  """Decodes, checks MAC tag and unwraps a token."""
  # Unwrap version, payload and MAC.
  _, digest_size = MAC_ALGOS[algo]
  try:
    binary = base64_decode(token)
    if len(binary) <= digest_size + 2:
      raise ValueError()
    version = ord(binary[0])
    public = binary[1:-digest_size]
    mac = binary[-digest_size:]
  except ValueError:
    raise InvalidTokenError('Bad token format: %r' % token)

  # Validate MAC tag in constant time.
  valid = False
  for secret in possible_secrets:
    good_mac = compute_mac(algo, secret, [str(version), public] + message)
    assert len(good_mac) == len(mac)
    accum = 0
    for x, y in zip(mac, good_mac):
      accum |= ord(x) ^ ord(y)
    if not accum:
      valid |= True

  # At least one secret key should match.
  if not valid:
    raise InvalidTokenError('Bad token MAC')

  # Return version and embedded token data.
  return version, json.loads(public, encoding='ascii')
