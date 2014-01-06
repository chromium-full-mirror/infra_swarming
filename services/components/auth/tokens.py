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
  """Base class for token types."""

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
  def generate(cls, message, embedded=None):
    """Generates a token that contains signature for |message|."""
    embedded = (embedded or {}).copy()
    assert not any(k.startswith('_') for k in embedded), '_<id> is reserved'
    if cls.expiration_sec is not None:
      embedded['_x'] = str(int(time.time() * 1000 + cls.expiration_sec * 1000))
    secret = api.get_secret(cls.secret_key)
    if not secret:
      raise BadSecretError('Secret key is missing')
    return encode_token(
        cls.version, secret[0], [cls.kind] + message, embedded, cls.algo)

  @classmethod
  def validate(cls, token, message):
    """Validates token signature and extracts embedded data from token."""
    secret = api.get_secret(cls.secret_key)
    if not secret:
      raise BadSecretError('Secret key is missing')
    version, embedded = decode_token(
        token, secret, [cls.kind] + message, cls.algo)
    if version != cls.version:
      raise InvalidTokenError(
          'Bad token format version - '
          'expected %r, got %r' % (cls.version, version))
    if cls.expiration_sec is not None:
      expiration_ts = embedded.pop('_x', None)
      if expiration_ts is None:
        raise InvalidTokenError('Bad token: expiration timestamp is missing')
      if time.time() * 1000 > int(expiration_ts):
        raise InvalidTokenError('Bad token: expired')
    internal_keys = [k for k in embedded if k.startswith('_')]
    if internal_keys:
      raise InvalidTokenError('Bad token: unexpected keys %r' % internal_keys)
    return embedded


def base64_encode(data):
  """Binary -> URL safe base64."""
  # Borrowed from ndb's key.py. This is 3-4x faster than urlsafe_b64encode().
  urlsafe = base64.b64encode(data)
  return urlsafe.rstrip('=').replace('+', '-').replace('/', '_')


def base64_decode(urlsafe):
  """URL safe base64 -> binary."""
  # Borrowed from ndb's key.py, _DecodeUrlSafe.
  if not isinstance(urlsafe, basestring):
    raise TypeError('urlsafe must be a string; received %r' % urlsafe)
  if isinstance(urlsafe, unicode):
    urlsafe = urlsafe.encode('utf8')
  mod = len(urlsafe) % 4
  if mod:
    urlsafe += '=' * (4 - mod)
  # This is 3-4x faster than urlsafe_b64decode()
  return base64.b64decode(urlsafe.replace('-', '+').replace('_', '/'))


def compute_mac(secret, chunks, algo):
  """Secret string + list of arbitrary strings -> MAC."""
  assert isinstance(secret, str) and secret
  hash_algo, digest_size = MAC_ALGOS[algo]
  mac = hmac.new(secret, digestmod=hash_algo)
  for chunk in chunks:
    assert isinstance(chunk, basestring)
    if isinstance(chunk, unicode):
      chunk = chunk.encode('utf-8')
    mac.update(str(len(chunk)))
    mac.update(chunk)
  return mac.digest()[:digest_size]


def encode_token(version, secret, message, embedded, algo):
  """Wraps, tags and encodes a token.

  Anatomy of an encoded token:
    base64(<version byte> + payload json + mac(<version byte> + payload json))
  Where:
    <version byte> - one byte that defines version of a token format.
    payload json - compactly serialized json dict with token payload.
    mac - binary MAC tag of known size (may depend on version).
  """
  assert isinstance(version, int) and 0 <= version <= 255
  assert isinstance(secret, str) and secret
  assert isinstance(embedded, dict)
  assert isinstance(message, (list, tuple))
  assert embedded or message
  public = json.dumps(embedded, sort_keys=True, separators=(',', ':'))
  mac = compute_mac(secret, [str(version), public] + message, algo)
  return base64_encode(''.join([chr(version), public, mac]))


def decode_token(token, possible_secrets, message, algo):
  """Decodes, checks MAC tag and unwraps a token."""
  assert isinstance(possible_secrets, (list, tuple)) and possible_secrets
  assert isinstance(token, str)
  assert isinstance(message, (list, tuple))

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
    good_mac = compute_mac(secret, [str(version), public] + message, algo)
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
  return version, json.loads(public)
