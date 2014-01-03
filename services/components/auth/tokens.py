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

__all__ = ['InvalidTokenError', 'Token']


# Name -> (hash to use, how many bytes of digest to use).
MAC_ALGOS = {
  'hmac256-128': (hashlib.sha256, 16),
}


class InvalidTokenError(ValueError):
  """Token validation failed."""


class Token(object):
  """Base class for token types."""

  # What algo to use for MAC tag.
  algo = 'hmac256-128'
  # Will be added to tagged message so that tokens of different kinds always
  # have different tags (even if payload, secret, timestamp, etc. matches).
  kind = 'unknown'
  # Format version number that will be embedded into the token.
  version = '1'
  # If set defines how long token can live.
  expiration_sec = None
  # Name of the secret key to use when generating and validating the token.
  # Must be an instance of LocalSecret or GlobalSecret.
  secret_id = None

  @classmethod
  def generate(cls, message, embedded=None):
    """Generates a token that contains signature for |message|."""
    embedded = (embedded or {}).copy()
    assert not any(k.startswith('_') for k in embedded), '_<id> is reserved'
    embedded['_v'] = cls.version
    if cls.expiration_sec is not None:
      embedded['_x'] = str(int(time.time() * 1000 + cls.expiration_sec * 1000))
    return encode_token(
        api.get_secret(cls.secret_id), [cls.kind] + message, embedded, cls.algo)

  @classmethod
  def validate(cls, token, message):
    """Validates token signature and extracts embedded data from token."""
    embedded = decode_token(
        token, api.get_secret(cls.secret_id), [cls.kind] + message, cls.algo)
    version = embedded.pop('_v', None)
    if version != cls.version:
      raise InvalidTokenError(
          'Bad token format version. '
          'Expected %r, got %r.' % (cls.version, version))
    if cls.expiration_sec is not None:
      expiration_ts = embedded.pop('_x', None)
      if expiration_ts is None:
        raise InvalidTokenError('Bad token: expiration timestamp is missing.')
      if time.time() * 1000 > int(expiration_ts):
        raise InvalidTokenError('Bad token: expired.')
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
  hash_algo, digest_size = MAC_ALGOS[algo]
  mac = hmac.new(secret, digestmod=hash_algo)
  for chunk in chunks:
    assert isinstance(chunk, basestring)
    if isinstance(chunk, unicode):
      chunk = chunk.encode('utf-8')
    mac.update(str(len(chunk)))
    mac.update(chunk)
  return mac.digest()[:digest_size]


def encode_token(secret, message, embedded, algo):
  """Wraps, tags and encodes a token."""
  assert isinstance(secret, str) and secret
  assert isinstance(embedded, dict)
  assert isinstance(message, list)
  assert embedded or message
  public = json.dumps(embedded, sort_keys=True, separators=(',', ':'))
  mac = compute_mac(secret, [public] + message, algo)
  return base64_encode(public + mac)


def decode_token(token, secret, message, algo):
  """Decodes, checks MAC tag and unwraps a token."""
  assert isinstance(secret, str) and secret
  assert isinstance(token, str)
  assert isinstance(message, list)

  # Unwrap payload and MAC.
  _, digest_size = MAC_ALGOS[algo]
  try:
    binary = base64_decode(token)
    if len(binary) <= digest_size:
      raise ValueError()
    public, mac = binary[:-digest_size], binary[-digest_size:]
  except ValueError:
    raise InvalidTokenError('Bad token format: %r.' % token)

  # Validate MAC tag in constant time.
  good_mac = compute_mac(secret, [public] + message, algo)
  assert len(good_mac) == len(mac)
  accum = 0
  for x, y in zip(mac, good_mac):
    accum |= ord(x) ^ ord(y)
  if accum:
    raise InvalidTokenError('Bad token MAC.')

  # Return embedded token data.
  return json.loads(public)
