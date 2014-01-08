# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""OAuth2 login flow implementation."""

import httplib2
import json
import os
import sys

from google.appengine.api import urlfetch

from oauth2client import appengine
from oauth2client import client

from . import api
from . import model
from . import tokens
from . import utils

__all__ = [
  'OAuthError', 'refresh_oauth_access_token',
  'start_oauth_flow', 'finish_oauth_flow',
]


# OAuth2 service scope to use for authentication.
EMAIL_SCOPE = 'https://www.googleapis.com/auth/userinfo.email'


class OAuthError(Exception):
  """OAuth related error."""

  def __init__(self, message, inner=None):
    super(OAuthError, self).__init__(message)
    self.inner = inner


class OAuthStateToken(tokens.Token):
  """Used to sign OAuth 'state' block passed between client and provider."""
  kind = 'oauth_state_token'
  expiration_sec = 60
  secret_key = api.SecretKey('xsrf_token', 'local')


def refresh_oauth_access_token(identity):
  """Refreshes access_token using refresh_token stored in DB.

  Returns tuple (access_token, expiration_timestamp).

  Raises OAuthError if user is required to go through full login flow.
  """
  # Get refresh_token from DB.
  storage = credentials_storage(identity)
  credentials = storage.get()
  if credentials is None or credentials.invalid:
    raise OAuthError('Refresh token is not known or invalid')

  # User refresh_token to get new access_token.
  if credentials.access_token is None or credentials.access_token_expired:
    try:
      credentials.refresh(httplib2.Http())
    except client.Error as err:
      raise OAuthError('OAuth error: %s' % err, inner=err)
    storage.put(credentials)

  return credentials.access_token, to_timestamp(credentials.token_expiry)


def start_oauth_flow(state=None):
  """Returns URI to redirect a client to start OAuth2 login dance.

  Current identity is ignored. OAuth2 flow always finishes with establishing
  a new identity.

  Raises OAuthError on error.
  """
  flow = create_flow()
  if not flow:
    raise OAuthError('OAuth is not configured')
  flow.params['state'] = OAuthStateToken.generate(embedded=state)
  return flow.step1_get_authorize_url()


def finish_oauth_flow(code, state):
  """Finishes OAuth2 login dance, should be called from OAuth2 callback.

  Current identity is ignored. OAuth2 flow always finishes with establishing
  a new identity.

  Returns tuple (Identity, state dict, access_token, expiration_timestamp).
  Raises OAuthError on error.
  """
  # Validate state MAC, deserialize state.
  try:
    state = OAuthStateToken.validate(state)
  except tokens.InvalidTokenError as err:
    raise OAuthError('State token is invalid or expired', inner=err)

  flow = create_flow()
  if flow is None:
    raise OAuthError('OAuth is not configured')

  # Convert grant into refresh_token and access_token.
  try:
    credentials = flow.step2_exchange(code)
  except client.Error as err:
    raise OAuthError('OAuth error: %s' % err, inner=err)

  # access_token should be valid and fresh.
  if not credentials.access_token or credentials.access_token_expired:
    raise OAuthError('OAuth error: access token is missing or expired')
  access_token = credentials.access_token

  # Get email associated with that access token.
  user_email = get_user_email(access_token)
  identity = model.Identity(model.IDENTITY_USER, user_email)

  # Associate refresh_token with that identity in Datastore.
  credentials_storage(identity).put(credentials)

  # Return all that back to caller.
  return identity, state, access_token, to_timestamp(credentials.token_expiry)


def get_user_email(access_token):
  """Performs call to Google API to get email associated with a token."""
  response = urlfetch.fetch(
      url='https://www.googleapis.com/oauth2/v2/userinfo',
      headers={'Authorization': 'Bearer %s' % access_token},
      validate_certificate=True)
  if response.status_code != 200:
    raise OAuthError('Failed to get user profile: %s' % response.content)
  if response.headers['Content-type'] != 'application/json; charset=UTF-8':
    raise OAuthError('Failed to get user profile: unexpected content type')
  # Format of the response:
  # {
  #   "id": "......", // optional
  #   "email": ".....",
  #   "verified_email": true,
  #   "hd": "....." // optional
  # }
  user_info = json.loads(response.content)
  assert isinstance(user_info, dict)
  return user_info['email']


def create_flow():
  """Returns OAuth2WebServerFlow or None if OAuth is not configured."""
  auth_db = api.get_request_auth_db()
  client_id, client_secret, callback_uri = auth_db.get_oauth_config()
  if not client_id or not client_secret or not callback_uri:
    return None
  return client.OAuth2WebServerFlow(
      client_id, client_secret, EMAIL_SCOPE,
      redirect_uri=callback_uri, approval_prompt='force')


def credentials_storage(identity):
  """Returns oauth2client.Storage for given identity."""
  assert identity and identity.is_user
  return appengine.StorageByKeyName(
      model.AuthAccountOAuth2, identity.to_bytes(), 'oauth_credentials')


def to_timestamp(dt):
  """Convert datetime to Unix timestamp."""
  return utils.datetime_to_timestamp(dt) / 1000 if dt else None
