# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""ACL management public API."""

import json
import urllib
import webapp2

from google.appengine.ext import ndb

from components import auth
from components.auth import model
from components.auth import utils


# webapp2 routes defined in this file, collected by 'route' decorator.
_routes = []


def get_routes():
  """Return a list of webapp2 API routes to add to WSGI application."""
  return _routes


def route(regexp):
  """Tiny class decorator that just collects webapp2 routes from this file."""
  def decorator(cls):
    _routes.append(webapp2.Route(regexp, cls))
    return cls
  return decorator


class AuthApiHandler(auth.ApiHandler):
  """Parses JSON request body to dict."""

  def parse_body(self, required_keys=None):
    """Parse body json and verifies it\'s a dict that has given keys."""
    try:
      body = json.loads(self.request.body)
    except ValueError:
      self.abort_with_error(400, text='Not a valid json body.')
    if not isinstance(body, dict):
      self.abort_with_error(400, text='Expecting json dict.')
    for key in (required_keys or []):
      if key not in body:
        self.abort_with_error(400, text='Missing required key \'%s\'.' % key)
    return body


@route('/auth/api/v1/xsrf_token')
class XSRFHandler(AuthApiHandler):
  """Generates XSRF token on demand."""

  # Don't enforce prior XSRF token, it might not be known yet.
  enforce_xsrf_token = ()

  @auth.public
  def post(self):
    if not self.request.headers.get('X-XSRF-Token-Request'):
      raise auth.AuthorizationError('Missing required XSRF request header')
    self.send_response({'xsrf_token': self.generate_xsrf_token()})


@route('/auth/api/v1/groups')
class GroupsHandler(AuthApiHandler):
  """Group listing."""

  @auth.require(auth.READ, 'auth/management/groups')
  def get(self):
    groups = model.AuthGroup.query(ancestor=model.ROOT_KEY).fetch()
    self.send_response({
      'groups': [
        g.to_simple_dict(with_id_as='name') for g in groups
      ],
    })


@route('/auth/api/v1/groups/<group:%s>' % model.GROUP_NAME_RE.pattern)
class GroupHandler(AuthApiHandler):
  """Creating, reading, updating and deleting a single group."""

  @staticmethod
  def last_modified_header(group_entity):
    """Value of 'Last-Modified' header based on |modified_ts|."""
    return utils.datetime_to_rfc2822(group_entity.modified_ts or 0)

  @staticmethod
  def location_header(group_entity):
    """Value of 'Location' header based on group entity key."""
    return '/auth/api/v1/groups/%s' % urllib.quote(group_entity.key.string_id())

  def parse_group_body(self, group):
    """JSON request body -> dict with AuthGroup properties."""
    try:
      body = self.parse_body(required_keys=('name',))
      name = body.pop('name')
      if name != group:
        raise ValueError('Mismatching group name.')
      return model.AuthGroup.convert_simple_dict(body)
    except (ValueError, TypeError) as err:
      self.abort_with_error(400, text=str(err))

  @auth.require(auth.READ, 'auth/management/groups/{group}')
  def get(self, group):
    """Fetch all information about existing group."""
    entity = model.AuthGroup.get_by_id(group, parent=model.ROOT_KEY)
    if not entity:
      self.abort_with_error(404, text='No such group.')
    headers = {
      'Last-Modified': self.last_modified_header(entity),
    }
    self.send_response(
        {'group': entity.to_simple_dict(with_id_as='name')}, headers=headers)

  @auth.require(auth.UPDATE, 'auth/management/groups/{group}')
  def put(self, group):
    """Update existing group."""
    # Validate request body.
    params = self.parse_group_body(group)

    @ndb.transactional
    def update():
      # Missing?
      entity = model.AuthGroup.get_by_id(group, parent=model.ROOT_KEY)
      if not entity:
        self.abort_with_error(404, text='No such group.')
      # Midair collision?
      condition = self.request.headers.get('If-Unmodified-Since')
      if condition and self.last_modified_header(entity) != condition:
        self.abort_with_error(412, text='Group was modified by someone else.')
      # Update, store.
      entity.populate(**params)
      entity.modified_by = auth.get_current_identity()
      entity.put()
      # Done.
      self.send_response({'ok': True})

    # Run the transaction.
    update()

  @auth.require(auth.CREATE, 'auth/management/groups/{group}')
  def post(self, group):
    """Create a new group, ensuring it's indeed new."""
    # Validate request body.
    params = self.parse_group_body(group)

    # Prepare entity for transaction.
    entity = model.AuthGroup(id=group, parent=model.ROOT_KEY)
    entity.populate(**params)
    entity.created_by = auth.get_current_identity()
    entity.modified_by = auth.get_current_identity()

    # Create the entity if it doesn't exist.
    @ndb.transactional
    def create():
      if entity.key.get():
        self.abort_with_error(409, text='Such group already exists.')
      entity.put()
      headers = {
        'Last-Modified': self.last_modified_header(entity),
        'Location': self.location_header(entity),
      }
      self.send_response({'ok': True}, http_code=201, headers=headers)
    create()

  @auth.require(auth.DELETE, 'auth/management/groups/{group}')
  def delete(self, group):
    """Delete existing group."""
    key = ndb.Key(model.AuthGroup, group, parent=model.ROOT_KEY)
    key.delete()
    self.send_response({'ok': True})


@route('/auth/api/v1/rules')
class RulesHandler(AuthApiHandler):
  """Reading and updating ACL rules."""

  @staticmethod
  def last_modified_header(rules_entity):
    """Value of 'Last-Modified' header based on |modified_ts|."""
    return utils.datetime_to_rfc2822(rules_entity.modified_ts or 0)

  @auth.require(auth.READ, 'auth/management/rules')
  def get(self):
    """Fetch all ACL rules."""
    entity = model.AuthRules.get_or_insert(
        model.ROOT_KEY.id(),
        rules=model.RuleList(),
        modified_by=auth.get_current_identity())
    assert entity.key == model.ROOT_KEY
    headers = {
      'Last-Modified': self.last_modified_header(entity),
    }
    self.send_response(entity.to_simple_dict(), headers=headers)

  @auth.require(auth.UPDATE, 'auth/management/rules')
  def put(self):
    # Parse and validate body.
    try:
      params = model.AuthRules.convert_simple_dict(self.parse_body())
    except (ValueError, TypeError) as err:
      self.abort_with_error(400, text=str(err))

    @ndb.transactional
    def update():
      # Missing?
      entity = model.ROOT_KEY.get()
      # Midair collision?
      condition = self.request.headers.get('If-Unmodified-Since')
      if condition and self.last_modified_header(entity) != condition:
        self.abort_with_error(412, text='Rules were modified by someone else.')
      # Update, store.
      entity.populate(**params)
      entity.modified_by = auth.get_current_identity()
      entity.put()
      # Done.
      self.send_response({'ok': True})

    # Run the transaction.
    update()
