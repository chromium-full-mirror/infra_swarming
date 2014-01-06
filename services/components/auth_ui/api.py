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


class ApiHandler(auth.AuthenticatingHandler):
  """Parses JSON request body to dict."""

  # Content type of requests and responses.
  content_type = 'application/json; charset=UTF-8'

  def validate_request_format(self):
    """Ensures body has JSON content type."""
    if self.request.body:
      content_type = self.request.headers.get('Content-Type')
      if content_type != self.content_type:
        msg = 'Expecting JSON body with content type \'%s\'' % self.content_type
        self.abort_with_error(400, text=msg)

  def authentication_error(self, error):
    self.abort_with_error(401, text=str(error))

  def authorization_error(self, error):
    self.abort_with_error(403, text=str(error))

  def send_response(self, response, http_code=200, headers=None):
    """Sends successful reply and continues execution."""
    self.response.set_status(http_code)
    self.response.headers.update(headers or {})
    self.response.headers['Content-Type'] = self.content_type
    self.response.write(json.dumps(response))

  def abort_with_error(self, http_code, **kwargs):
    """Sends error reply and stops execution."""
    self.abort(http_code,
        json=kwargs, headers={'Content-Type': self.content_type})

  def parse_body(self):
    """Parse body json and verifies it\'s a dict that has given keys."""
    try:
      body = json.loads(self.request.body)
      if not isinstance(body, dict):
        raise ValueError()
    except ValueError:
      self.abort_with_error(400, text='Not a valid json dict body')
    return body


@route('/auth/api/v1/accounts/me')
class MeHandler(ApiHandler):
  """Shows identity of a caller."""

  @auth.public
  def get(self):
    self.send_response({'identity': auth.get_current_identity().to_bytes()})


@route('/auth/api/v1/xsrf_token')
class XSRFHandler(ApiHandler):
  """Generates XSRF token on demand."""

  # Don't enforce prior XSRF token, it might not be known yet.
  enforce_xsrf_token = ()

  @auth.public
  def post(self):
    if not self.request.headers.get('X-XSRF-Token-Request'):
      raise auth.AuthorizationError('Missing required XSRF request header')
    self.send_response({'xsrf_token': self.generate_xsrf_token()})


@route('/auth/api/v1/groups')
class GroupsHandler(ApiHandler):
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
class GroupHandler(ApiHandler):
  """Creating, reading, updating and deleting a single group."""

  def parse_group_body(self, group):
    """JSON request body -> dict with AuthGroup properties."""
    try:
      body = self.parse_body()
      name = body.pop('name', None)
      if not name or name != group:
        raise ValueError('Missing or mismatching group name in request body')
      return model.AuthGroup.convert_simple_dict(body)
    except (ValueError, TypeError) as err:
      self.abort_with_error(400, text=str(err))

  @auth.require(auth.READ, 'auth/management/groups/{group}')
  def get(self, group):
    """Fetch all information about existing group."""
    entity = model.AuthGroup.get_by_id(group, parent=model.ROOT_KEY)
    if not entity:
      self.abort_with_error(404, text='No such group')
    headers = {
      'Last-Modified': utils.datetime_to_rfc2822(entity.modified_ts),
    }
    self.send_response(
        {'group': entity.to_simple_dict(with_id_as='name')}, headers=headers)

  @auth.require(auth.UPDATE, 'auth/management/groups/{group}')
  def put(self, group):
    """Update existing group."""

    @ndb.transactional
    def update(params):
      # Missing?
      entity = model.AuthGroup.get_by_id(group, parent=model.ROOT_KEY)
      if not entity:
        self.abort_with_error(404, text='No such group')
      # Midair collision?
      given = self.request.headers.get('If-Unmodified-Since')
      expected = utils.datetime_to_rfc2822(entity.modified_ts)
      if given and given != expected:
        self.abort_with_error(412, text='Group was modified by someone else')
      # Update, store.
      entity.populate(**params)
      entity.modified_by = auth.get_current_identity()
      entity.put()
      self.send_response({'ok': True})

    # Run the transaction.
    update(self.parse_group_body(group))

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
        self.abort_with_error(409, text='Such group already exists')
      entity.put()
      headers = {
        'Last-Modified': utils.datetime_to_rfc2822(entity.modified_ts),
        'Location': '/auth/api/v1/groups/%s' % urllib.quote(entity.key.id()),
      }
      self.send_response({'ok': True}, http_code=201, headers=headers)

    # Run the transaction.
    create()

  @auth.require(auth.DELETE, 'auth/management/groups/{group}')
  def delete(self, group):
    """Delete existing group."""
    key = ndb.Key(model.AuthGroup, group, parent=model.ROOT_KEY)
    key.delete()
    self.send_response({'ok': True})


@route('/auth/api/v1/rules')
class RulesHandler(ApiHandler):
  """Reading and updating ACL rules."""

  @auth.require(auth.READ, 'auth/management/rules')
  def get(self):
    """Fetch all ACL rules."""
    entity = model.AuthServiceConfig.get_or_insert(
        'default', parent=model.ROOT_KEY)
    headers = {
      'Last-Modified': utils.datetime_to_rfc2822(entity.modified_ts),
    }
    self.send_response(entity.to_simple_dict(), headers=headers)

  @auth.require(auth.UPDATE, 'auth/management/rules')
  def put(self):
    """Update all ACL rules."""

    @ndb.transactional
    def update(params):
      # Missing?
      entity = model.AuthServiceConfig.get_by_id(
          'default', parent=model.ROOT_KEY)
      # Midair collision?
      given = self.request.headers.get('If-Unmodified-Since')
      expected = utils.datetime_to_rfc2822(entity.modified_ts)
      if given and given != expected:
        self.abort_with_error(412, text='Rules were modified by someone else')
      # Update, store.
      entity.populate(**params)
      entity.modified_by = auth.get_current_identity()
      entity.put()
      # Done.
      self.send_response({'ok': True})

    # Run the transaction.
    try:
      update(model.AuthServiceConfig.convert_simple_dict(self.parse_body()))
    except (ValueError, TypeError) as err:
      self.abort_with_error(400, text=str(err))


@route('/auth/api/v1/rules/check')
class RulesHandler(ApiHandler):
  """Executing test queries against ACL rules."""

  @auth.require(auth.UPDATE, 'auth/management/rules')
  def post(self):
    """Check given ACL rules."""
    # Convert request body to dict.
    body = self.parse_body()

    # Parse identity (if given).
    identity = body.get('identity')
    if identity:
      try:
        identity = model.Identity.from_bytes(identity)
      except (ValueError, TypeError) as err:
        self.abort_with_error(400, text=str(err))
    else:
      identity = None

    # Extract resource (if given).
    resource = body['resource'] if body.get('resource') else None
    if resource and not isinstance(resource, basestring):
      self.abort_with_error(400, text='Bad resource name')

    # Extract action (if given).
    action = body['action'] if body.get('action') else None
    if action and action not in model.ALLOWED_ACTIONS:
      self.abort_with_error(400, text='Invalid action')

    # Parse 'rules' into AccessRule list.
    try:
      if not isinstance(body.get('rules'), list):
        raise ValueError('Missing or invalid \'rules\' entry')
      rule_list = [model.AccessRule.from_jsonish(r) for r in body['rules']]
    except (ValueError, TypeError) as err:
      self.abort_with_error(400, text=str(err))

    # Construct AuthDB with rules under test and all existing groups.
    auth_db = model.AuthDB(
        service_config=model.AuthServiceConfig(rules=rule_list),
        groups=model.AuthGroup.query(ancestor=model.ROOT_KEY).fetch())

    # Response will contain these.
    unrecognized_groups = None
    identity_groups = None
    matching_rules = None

    # Get all rules that mention non-existing groups.
    groups = auth_db.get_groups() | set('*')
    unrecognized_groups = [
      rule.group for rule in auth_db.get_rules()
      if rule.group not in groups
    ]

    # Identity is given -> see what groups it belongs to.
    if identity:
      identity_groups = sorted(auth_db.get_groups(identity))

    # Identity or resource given -> see relevant rules.
    if identity or action or resource:
      matching_rules = [
        rule.to_jsonish()
        for rule in auth_db.get_matching_rules(identity, action, resource)
      ]

    # Done.
    self.send_response({
      'identity': identity.to_bytes() if identity else None,
      'resource': resource,
      'action': action,
      'unrecognizedGroups': unrecognized_groups,
      'identityGroups': identity_groups,
      'matchingRules': matching_rules,
    })
