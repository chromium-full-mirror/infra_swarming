# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""ACL management API handlers."""

import json
import webapp2

from components import auth
from components.auth import model


class ApiHandler(auth.AuthenticatingHandler):
  def reply(self, result):
    self.response.headers['Content-Type'] = 'application/json;charset=UTF-8'
    self.response.write(json.dumps(result))


class MeHandler(ApiHandler):
  @auth.public
  def get(self):
    me = auth.get_current_identity()
    self.reply({'me': me.to_string()})


class GroupsHandler(ApiHandler):
  @auth.require(auth.UPDATE, 'auth/management/groups')
  def get(self):
    groups = model.fetch_groups()
    self.reply({
      'groups': dict((name, g.to_dict()) for name, g in groups.iteritems()),
    })


def get_routes():
  """Return a list of webapp2 API routes to add to WSGI application."""
  return [
    # API handlers.
    webapp2.Route(r'/auth/api/v1/me', MeHandler),
    webapp2.Route(r'/auth/api/v1/groups', GroupsHandler),
  ]
