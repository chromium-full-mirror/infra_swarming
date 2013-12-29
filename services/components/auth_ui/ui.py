# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""ACL management UI handlers."""

import jinja2
import json
import os
import webapp2

from google.appengine.api import users

from components import auth


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
JINJA = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(ROOT_DIR, 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


# Top navigation bar links as tuple (id, title, url, auth resource).
NAVBAR_SECTIONS = (
    ('main', 'Main', '/auth', 'auth/management/ui'),
)

class UIConfig(object):
  """Global static configuration set in 'configure'."""
  app_name = 'Unknown'
  app_revision_url = 'about:blank'
  app_version = 'unknown'

# Note: this variable is accessed in main.py.
ui_config = UIConfig()


class UIHandler(auth.AuthenticatingHandler):
  """Renders HTML pages that extend base.html template."""

  css_file = None
  js_file = None
  navbar_tab_id = None
  page_title = 'ACL Configuration'

  def reply(self, path, env=None, js_config=None, status=200):
    """Render template |path| to response using given environment."""
    # This goes to both jinja2 env and javascript config.
    common = {
      'login_url': users.create_login_url(self.request.path),
      'logout_url': users.create_logout_url('/'),
    }

    # This will be accessible from js as for global 'config' variable.
    full_js_config = {
      'identity': auth.get_current_identity().to_string(),
    }
    full_js_config.update(common)
    full_js_config.update(js_config or {})

    # Filter navbar tabs by removing ones inaccessible to current user.
    navbar = [
      (tab_id, title, url) for tab_id, title, url, resource in NAVBAR_SECTIONS
      if auth.has_permission(auth.READ, resource)
    ]

    # Jinja2 environment to render a template.
    full_env = {
      'app_name': ui_config.app_name,
      'app_revision_url': ui_config.app_revision_url,
      'app_version': ui_config.app_version,
      'config': json.dumps(full_js_config),
      'css_file': self.css_file,
      'identity': auth.get_current_identity(),
      'js_file': self.js_file,
      'navbar': navbar,
      'navbar_tab_id': self.navbar_tab_id,
      'page_title': self.page_title,
    }
    full_env.update(common)
    full_env.update(env or {})

    # Render it.
    self.response.set_status(status)
    self.response.headers['Content-Type'] = 'text/html;charset=UTF-8'
    self.response.write(JINJA.get_template(path).render(full_env))

  def authorization_error(self, error):
    """Redirects to login or shows 'Access Denied' page."""
    if auth.get_current_identity().is_anonymous:
      self.redirect(users.create_login_url(self.request.path))
    else:
      self.reply('access_denied.html', env={'error': error})


class MainHandler(UIHandler):
  """Renders HTML page with ACLs management UI."""

  page_title = 'ACL Configuration Main'
  js_file = 'main.js'
  navbar_tab_id = 'main'

  @auth.require(auth.READ, 'auth/management/ui')
  def get(self):
    self.reply('main.html')


def get_routes():
  """Return a list of webapp2 routes to add to WSGI application."""
  return [
    webapp2.Route(r'/auth', MainHandler),
  ]
