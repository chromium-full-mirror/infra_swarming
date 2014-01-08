# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""ACL management UI handlers.

It's mostly Javascript-side application that uses service public API,
so not much code here.
"""

import jinja2
import json
import os
import webapp2

from google.appengine.api import users
from google.appengine.ext import ndb

from components import auth
from components.auth import model
from components.auth import utils


ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
JINJA = jinja2.Environment(
    loader=jinja2.FileSystemLoader(os.path.join(ROOT_DIR, 'templates')),
    extensions=['jinja2.ext.autoescape'],
    autoescape=True)


# Top navigation bar links as tuple (id, title, url, auth resource).
NAVBAR_SECTIONS = (
    ('rules', 'Rules', '/auth/rules', 'auth/management/ui'),
    ('groups', 'Groups', '/auth/groups', 'auth/management/ui'),
    ('oauth_config', 'OAuth', '/auth/oauth-config', 'auth/management/ui'),
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

  template_file = None
  css_file = None
  js_file = None
  navbar_tab_id = None
  page_title = None

  def reply(self, path=None, env=None, status=200):
    """Render template |path| to response using given environment."""
    path = path or self.template_file
    assert path

    # This goes to both jinja2 env and javascript config.
    common = {
      'login_url': users.create_login_url(self.request.path),
      'logout_url': users.create_logout_url('/'),
      'xsrf_token': self.generate_xsrf_token(),
    }

    # This will be accessible from js as for global 'config' variable.
    js_config = {
      'identity': auth.get_current_identity().to_bytes(),
    }
    js_config.update(common)

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
      'config': json.dumps(js_config),
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
    self.response.headers['Content-Type'] = 'text/html; charset=UTF-8'
    self.response.write(JINJA.get_template(path).render(full_env))

  def authorization_error(self, error):
    """Redirects to login or shows 'Access Denied' page."""
    if auth.get_current_identity().is_anonymous:
      self.redirect(users.create_login_url(self.request.path))
    else:
      env = {
        'page_title': 'Access Denied',
        'error': error,
      }
      self.reply('access_denied.html', env=env, status=403)

  @auth.require(auth.READ, 'auth/management/ui')
  def get(self):
    self.reply()


class MainHandler(UIHandler):
  """Blindly redirects to /auth/rules (that is default ACL UI tab)."""
  @auth.require(auth.READ, 'auth/management/ui')
  def get(self):
    self.redirect('/auth/rules')


class RulesHandler(UIHandler):
  """Renders HTML page with ACLs management UI."""
  template_file = 'rules.html'
  js_file = 'rules.js'
  navbar_tab_id = 'rules'
  page_title = 'ACL Rules'


class GroupsHandler(UIHandler):
  """Renders HTML page with Group listing."""
  template_file = 'groups.html'
  js_file = 'groups.js'
  navbar_tab_id = 'groups'
  page_title = 'ACL Groups'


class OAuthConfigHandler(UIHandler):
  """Renders HTML page with OAuth configuration."""
  template_file = 'oauth_config.html'
  navbar_tab_id = 'oauth_config'
  page_title = 'OAuth Config'

  @auth.require(auth.READ, 'auth/management/oauth')
  def get(self):
    oauth_client_id = None
    additional_oauth_client_ids = None

    # Read OAuth config from model.
    service_config = model.AuthServiceConfig.get_by_id(
        'default', parent=model.ROOT_KEY)
    oauth_client_id = service_config.oauth_client_id
    oauth_callback_uri = service_config.oauth_callback_uri
    global_config = model.ROOT_KEY.get()
    additional_oauth_client_ids = global_config.oauth_client_ids

    env = {
      'client_id': oauth_client_id or '',
      'callback_uri': oauth_callback_uri or '',
      'additional_client_ids': '\n'.join(additional_oauth_client_ids or []),
    }
    self.reply(env=env)

  @auth.require(auth.UPDATE, 'auth/management/oauth')
  def post(self):
    # Extract data from the form.
    client_id = self.request.get('client_id')
    callback_uri = self.request.get('callback_uri')
    client_secret = self.request.get('client_secret')
    if '*' in client_secret:
      client_secret = None
    additional_client_ids = [
      x.strip() for x in self.request.get('additional_client_ids').split('\n')
      if x.strip()
    ]

    # Store.
    @ndb.transactional
    def update():
      # AuthServiceConfig first.
      service_config = model.AuthServiceConfig.get_by_id(
          'default', parent=model.ROOT_KEY)
      service_config.oauth_client_id = client_id
      service_config.oauth_callback_uri = callback_uri
      if client_secret:
        service_config.oauth_client_secret = client_secret
      service_config.put()
      # AuthGlobalConfig next.
      global_config = model.ROOT_KEY.get()
      global_config.oauth_client_ids = additional_client_ids
      global_config.put()

    update()
    self.redirect(self.request.uri)


class OAuthGetTokenHandler(UIHandler):
  """Initiates OAuth2 login flow."""

  @auth.public
  def get(self):
    try:
      self.redirect(auth.start_oauth_flow())
    except auth.OAuthError as err:
      env = {
        'page_title': 'OAuth Error',
        'error': error,
      }
      self.reply('oauth_error.html', env=env, status=403)


class OAuthCallbackHandler(UIHandler):
  """Completes OAuth2 login flow."""

  @auth.public
  def get(self):
    # OAuth provider returned error?
    error = self.request.get('error')
    if error:
      env = {
        'page_title': 'OAuth Error',
        'error': self.request.get('error_description', error),
      }
      return self.reply('oauth_error.html', env=env, status=403)

    # Try to exchange authorization code into access_token.
    try:
      identity, state, access_token, expiration_ts = auth.finish_oauth_flow(
          self.request.get('code'), self.request.get('state'))
    except auth.OAuthError as err:
      env = {
        'page_title': 'OAuth Error',
        'error': str(err),
      }
      return self.reply('oauth_error.html', env=env, status=403)

    # Show access token to user.
    env = {
      'page_title': 'Token obtained',
      'identity': identity,
      'access_token': access_token,
    }
    self.reply('oauth_success.html', env=env)


def get_routes():
  """Return a list of webapp2 routes to add to WSGI application."""
  return [
    webapp2.Route(r'/auth', MainHandler),
    webapp2.Route(r'/auth/rules', RulesHandler),
    webapp2.Route(r'/auth/groups', GroupsHandler),
    webapp2.Route(r'/auth/oauth-config', OAuthConfigHandler),
    webapp2.Route(r'/auth/oauth-get-token', OAuthGetTokenHandler),
    webapp2.Route(r'/auth/oauth-callback', OAuthCallbackHandler),
  ]
