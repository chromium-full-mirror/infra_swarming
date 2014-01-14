# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""Main public interface of auth_ui component."""

from . import rest_api
from . import ui

__all__ = ['configure', 'get_routes']


def configure(app_name, app_version, app_revision_url):
  """Global configuration of some UI parameters."""
  ui.ui_config.app_name = app_name
  ui.ui_config.app_version = app_version
  ui.ui_config.app_revision_url = app_revision_url


def get_routes():
  """Return a list of webapp2 routes to add to WSGI application."""
  return rest_api.get_routes() + ui.get_routes()
