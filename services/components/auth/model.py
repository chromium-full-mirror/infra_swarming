# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""NDB model classes used to model AuthDB relations."""

import collections
import fnmatch
import re

from google.appengine.ext import ndb
from google.appengine.ext.ndb import metadata

from . import utils

__all__ = [
  'CREATE', 'DELETE', 'READ', 'UPDATE', 'GROUP_NAME_RE',
  'Identity', 'IdentityProperty', 'Anonymous', 'IdentityGlob',
  'IdentityGlobProperty',
]


# Possible actions that can be applied to a resource.
CREATE = 0
DELETE = 1
READ = 2
UPDATE = 3

# Dict of actions with their names.
ALLOWED_ACTIONS = {
    CREATE: 'CREATE',
    DELETE: 'DELETE',
    READ: 'READ',
    UPDATE: 'UPDATE',
}

# No identity information is provided. Identity name is always 'anonymous'.
IDENTITY_ANONYMOUS = 'anonymous'
# Using bot credentials. Identity name is bot's access_id.
IDENTITY_BOT = 'bot'
# Using App Engine service credentials. Identity name is service URL.
IDENTITY_SERVICE = 'service'
# Using user credentials. Identity name is user's email.
IDENTITY_USER = 'user'

# All allowed identity kinds + regexps that describe possible identity name.
ALLOWED_IDENTITY_KINDS = {
    IDENTITY_ANONYMOUS: re.compile(r'anonymous$'),
    IDENTITY_BOT: re.compile(r'[0-9a-zA-Z_\-\.@]+$'),
    IDENTITY_SERVICE: re.compile(r'[0-9a-zA-Z_\-\.]+$'),
    IDENTITY_USER: re.compile(r'[0-9a-zA-Z_\-\.@]+$'),
}

# Rule types.
ALLOW_RULE = 'allow'
DENY_RULE = 'deny'

# Regular expression that matches group names.
GROUP_NAME_RE = re.compile(r'[0-9a-zA-Z_\-\. ]{3,40}$')

# Global root key of AuthRules entity group.
ROOT_KEY = ndb.Key('AuthRules', 'default')


class Identity(
    utils.StringSerializable,
    collections.namedtuple('Identity', ['kind', 'name'])):
  """Represents a caller that can make requests.

  A tuple of (kind, name) where 'kind' is one of IDENTITY_* constants and
  meaning of 'name' depends on kind. It generalizes real people accounts and bot
  accounts.

  It's a pure identity information. Any additional information that may be
  related to an identity (like maybe registration date, etc.) should be stored
  elsewhere using Identity.to_string() as a primary key.
  """

  def __init__(self, kind, name):
    if (kind not in ALLOWED_IDENTITY_KINDS or
        not ALLOWED_IDENTITY_KINDS[kind].match(name)):
      raise TypeError('Identity has invalid format.')
    super(Identity, self).__init__(kind, name)

  def to_string(self):
    """Serializes this identity to string."""
    return '%s:%s' % (self.kind, self.name)

  @classmethod
  def from_string(cls, string):
    """Given a string returns corresponding Identity object."""
    kind, sep, name = string.partition(':')
    if not sep:
      raise TypeError('Missing \':\' separator in Identity string.')
    return cls(kind, name)

  @property
  def is_anonymous(self):
    """True if this object represents anonymous identity."""
    return self.kind == IDENTITY_ANONYMOUS


# Predefined Anonymous identity. While not strictly a singleton, it's still can
# be used in comparisons like identity_obj == Anonymous.
Anonymous = Identity(IDENTITY_ANONYMOUS, 'anonymous')


class IdentityGlob(
    utils.StringSerializable,
    collections.namedtuple('IdentityGlob', ['kind', 'pattern'])):
  """Glob like pattern that matches subset of identities."""

  def __init__(self, kind, pattern):
    if kind not in ALLOWED_IDENTITY_KINDS:
      raise TypeError('Invalid Identity kind: %s.' % kind)
    if ':' in pattern:
      raise TypeError('Invalid IdentityGlob pattern: %s' % pattern)
    super(IdentityGlob, self).__init__(kind, pattern)

  def to_string(self):
    """Serializes this identity glob to string."""
    return '%s:%s' % (self.kind, self.pattern)

  @classmethod
  def from_string(cls, string):
    """Given a string returns corresponding IdentityGlob object."""
    kind, sep, pattern = string.partition(':')
    if not sep:
      raise TypeError('Missing \':\' separator in IdentityGlob string.')
    return cls(kind, pattern)

  def match(self, identity):
    """Return True if |identity| matches this pattern."""
    if identity.kind != self.kind:
      return False
    # TODO(vadimsh): fnmatchcase has some odd cache inside, better to replace it
    # with more explicit one.
    return fnmatch.fnmatchcase(identity.name, self.pattern)


class IdentityProperty(utils.StringSerializableProperty):
  """NDB model property for Identity values.

  Identities are stored as strings internally.
  """
  _value_type = Identity


class IdentityGlobProperty(utils.StringSerializableProperty):
  """NDB model property for IdentityGlob values.

  IdentityGlobs are stored as string internally.
  """
  _value_type = IdentityGlob


class AuthRules(ndb.Model):
  """Singleton entity that holds all ACL rules.

  Acts as entity root for AuthGroup model.
  """
  # All ACL rules stored in NDB agnostic format.
  rules = ndb.JsonProperty()


class AuthGroup(utils.SerializableModel):
  """A user group.

  Id matches group name. Parent entity is AuthRules.
  """

  @classmethod
  def get_serializable_fields(cls):
    return {
      'members': utils.WRITABLE,
      'globs': utils.WRITABLE,
      'nested': utils.WRITABLE,
      'description': utils.WRITABLE,
      'created_ts': utils.READ_ONLY,
      'created_by': utils.READ_ONLY,
      'modified_ts': utils.READ_ONLY,
      'modified_by': utils.READ_ONLY,
    }

  # List of members that are explicitly in this group. Indexed.
  members = IdentityProperty(repeated=True)
  # List of identity-glob expressions (like 'user:*@example.com'). Indexed.
  globs = IdentityGlobProperty(repeated=True)
  # List of nested group names. Indexed.
  nested = ndb.StringProperty(repeated=True)

  # Human readable description.
  description = ndb.StringProperty()

  # When the group was created.
  created_ts = ndb.DateTimeProperty(auto_now_add=True)
  # How created the group.
  created_by = IdentityProperty()

  # When group was modified last time, used in conditional requests.
  modified_ts = ndb.DateTimeProperty(auto_now=True)
  # Who modified the group last time.
  modified_by = IdentityProperty()


################################################################################


_AccessRule = collections.namedtuple(
    'AccessRule', ['kind', 'actions', 'group', 'resource'])

class AccessRule(_AccessRule):
  """Single access rule definition."""

  def __init__(self, kind, actions, group, resource):
    if kind not in (ALLOW_RULE, DENY_RULE):
      raise ValueError('Invalid access rule kind: %s' % kind)
    actions = tuple(actions)
    for action in actions:
      if action not in ALLOWED_ACTIONS:
        raise ValueError('Invalid action: %s' % action)
    if not GROUP_NAME_RE.match(group):
      raise ValueError('Invalid group name: %s' % group)
    if not resource.endswith('$'):
      raise ValueError('Resource pattern should end with $: %s' % resource)
    try:
      resource = re.compile(resource)
    except re.error:
      raise ValueError('Invalid resource regexp pattern: %s' % resource)
    super(AccessRule, self).__init__(kind, actions, group, resource)

  def to_dict(self):
    return {
      'actions': self.actions,
      'group': self.group,
      'kind': self.kind,
      'resource': self.resource.pattern,
    }

  @staticmethod
  def from_dict(dct):
    try:
      return AccessRule(
          dct['kind'], dct['actions'], dct['group'], dct['resource'])
    except KeyError, TypeError:
      raise ValueError('Invalid format of rule dict: %s' % dct)


def decode_rules(dct):
  # TODO(vadimsh): Check format version?
  return [AccessRule.from_dict(rule) for rule in dct.get('rules', [])]


def encode_rules(rules):
  return {'rules': [rule.to_dict() for rule in rules]}


################################################################################


class AuthDB(object):
  """Represents an entire read-only database of ACL Rules and User Groups."""

  def __init__(self, rules=None, groups=None, entity_group_version=None):
    self.rules = rules or []
    self.groups = dict((g.name, g) for g in groups) if groups else {}
    self.entity_group_version = entity_group_version

  def is_group_member(self, identity, group):
    """Return True if |identity| belongs to group |group| (given as str)."""
    group_obj = self.groups.get(group)
    if not group_obj:
      return False
    for glob in group.globs:
      if glob.match(identity):
        return True
    for member in group.members:
      if identity == member:
        return True
    # TODO(vadimsh): If group nesting graph has cycles, this can stuck.
    for nested in group.nested:
      if self.is_group_member(identity, nested):
        return True
    return False

  def check_identity_has_permission(self, identity, action, resource):
    """True if |identity| can execute |action| against |resource|."""
    if action not in ALLOWED_ACTIONS:
      return False
    for rule in self.rules:
      if (action in rule.actions and
          rule.resource.match(resource) and
          self.is_group_member(identity, rule.group)):
        return rule.kind == ALLOW_RULE
    return False


def fetch_auth_db(root_key=ROOT_KEY, known_version=None):
  """Return new instance of AuthDB fetching it from Datastore.

  If |known_version| is None, this function always returns a new instance.

  If |known_version| is not None, this function will first call
  get_entity_group_version() to get up-to-date version of ACL DB entity group
  and compare it to |known_version|. It they match, function will return None,
  otherwise it will fetch a fresh copy of AuthDB and return it.
  """
  # Don't fetch anything if |known_version| is up to date.
  current_version = metadata.get_entity_group_version(root_key)
  if known_version is not None and current_version == known_version:
    return None

  # Start fetching root ACL object.
  rules_future = root_key.get_async(use_cache=False)
  # Meanwhile fetch all groups groups.
  groups = AuthGroup.query(ancestor=root_key).fetch()
  # Wait for root ACL object to finish fetching.
  rules_entity = rules_future.wait()

  # Note that by that moment |current_version| might not be current anymore.
  # But that's fine, in the worst case next comparison with
  # |known_version| will return False and DB will be refetched.
  if rules_entity is None:
    return AuthDB()
  else:
    return AuthDB(decode_rules(rules_entity.rules), groups, current_version)
