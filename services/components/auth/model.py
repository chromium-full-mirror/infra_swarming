# Copyright 2013 The Swarming Authors. All rights reserved.
# Use of this source code is governed by the Apache v2.0 license that can be
# found in the LICENSE file.

"""NDB model classes used to model AuthDB relations."""

import collections
import datetime
import fnmatch
import os
import re

from google.appengine.ext import ndb
from google.appengine.ext.ndb import metadata

from . import utils

__all__ = [
  'CREATE', 'DELETE', 'READ', 'UPDATE', 'Identity', 'Anonymous',
  'IdentityProperty', 'IdentityGlob', 'IdentityGlobProperty',
]


# Rule types.
ALLOW_RULE = 'ALLOW'
DENY_RULE = 'DENY'

# Possible actions that can be applied to a resource.
CREATE = 'CREATE'
DELETE = 'DELETE'
READ = 'READ'
UPDATE = 'UPDATE'

# Set of all allowed actions.
ALLOWED_ACTIONS = frozenset([CREATE, DELETE, READ, UPDATE])

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

# Regular expression that matches group names. No trailing spaces allowed.
GROUP_NAME_RE = re.compile(
    r'[0-9a-zA-Z_][0-9a-zA-Z_\-\.\ ]{1,40}[0-9a-zA-Z_\-\.]$')
# Special group name that means 'All possible users' (including anonymous).
GROUP_ALL = '*'

# Global root key of auth models entity group.
ROOT_KEY = ndb.Key('AuthGlobalConfig', 'root')


class Identity(
    utils.BytesSerializable,
    collections.namedtuple('Identity', 'kind, name')):
  """Represents a caller that can make requests. Immutable.

  A tuple of (kind, name) where 'kind' is one of IDENTITY_* constants and
  meaning of 'name' depends on kind. It generalizes real people accounts and bot
  accounts.

  It's a pure identity information. Any additional information that may be
  related to an identity (like maybe registration date, etc.) should be stored
  elsewhere using Identity.to_bytes() as a primary key.
  """

  __slots__ = ()

  def __new__(cls, kind, name):
    if isinstance(name, unicode):
      try:
        name = name.encode('ascii')
      except UnicodeEncodeError:
        raise TypeError('Identity has invalid format: only ASCII is allowed')
    if (kind not in ALLOWED_IDENTITY_KINDS or
        not ALLOWED_IDENTITY_KINDS[kind].match(name)):
      raise TypeError('Identity has invalid format')
    return super(cls, Identity).__new__(cls, str(kind), name)

  def to_bytes(self):
    """Serializes this identity to byte buffer."""
    return '%s:%s' % (self.kind, self.name)

  @classmethod
  def from_bytes(cls, bytes):
    """Given a byte buffer returns corresponding Identity object."""
    kind, sep, name = bytes.partition(':')
    if not sep:
      raise TypeError('Missing \':\' separator in Identity string')
    return cls(kind, name)

  @property
  def is_anonymous(self):
    """True if this object represents anonymous identity."""
    return self.kind == IDENTITY_ANONYMOUS

  @property
  def is_user(self):
    """True if this object represents user account."""
    return self.kind == IDENTITY_USER


# Predefined Anonymous identity. While not strictly a singleton, it's still can
# be used in comparisons like identity_obj == Anonymous.
Anonymous = Identity(IDENTITY_ANONYMOUS, 'anonymous')


class IdentityProperty(utils.BytesSerializableProperty):
  """NDB model property for Identity values.

  Identities are stored as short blobs internally.
  """
  _value_type = Identity
  _indexed = True


class IdentityGlob(
    utils.BytesSerializable,
    collections.namedtuple('IdentityGlob', 'kind, pattern')):
  """Glob like pattern that matches subset of identities. Immutable."""

  __slots__ = ()

  def __new__(cls, kind, pattern):
    if isinstance(pattern, unicode):
      try:
        pattern = pattern.encode('ascii')
      except UnicodeEncodeError:
        raise TypeError('Invalid IdentityGlob pattern: only ASCII is allowed')
    if kind not in ALLOWED_IDENTITY_KINDS:
      raise TypeError('Invalid Identity kind: %s' % kind)
    if ':' in pattern:
      raise TypeError('Invalid IdentityGlob pattern: %s' % pattern)
    return super(cls, IdentityGlob).__new__(cls, str(kind), pattern)

  def to_bytes(self):
    """Serializes this identity glob to byte buffer."""
    return '%s:%s' % (self.kind, self.pattern)

  @classmethod
  def from_bytes(cls, bytes):
    """Given a byte buffer returns corresponding IdentityGlob object."""
    kind, sep, pattern = bytes.partition(':')
    if not sep:
      raise TypeError('Missing \':\' separator in IdentityGlob string')
    return cls(kind, pattern)

  def match(self, identity):
    """Return True if |identity| matches this pattern."""
    if identity.kind != self.kind:
      return False
    return fnmatch.fnmatchcase(identity.name, self.pattern)


class IdentityGlobProperty(utils.BytesSerializableProperty):
  """NDB model property for IdentityGlob values.

  IdentityGlobs are stored as short blobs internally.
  """
  _value_type = IdentityGlob
  _indexed = True


################################################################################


class AccessRule(
    utils.JsonSerializable,
    collections.namedtuple('AccessRule', 'kind, group, actions, resource')):
  """Single access rule definition. Immutable."""

  __slots__ = ()

  def __new__(cls, kind, group, actions, resource):
    # Validate kind, convert to str.
    if kind not in (ALLOW_RULE, DENY_RULE):
      raise ValueError('Invalid access rule kind: %s' % kind)
    kind = str(kind)

    # Validate group name.
    if not GROUP_NAME_RE.match(group) and group != GROUP_ALL:
      raise ValueError('Invalid group name: %s' % group)

    # Validate action list, convert to str.
    for action in actions:
      if action not in ALLOWED_ACTIONS:
        raise ValueError('Invalid action: %s' % action)
    actions = tuple(sorted(map(str, set(actions))))

    # Validate resource regular expression.
    if not resource.endswith('$'):
      raise ValueError('Resource pattern should end with \'$\': %s' % resource)
    try:
      resource = re.compile(resource)
    except re.error:
      raise ValueError('Invalid resource regexp pattern: %s' % resource)

    return super(cls, AccessRule).__new__(cls, kind, group, actions, resource)

  def to_jsonish(self):
    return {
      'actions': self.actions,
      'group': self.group,
      'kind': self.kind,
      'resource': self.resource.pattern,
    }

  @classmethod
  def from_jsonish(cls, obj):
    try:
      return cls(obj['kind'], obj['group'], obj['actions'], obj['resource'])
    except (KeyError, TypeError):
      raise ValueError('Invalid format of a rule dict: %r' % obj)


class AccessRuleProperty(utils.JsonSerializableProperty):
  """NDB model property for AccessRule values.

  Stored as JSON blob internally.
  """
  _value_type = AccessRule
  _indexed = False


################################################################################


class AuthGlobalConfig(ndb.Model):
  """Acts as a root entity for all other auth models.

  Replicated between services.
  """
  # OAuth2 client_id allowed to access the services.
  oauth_client_ids = ndb.StringProperty(repeated=True, indexed=False)


class AuthServiceConfig(utils.SerializableModel):
  """Holds ACL rules and other configuration for a single service.

  Master auth service have multiple entities of this kind, while each managed
  service has only one (with id 'default'), that gets replicated from
  corresponding master entity.
  """

  @classmethod
  def get_serializable_fields(cls):
    return {
      'rules': utils.WRITABLE,
      'modified_ts': utils.READ_ONLY,
      'modified_by': utils.READ_ONLY,
    }

  # All ACL rules.
  rules = AccessRuleProperty(repeated=True)

  # OAuth2 client_id of the service.
  oauth_client_id = ndb.StringProperty(indexed=False)
  # OAuth2 client secret required to mint access_tokens.
  oauth_client_secret = ndb.StringProperty(indexed=False)

  # When rules were modified last time, used in conditional requests.
  modified_ts = ndb.DateTimeProperty(auto_now=True, indexed=False)
  # Who modified the rules last time.
  modified_by = IdentityProperty(indexed=False)


class AuthGroup(utils.SerializableModel):
  """A user group.

  Replicated between services.
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


class AuthSecretStore(ndb.Model):
  """Entity kind to act as parent entity for AuthSecret."""


class AuthSecret(utils.SerializableModel):
  """Some shared secret with auto-expiration.

  Entity can be a child of:
    * Key(AuthSecretStore, 'global', parent=ROOT_KEY):
        Global secrets replicated across services.
    * Key(AuthSecretStore, 'local', parent=ROOT_KEY):
        Secrets local to the current service.

  Both parent keys (and thus all AuthSecrets) belong to ROOT_KEY entity group.
  """
  # How many historical values to hold.
  retention = ndb.IntegerProperty(default=2, indexed=False)
  # How long a key lives before it needs to be replaced (seconds).
  lifetime_sec = ndb.IntegerProperty(default=0, indexed=False)

  # When this secret expires and should be replaced.
  expiration_ts = ndb.DateTimeProperty(indexed=True)
  # Last |retention| values, most recent first.
  values = ndb.BlobProperty(repeated=True, indexed=False)

  # When secret was modified last time.
  modified_ts = ndb.DateTimeProperty(auto_now=True)
  # Who modified the secret last time.
  modified_by = IdentityProperty()

  def update(self, secret, author, keep_previous=True):
    """Generates new key value, optionally remembering previous one."""
    values = list(self.values or [])
    if keep_previous:
      values = [secret] + values[:self.retention]
    else:
      if values:
        values[0] = secret
      else:
        values = [secret]
    self.values = values
    self.modified_by = author
    if self.lifetime_sec:
      lifetime_td = datetime.timedelta(seconds=self.lifetime_sec)
      self.expiration_ts = datetime.datetime.utcnow() + lifetime_td
    else:
      self.expiration_ts = None

  @classmethod
  def get_entity_key(cls, name, scope):
    """Returns ndb.Key that correspond to a secret key."""
    assert scope in ('local', 'global')
    return ndb.Key(AuthSecretStore, scope, cls, name, parent=ROOT_KEY)

  @classmethod
  def bootstrap(cls, author, name, scope, retention=2, lifetime_sec=0):
    """Creates a secret key if it doesn't exist."""
    key = cls.get_entity_key(name, scope)
    entity = key.get()
    if entity is not None:
      return entity
    @ndb.transactional
    def create():
      entity = key.get()
      if entity is not None:
        return entity
      entity = cls(key=key, retention=retention, lifetime_sec=lifetime_sec)
      entity.update(os.urandom(512), author)
      entity.put()
      return entity
    return create()


################################################################################


class AuthDB(object):
  """Represents an entire read-only database of ACL Rules and User Groups."""

  def __init__(self, global_config=None, service_config=None,
               groups=None, secrets=None, entity_group_version=None):
    self.global_config = global_config or AuthGlobalConfig()
    self.service_config = service_config or AuthServiceConfig()
    self.groups = dict((g.key.string_id(), g) for g in (groups or []))
    self.secrets = {'local': {}, 'global': {}}
    self.entity_group_version = entity_group_version
    self.allowed_oauth_client_ids = set()

    # Split |secrets| into local and global ones based on parent key.
    for secret in (secrets or []):
      scope = secret.key.parent().string_id()
      if scope in self.secrets:
        self.secrets[scope][secret.key.string_id()] = secret

    # Grab the list of allowed OAuth client_ids.
    if self.service_config.oauth_client_id:
      self.allowed_oauth_client_ids.add(self.service_config.oauth_client_id)
    if self.global_config.oauth_client_ids:
      self.allowed_oauth_client_ids.update(self.global_config.oauth_client_ids)

  def get_groups(self, identity=None):
    """Return set of group names that contain |identity| as a member."""
    if not identity:
      return set(self.groups)
    return set(g for g in self.groups if self.is_group_member(identity, g))

  def is_group_member(self, identity, group, _seen=None):
    """Return True if |identity| belongs to group |group|."""
    # Wildcard group that matches all identities (including anonymous).
    if group == GROUP_ALL:
      return True

    # Unknown group is by convention empty.
    group_obj = self.groups.get(group)
    if not group_obj:
      return False

    # Use _seen to avoid infinite recursion if group nesting graph has cycles.
    _seen = _seen or set()
    if group in _seen:
      return False
    _seen.add(group)

    for glob in group_obj.globs:
      if glob.match(identity):
        return True

    for member in group_obj.members:
      if identity == member:
        return True

    for nested in group_obj.nested:
      if self.is_group_member(identity, nested, _seen=_seen):
        return True

    return False

  def get_rules(self):
    """Return all defined AccessRules."""
    return self.service_config.rules or []

  def get_matching_rules(self, identity=None, action=None, resource=None):
    """Return list of AccessRules that match given ACL query."""
    rules = []
    for rule in self.service_config.rules:
      if action and action not in rule.actions:
        continue
      if resource and not rule.resource.match(resource):
        continue
      if identity and not self.is_group_member(identity, rule.group):
        continue
      # First matched rule terminates ACL evaluation, so if complete triple is
      # given do not even show all other rules.
      if identity and action and resource:
        return [rule]
      rules.append(rule)
    # No rules match -> apply default 'deny all' rule.
    return rules or [AccessRule(DENY_RULE, GROUP_ALL, ALLOWED_ACTIONS, '.*$')]

  def check_identity_has_permission(self, identity, action, resource):
    """True if |identity| can execute |action| against |resource|."""
    assert action in ALLOWED_ACTIONS
    for rule in self.service_config.rules:
      if (action in rule.actions and
          rule.resource.match(resource) and
          self.is_group_member(identity, rule.group)):
        return rule.kind == ALLOW_RULE
    return False

  def get_secret(self, name, scope):
    """Returns list of strings with last known values of a secret key."""
    if scope not in self.secrets:
      raise ValueError('Invalid secret key scope')
    entity = self.secrets[scope].get(name)
    return list(entity.values) if entity and entity.values else None

  def is_allowed_oauth_client_id(self, client_id):
    """True if given client_id is known."""
    return client_id and client_id in self.allowed_oauth_client_ids

  def get_oauth_config(self):
    """Returns tuple (client_id, client_secret)."""
    if not self.service_config:
      return None, None
    return (
        self.service_config.oauth_client_id,
        self.service_config.oauth_client_secret)


def fetch_auth_db(service='default', known_version=None):
  """Return new instance of AuthDB fetching it from Datastore.

  If |known_version| is None, this function always returns a new instance.

  If |known_version| is not None, this function will first call
  get_entity_group_version() to get up-to-date version of ACL DB entity group
  and compare it to |known_version|. It they match, function will return None,
  otherwise it will fetch a fresh copy of AuthDB and return it.
  """
  # Don't fetch anything if |known_version| is up to date.
  current_version = metadata.get_entity_group_version(ROOT_KEY)
  if known_version is not None and current_version == known_version:
    return None

  # Fetching all stuff in parallel.
  global_config = ROOT_KEY.get_async()
  service_config = AuthServiceConfig.get_by_id_async(service, parent=ROOT_KEY)
  groups = AuthGroup.query(ancestor=ROOT_KEY).fetch_async()
  secrets = AuthSecret.query(ancestor=ROOT_KEY).fetch_async()

  # Note that by that moment |current_version| might not be current anymore.
  # But that's fine, in the worst case next comparison with
  # |known_version| will return False and DB will be refetched.
  return AuthDB(
      global_config=global_config.get_result(),
      service_config=service_config.get_result(),
      groups=groups.get_result(),
      secrets=secrets.get_result(),
      entity_group_version=current_version)


def bootstrap():
  """Creates root entities if they don't exist yet."""
  futures = [
    AuthGlobalConfig.get_or_insert_async(ROOT_KEY.string_id()),
    AuthServiceConfig.get_or_insert_async('default', parent=ROOT_KEY)
  ]
  ndb.Future.wait_all(futures)
