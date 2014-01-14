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
  'Anonymous',
  'CREATE',
  'DELETE',
  'Identity',
  'IdentityGlob',
  'IdentityGlobProperty',
  'IdentityProperty',
  'READ',
  'UPDATE',
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
    IDENTITY_SERVICE: re.compile(r'[0-9a-zA-Z_\-]+$'),
    IDENTITY_USER: re.compile(r'[0-9a-zA-Z_\-\.@]+$'),
}

# Regular expression that matches group names. No trailing spaces allowed.
GROUP_NAME_RE = re.compile(
    r'[0-9a-zA-Z_][0-9a-zA-Z_\-\.\ ]{1,40}[0-9a-zA-Z_\-\.]$')
# Special group name that means 'All possible users' (including anonymous).
GROUP_ALL = '*'

# Global root key of auth models entity group.
ROOT_KEY = ndb.Key('AuthGlobalConfig', 'root')


################################################################################
## Identity & IdentityGlob.


class Identity(
    utils.BytesSerializable,
    collections.namedtuple('Identity', 'kind, name')):
  """Represents a caller that can make requests. Immutable.

  A tuple of (kind, name) where 'kind' is one of IDENTITY_* constants and
  meaning of 'name' depends on a kind. It generalizes real people accounts,
  bot accounts and service-to-service accounts.

  It's a pure identity information. Any additional information that may be
  related to an identity (like registration date, etc.) should be stored
  elsewhere using Identity.to_bytes() as a primary key.
  """

  # Empty slots prohibit adding attributes to |self| on the fly.
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
  def is_bot(self):
    """True if this object represents bot account."""
    return self.kind == IDENTITY_BOT

  @property
  def is_service(self):
    """True if this object represents service account."""
    return self.kind == IDENTITY_SERVICE

  @property
  def is_user(self):
    """True if this object represents user account."""
    return self.kind == IDENTITY_USER


# Predefined Anonymous identity.
Anonymous = Identity(IDENTITY_ANONYMOUS, 'anonymous')


class IdentityProperty(utils.BytesSerializableProperty):
  """NDB model property for Identity values.

  Identities are stored as indexed short blobs internally.
  """
  _value_type = Identity
  _indexed = True


class IdentityGlob(
    utils.BytesSerializable,
    collections.namedtuple('IdentityGlob', 'kind, pattern')):
  """Glob like pattern that matches subset of identities. Immutable."""

  # Empty slots prohibit adding attributes to |self| on the fly.
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

  IdentityGlobs are stored as short indexed blobs internally.
  """
  _value_type = IdentityGlob
  _indexed = True


################################################################################
## AccessRule.


class AccessRule(
    utils.JsonSerializable,
    collections.namedtuple('AccessRule', 'kind, group, actions, resource')):
  """Single access rule definition. Immutable."""

  # Empty slots prohibit adding attributes to |self| on the fly.
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

    # Validate resource regular expression, prohibit open-ended patterns.
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
## Root models: AuthGlobalConfig and AuthServiceConfig.


class AuthGlobalConfig(ndb.Model):
  """Acts as a root entity for all other auth models.

  There should be only one instance of this model, with key ROOT_KEY.

  Replicated from master auth services to slave services.
  """
  # OAuth2 client_ids allowed to access the services.
  oauth_client_ids = ndb.StringProperty(repeated=True, indexed=False)


class AuthServiceConfig(utils.SerializableModel):
  """Holds ACL rules and other configuration for a single service.

  Master auth service have multiple entities of this kind for each slave service
  (with entity id set to service name), while each slave service has only one
  (with id 'default'), that gets replicated from corresponding master entity.
  """

  @classmethod
  def get_serializable_fields(cls):
    return {
      'rules': utils.WRITABLE,
      'modified_ts': utils.READ_ONLY,
      'modified_by': utils.READ_ONLY,
    }

  # All ACL rules. Order is important.
  rules = AccessRuleProperty(repeated=True)

  # OAuth2 client_id of the service, can be used to mint new OAuth2 tokens.
  oauth_client_id = ndb.StringProperty(indexed=False)
  # OAuth2 client secret, required to mint new OAuth2 tokens.
  oauth_client_secret = ndb.StringProperty(indexed=False)

  # When entity were modified last time, used in conditional requests.
  modified_ts = ndb.DateTimeProperty(auto_now=True, indexed=False)
  # Who modified the entity last time.
  modified_by = IdentityProperty(indexed=False)


class AuthGroup(utils.SerializableModel):
  """A group of identities.

  Replicated between services, with source of truth in master auth service.
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
  description = ndb.StringProperty(indexed=False)

  # When the group was created.
  created_ts = ndb.DateTimeProperty(auto_now_add=True)
  # How created the group.
  created_by = IdentityProperty()

  # When group was modified last time, used in conditional requests.
  modified_ts = ndb.DateTimeProperty(auto_now=True)
  # Who modified the group last time.
  modified_by = IdentityProperty()


################################################################################
## Secrets store.


class AuthSecretStore(ndb.Model):
  """Entity kind to act as parent entity for AuthSecret.

  AuthSecretStore have root AuthGlobalConfig (key is ROOT_KEY) as a parent.

  Id of this entity defines scope of secret keys ('local' or 'global') that have
  this entity as a parent.

  Secrets in 'local' scope never leave Datastore they are stored in and they
  are different for each slave service.

  Secrets in 'global' scope are defined in master auth service's Datastore and
  are replicated to all slave services.
  """


class AuthSecret(utils.SerializableModel):
  """Some service-wide secret string.

  Entity can be a child of:
    * Key(AuthSecretStore, 'global', parent=ROOT_KEY):
        Global secrets replicated across all services.
    * Key(AuthSecretStore, 'local', parent=ROOT_KEY):
        Secrets local to the current service.

  There should be only very limited number of AuthSecret entities around. AuthDB
  fetches them all at once. Do not use this entity for per-user secrets.
  """
  # How many historical values to hold.
  retention = ndb.IntegerProperty(default=2, indexed=False)
  # Last |retention| values, most recent first.
  values = ndb.BlobProperty(repeated=True, indexed=False)

  # When secret was modified last time.
  modified_ts = ndb.DateTimeProperty(auto_now=True)
  # Who modified the secret last time.
  modified_by = IdentityProperty()

  def update(self, secret, author=None, keep_previous=True):
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

  @classmethod
  def bootstrap(cls, name, scope, retention=2):
    """Creates a secret key if it doesn't exist yet."""
    # Note that 'get_or_insert' is a bad fit here. With 'get_or_insert' we'd
    # have to call os.urandom every time we want to get a key. It's a waste of
    # time and entropy.
    assert scope in ('local', 'global')
    key = ndb.Key(AuthSecretStore, scope, cls, name, parent=ROOT_KEY)
    entity = key.get()
    if entity is not None:
      return entity
    @ndb.transactional
    def create():
      entity = key.get()
      if entity is not None:
        return entity
      entity = cls(key=key, retention=retention)
      entity.update(os.urandom(32))
      entity.put()
      return entity
    return create()


################################################################################
## DB of ACL rules.


class AuthDB(object):
  """A read-only database of ACL Rules and User Groups for a service."""

  def __init__(
      self,
      global_config=None,
      service_config=None,
      groups=None,
      secrets=None,
      entity_group_version=None):
    self.global_config = global_config or AuthGlobalConfig()
    self.service_config = service_config or AuthServiceConfig()
    self.groups = dict((g.key.string_id(), g) for g in (groups or []))
    self.secrets = {'local': {}, 'global': {}}
    self.entity_group_version = entity_group_version
    self.allowed_oauth_client_ids = set()

    # Split |secrets| into local and global ones based on parent key id.
    for secret in (secrets or []):
      scope = secret.key.parent().string_id()
      assert scope in self.secrets, scope
      self.secrets[scope][secret.key.string_id()] = secret

    # Grab the list of allowed OAuth client_ids.
    if self.service_config.oauth_client_id:
      self.allowed_oauth_client_ids.add(self.service_config.oauth_client_id)
    if self.global_config.oauth_client_ids:
      self.allowed_oauth_client_ids.update(self.global_config.oauth_client_ids)

  def get_groups(self, identity=None):
    """Returns a set of group names that contain |identity| as a member."""
    if not identity:
      return set(self.groups)
    return set(g for g in self.groups if self.is_group_member(identity, g))

  def is_group_member(self, identity, group, _seen=None):
    """Returns True if |identity| belongs to group |group|."""
    # Wildcard group that matches all identities (including anonymous!).
    if group == GROUP_ALL:
      return True

    # An unknown group is empty.
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
    return list(self.service_config.rules)

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

  def has_permission(self, identity, action, resource):
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
    # There's a race condition here: multiple requests, that share same AuthDB
    # object, fetch same missing secret key. It's rare (since key bootstrap
    # process is rare) and not harmful (since AuthSecret.bootstrap is
    # implemented with transaction inside). We ignore it.
    if name not in self.secrets[scope]:
      self.secrets[scope][name] = AuthSecret.bootstrap(name, scope)
    entity = self.secrets[scope][name]
    return list(entity.values)

  def is_allowed_oauth_client_id(self, client_id):
    """True if given OAuth client_id can be used to authenticate the user."""
    return client_id and client_id in self.allowed_oauth_client_ids

  def get_oauth_config(self):
    """Returns a tuple with current service's (client_id, client_secret)."""
    if not self.service_config:
      return None, None
    return (
        self.service_config.oauth_client_id,
        self.service_config.oauth_client_secret)


# True if fetch_auth_db was called at least once and created all root entities.
_lazy_bootstrap_ran = False


def fetch_auth_db(known_version=None):
  """Return new instance of AuthDB fetching it from Datastore.

  If |known_version| is None, this function always returns a new instance.

  If |known_version| is not None, this function will first call
  get_entity_group_version() to get up-to-date version of ACL DB entity group
  and compare it to |known_version|. It they match, function will return None,
  otherwise it will fetch a fresh copy of AuthDB and return it.
  """
  global _lazy_bootstrap_ran

  # Don't fetch anything if |known_version| is up to date.
  current_version = metadata.get_entity_group_version(ROOT_KEY)
  if known_version is not None and current_version == known_version:
    return None

  # Run bootstrap code at most once per lifetime of an instance. We do it lazily
  # here (instead of module scope) to ensure NDB calls are happening in
  # a context of HTTP request. Hypothetically it reduces probability of stuck
  # instance launches.
  if not _lazy_bootstrap_ran:
    _lazy_bootstrap_ran = True
    ndb.Future.wait_all([
      AuthGlobalConfig.get_or_insert_async(ROOT_KEY.string_id()),
      AuthServiceConfig.get_or_insert_async('default', parent=ROOT_KEY),
    ])

  # Fetching all stuff in parallel.
  global_config = ROOT_KEY.get_async()
  service_config = AuthServiceConfig.get_by_id_async('default', parent=ROOT_KEY)
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
