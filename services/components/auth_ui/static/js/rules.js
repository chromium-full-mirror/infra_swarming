var rules = (function() {
var exports = {};


////////////////////////////////////////////////////////////////////////////////
// Utilities.


// Kinds of ACL rules allowed.
var allowedRuleKinds = {
  ALLOW: true,
  DENY: true
};


// Actions allowed in ACL rules.
var allowedRuleActions = {
  CREATE: true,
  DELETE: true,
  READ: true,
  UPDATE: true
};


// Regular expression that matches valid group names.
var allowedGroupRe = /([0-9a-zA-Z_\-\. ]{3,40})|\*$/;


// Ensure |str| is at least |len| chars long.
var padWithSpaces = function(str, len) {
  var result = str;
  for (var i = str.length; i < len; i++)
    result += ' ';
  return result;
}


// Rule object -> string.
var ruleToString = function(rule) {
  var actions = rule.actions.join(' ');
  return String.format(
      '{0} | {1} | {2} | {3}',
      padWithSpaces(rule.kind, 6),
      padWithSpaces(rule.group, 24),
      padWithSpaces(actions, 28),
      rule.resource);
}


// String -> {rule: <Rule object>, error: <Error string>}.
var stringToRule = function(str) {
  // Skip empty lines.
  if (str.trim() == '')
    return null;

  // Split by '|' char, strip whitespace.
  var terms = _.map(str.split('|'), function(term) {
    return term.trim();
  });

  // Expecting 4 terms.
  if (terms.length != 4) {
    return {
      error: ('Expected format: (ALLOW|DENY) | <Group> |' +
              '<Action> <Action> ... | <Resource Regex>.')
    };
  }

  // Check rule kind.
  var kind = terms[0].toUpperCase();
  if (!allowedRuleKinds[kind])
    return {error: String.format('Invalid rule kind: {0}.', kind)};

  // Check group name.
  var group = terms[1];
  if (!allowedGroupRe.test(group))
    return {error: String.format('Invalid group name: {0}.', group)};

  // Parse and check actions: <Action> <Action>... -> list of upper actions.
  var actions = terms[2];
  actions = _.map(actions.split(/[ \t]+/), function(action) {
    return action.toUpperCase();
  });
  for (var i = 0; i < actions.length; i++) {
    if (!allowedRuleActions[actions[i]])
      return {error: String.format('Invalid rule action: {0}.', actions[i])};
  }

  // Resource regexp will be validated by the server.
  var resource = terms[3];

  return {
    rule: {
      kind: kind,
      group: group,
      actions: actions,
      resource: resource
    }
  };
}


////////////////////////////////////////////////////////////////////////////////
// List of rules.


var RuleList = function($element) {
  this.$element = $element;
  this.lastModified = null;

  var self = this;
  $('#rules-form', $element).submit(function(e) {
    e.preventDefault();
    self.onSubmit();
  });
}


// Reload rules from the server.
RuleList.prototype.refetch = function() {
  var defer = api.rulesRead();
  var self = this;
  defer.then(function(response) {
    self.setRules(response.data.rules, response.headers['Last-Modified']);
  });
  return defer;
}


// Update UI based on rules passed from server.
RuleList.prototype.setRules = function(rules, lastModified) {
  var asStrings = [];
  _.each(rules, function(rule) {
    asStrings.push(ruleToString(rule));
  });
  asStrings.push('');
  $('textarea[name=rules]', this.$element).val(asStrings.join('\n'));
  this.lastModified = lastModified;
}


// Validate and parse currently set rules.
// Returns object {rules: <array of rules>, error: {title: ..., message: ...}}.
RuleList.prototype.getRules = function() {
  var rules = [];
  var error = null;
  var lineNum = 0;
  var asStrings = $('textarea[name=rules]', this.$element).val().split('\n');
  _.every(asStrings, function(ruleStr) {
    var result = stringToRule(ruleStr);
    lineNum += 1;
    // Skip empty lines.
    if (!result)
      return true;
    // Error? Stop iteration.
    if (!result.rule) {
      rules = null;
      error = {
        title: String.format('Error on line {0}:', lineNum),
        message: result.error
      };
      return false;
    }
    rules.push(result.rule);
    return true;
  });
  return {rules: rules, error: error};
}


// Send rules to server.
RuleList.prototype.onSubmit = function() {
  var parsed = this.getRules();
  if (parsed.error) {
    this.showMessage('error', parsed.error.title, parsed.error.message);
    return;
  }

  // Local validation passed, try to submit.
  var request = api.rulesUpdate({rules: parsed.rules}, this.lastModified);
  var self = this;
  request.then(function() {
    self.refetch().done(function() {
      self.showMessage('success', 'Done!', 'ACL rules updated.');
    });
  }, function(error) {
    self.showMessage('error', 'Error:', error.error.text || error.text);
  });
}


// Shows error or success message.
RuleList.prototype.showMessage = function(type, title, message) {
  $('#alerts', this.$element).html(
      common.getAlertBoxHtml(type, title, message));
}


// Hides error or success message.
RuleList.prototype.hideMessage = function() {
  $('#alerts', this.$element).empty();
}


////////////////////////////////////////////////////////////////////////////////
// ACL query sandbox.


SandboxModal = function($element) {
  this.$element = $element;
  this.rules = null;

  var self = this;

  // Run query on form submit.
  $('form', this.$element).submit(function(e) {
    e.preventDefault();
    self.onRunQuery();
  });

  // Focus first field when form is shown.
  this.$element.on('shown.bs.modal', function(e) {
    $('input[name=identity]', self.$element).focus();
  });
}


// Shows sandbox modal dialog.
SandboxModal.prototype.show = function(rules) {
  this.rules = rules;
  this.setQueryResult('');
  this.setErrorMessage('');
  this.$element.modal('show');
}


// 'Query' button clicked.
SandboxModal.prototype.onRunQuery = function() {
  // Grab query parameters.
  var identity = $('input[name=identity]', this.$element).val();
  var action = $('input[name=action]', this.$element).val();
  var resource = $('input[name=resource]', this.$element).val();

  // Local validation passed, send to server.
  var request = api.rulesCheck({
    rules: this.rules,
    identity: identity,
    action: action.length ? action.toUpperCase() : null,
    resource: resource
  });

  var self = this;
  request.then(function(response) {
    self.setErrorMessage('');
    self.setQueryResult(self.reportToText(response.data));
  }, function(error) {
    self.setErrorMessage(error.error.text || error.text);
    self.setQueryResult('');
  });
}


SandboxModal.prototype.reportToText = function(report) {
  var text = [];
  text.push('Unrecognized groups:');
  if (report.unrecognizedGroups && report.unrecognizedGroups.length) {
    _.each(report.unrecognizedGroups, function(name) {
      text.push(String.format('  "{0}"', name));
    });
  } else {
    text.push('  None');
  }
  text.push('');
  if (report.identityGroups) {
    text.push(
        String.format('Identity "{0}" belongs to groups:', report.identity));
    if (report.identityGroups.length) {
      _.each(report.identityGroups, function(name) {
        text.push(String.format('  "{0}"', name));
      });
    }  else {
      text.push('  None');
    }
    text.push('');
  }
  if (report.matchingRules) {
    text.push('Matching rules:');
    _.each(report.matchingRules, function(rule) {
      text.push('  ' + ruleToString(rule));
    });
    text.push('');
  }
  return text.join('\n');
}


// Shows or hides result of a query execution.
SandboxModal.prototype.setQueryResult = function(text) {
  if (text && text.length) {
    $('#results-box', this.$element).text(text);
    $('#results-panel', this.$element).removeClass('hidden');
  } else {
    $('#results-box', this.$element).empty();
    $('#results-panel', this.$element).addClass('hidden');
  }
}


// Shows or hides error alert.
SandboxModal.prototype.setErrorMessage = function(text) {
  if (text)
    $('#alerts', this.$element).html(common.getAlertBoxHtml('error', '', text));
  else
    $('#alerts', this.$element).empty();
}


////////////////////////////////////////////////////////////////////////////////
// Main entry point, sets up all high-level UI logic.


exports.onContentLoaded = function() {
  var ruleList = new RuleList($('#rule-list'));
  var sandboxModal = new SandboxModal($('#sandbox-modal'));

  // Open sandbox dialog on button click.
  $('#rule-list #sandbox-btn').click(function() {
    var parsed = ruleList.getRules();
    if (parsed.error) {
      ruleList.showMessage('error', parsed.error.title, parsed.error.message);
    } else {
      ruleList.hideMessage();
      sandboxModal.show(parsed.rules);
    }
  });

  // Load and show data.
  var defer = ruleList.refetch();
  defer.then(function() {
    common.presentContent();
  }, function(error) {
    common.presentError(error.text);
  });

  // Enable XSRF token auto-updater.
  api.setXSRFTokenAutoupdate(true);
}

return exports;

}());
