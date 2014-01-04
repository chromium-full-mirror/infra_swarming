var rules = (function() {
var exports = {};


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
var allowedGroupRe = /^[0-9a-zA-Z_\-\. ]{3,40}$/;


var padWithSpaces = function(str, len) {
  var result = str;
  for (var i = str.length; i < len; i++)
    result += ' ';
  return result;
}


// Rule object -> string.
var ruleToString = function(rule) {
  var actions = rule.actions.join('-');
  return String.format('{0} {1} {2} {3}',
      padWithSpaces(rule.kind, 10),
      padWithSpaces(rule.group, 20),
      padWithSpaces(actions, 26),
      rule.resource);
}


// String -> {rule: <Rule object>, error: <Error string>}.
var stringToRule = function(str) {
  // Split by whitespace.
  var terms = _.filter(str.split(/[ \t]+/), function(term) {
    return !!term;
  });

  // Ignore empty lines.
  if (terms.length == 0)
    return null;

  // Expecting 4 terms.
  if (terms.length != 4) {
    return {
      error: ('Expected format: (ALLOW|DENY) <Group> ' +
              '<Action>-<Action>-... <Resource Regex>.')
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

  // Parse and check actions: <Action>-<Action>... -> list of upper actions.
  var actions = terms[2];
  actions = _.map(actions.split('-'), function(action) {
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


var RuleList = function($element, progressSpinner) {
  this.$element = $element;
  this.progressSpinner = progressSpinner;
  this.lastModified = null;

  var self = this;
  $('#rules-form', $element).submit(function() {
    return self.onSubmit();
  });
}


RuleList.prototype.refetch = function() {
  var self = this;
  var defer = $.Deferred();
  var request = api.rulesRead();
  self.progressSpinner.wrapDeferred(request);
  api.rulesRead().then(function(response) {
    self.setRules(response.data.rules, response.headers['Last-Modified']);
    defer.resolve();
  }, function(error) {
    defer.reject(error);
  });
  return defer.promise();
}


RuleList.prototype.setRules = function(rules, lastModified) {
  var asStrings = [];
  _.each(rules, function(rule) {
    asStrings.push(ruleToString(rule));
  });
  asStrings.push('');
  $('textarea[name=rules]', this.$element).val(asStrings.join('\n'));
  this.lastModified = lastModified;
}


RuleList.prototype.getRules = function() {
  var asStrings = $('textarea[name=rules]', this.$element).val().split('\n');
  var rules = [];
  for (var i = 0; i < asStrings.length; i++) {
    var result = stringToRule(asStrings[i]);
    if (!result)
      continue;
    if (result.rule) {
      rules.push(result.rule);
    } else {
      return {
        error: {
          title: String.format('Error on line {0}:', i + 1),
          message: result.error
        }
      };
    }
  }
  return {rules: rules};
}


RuleList.prototype.onSubmit = function() {
  var self = this;
  var result = this.getRules();
  if (result.error) {
    // Local validation error.
    this.showError(result.error.title, result.error.message);
  } else {
    // Local validation passed, try to submit.
    var request = api.rulesUpdate({rules: result.rules}, self.lastModified);
    this.hideError();
    this.hideSuccess();
    this.progressSpinner.wrapDeferred(request);
    request.then(function() {
      self.refetch().done(function() {
        self.showSuccess('ACL rules updated.');
      });
    }, function(error) {
      self.showError('Error:', error.error.text || error.text);
    });
  }
  return false;
}


RuleList.prototype.showError = function(titleText, errorText) {
  this.hideSuccess();
  $('#error-alert-box #error-title', this.$element).text(titleText);
  $('#error-alert-box #error-msg', this.$element).text(errorText);
  $('#error-alert-box', this.$element).removeClass('hidden');
}


RuleList.prototype.hideError = function() {
  $('#error-alert-box', this.$element).addClass('hidden');
}


RuleList.prototype.showSuccess = function(text) {
  this.hideError();
  $('#success-alert-box #success-msg', this.$element).text(text);
  $('#success-alert-box', this.$element).removeClass('hidden');
}


RuleList.prototype.hideSuccess = function() {
  $('#success-alert-box', this.$element).addClass('hidden');
}


////////////////////////////////////////////////////////////////////////////////
// Main entry point, sets up all high-level UI logic.


var ruleList;
var progressSpinner;


exports.onContentLoaded = function() {
  progressSpinner = new common.ProgressSpinner();
  ruleList = new RuleList($('#rule-list'), progressSpinner);

  // Load and show data.
  var defer = ruleList.refetch();
  progressSpinner.wrapDeferred(defer);
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
