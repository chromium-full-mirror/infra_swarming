var groups = (function() {
var exports = {};


////////////////////////////////////////////////////////////////////////////////
// Utilities.


// Splits 'value' on lines boundaries and returns lines as array.
var splitItemList = function(value) {
  var trimmed = _.map(value.split('\n'), function(item) {
    return item.trim();
  });
  return _.filter(trimmed, function(item) {
    return !!item;
  });
}


// Splits 'value' on lines boundary and checks that each line matches 're'.
var validateItemList = function(re, value) {
  return _.reduce(value.split('\n'), function(acc, item) {
    return acc && (!item || re.test(item));
  }, true);
}


////////////////////////////////////////////////////////////////////////////////
// Group chooser UI element: list of groups + 'Create new group' button.


// UI element to choose groups.
var GroupChooser = function($element) {
  // Root jquery DOM element.
  this.$element = $element;
  // Currently known list of groups as shown in UI.
  this.groupList = [];
  // Same list, but as a dict: group name -> group object.
  this.groupMap = {};
  // If true, selection won't change on clicks in UI.
  this.interactionDisabled = false;
}


// Loads list of groups from a server. Updates group chooser UI.
// Returns deferred.
GroupChooser.prototype.refetchGroups = function() {
  var defer = api.groups();
  var self = this;
  defer.then(function(response) {
    self.setGroupList(response.data.groups);
  });
  return defer;
}


// Updates group chooser UI.
GroupChooser.prototype.setGroupList = function(groups) {
  var self = this;

  // Remember new list (sorted by created_ts).
  self.groupList = _.sortBy(groups, 'created_ts');
  self.groupMap = {};
  _.each(groups, function(group) {
    self.groupMap[group.name] = group;
  });

  // Helper function to add children to DOM.
  var addElement = function(markup, groupName) {
    var item = $(markup);
    item.addClass('chooser-element');
    item.data('group-name', groupName);
    item.appendTo(self.$element);
  }

  // Rebuild UI state.
  self.$element.addClass('list-group');
  self.$element.empty();
  _.each(groups, function(group) {
    addElement(common.render('group-chooser-item-template', group), group.name);
  });
  addElement(common.render('group-chooser-button-template'), null);

  // Wire click handlers.
  $('.chooser-element', self.$element).click(function() {
    if (!self.interactionDisabled)
      self.setSelection($(this).data('group-name'));
    return false;
  });
}


// Return name of the selected group or null if 'Create new group' is selected.
GroupChooser.prototype.getSelection = function() {
  var active = $('.chooser-element.active', self.$element);
  return active.length ? active.data('group-name') : undefined;
}


// Highlights group as chosen in group UI list.
// If |name| is null, then highlights 'Create new group' button.
// Triggers 'onSelectionChanged' event.
GroupChooser.prototype.setSelection = function(name) {
  // Nothing to do?
  if (this.getSelection() === name)
    return;
  var selectionMade = false;
  $('.chooser-element', self.$element).each(function() {
    if ($(this).data('group-name') === name) {
      $(this).addClass('active');
      selectionMade = true;
    } else {
      $(this).removeClass('active');
    }
  });
  if (selectionMade)
    this.$element.triggerHandler('selectionChanged', {group: name});
}


// Selects top element.
GroupChooser.prototype.selectDefault = function() {
  var elements = $('.chooser-element', self.$element);
  if (elements.length)
    this.setSelection(elements.first().data('group-name'));
}


// Registers new event listener.
GroupChooser.prototype.onSelectionChanged = function(listener) {
  this.$element.on('selectionChanged', function(event, selection) {
    listener(selection.group);
  });
}


// Disables an ability to change selection.
GroupChooser.prototype.setInteractionDisabled = function(disabled) {
  this.interactionDisabled = disabled;
}


////////////////////////////////////////////////////////////////////////////////
// Main content frame (with loading indicator).


var ContentFrame = function($element) {
  this.$element = $element;
  this.content = null;
  this.loading = null;
}


// Unconditionally replaces frame's content.
ContentFrame.prototype.setContent = function(content) {
  if (this.content) {
    this.content.hide();
    this.content = null;
  }
  this.$element.empty();
  this.content = content;
  if (this.content)
    this.content.show(this.$element);
  this.loading = null;
}


// Loads new content asynchronously.
ContentFrame.prototype.loadContent = function(content) {
  var self = this;
  if (self.content)
    self.content.setInteractionDisabled(true);
  self.loading = content;
  content.load().then(function() {
    // Still loading same content?
    if (self.loading == content)
      self.setContent(content);
  }, function(error) {
    // Still loading same content?
    if (self.loading == content) {
      self.setContent(null);
      self.$element.append($(common.render('frame-error-pane', error)));
    }
  });
}


////////////////////////////////////////////////////////////////////////////////
// Common code for 'New group' and 'Edit group' forms.


var GroupForm = function($element) {
  this.$element = $element;
  this.visible = false;
}


// Present this form in $parent.
GroupForm.prototype.show = function($parent) {
  this.visible = true;
  this.$element.appendTo($parent);
}


// Hide this form.
GroupForm.prototype.hide = function() {
  this.visible = false;
  this.$element.detach();
}


// Disables\enables controls on the form.
GroupForm.prototype.setInteractionDisabled = function(disabled) {
  $('button', this.$element).attr('disabled', disabled);
}


// Shows error or success message.
GroupForm.prototype.showMessage = function(type, title, message) {
  $('#alerts', this.$element).html(
      common.getAlertBoxHtml(type, title, message));
}


// Hides error or success message.
GroupForm.prototype.hideMessage = function() {
  $('#alerts', this.$element).empty();
}


// Adds validators and submit handlers to <form>.
GroupForm.prototype.hookUpHandlers = function($form, submitHandler) {
  $form.validate({
    submitHandler: function() {
      // Extract data from the form.
      var name = $('form input[name=name]', self.$element).val();
      var description = $('form input[name=description]', self.$element).val();
      var members = $('form textarea[name=members]', self.$element).val();
      var globs = $('form textarea[name=globs]', self.$element).val();
      var nested = $('form textarea[name=nested]', self.$element).val();
      // And call callback.
      try {
        submitHandler({
            name: name.trim(),
            description: description.trim(),
            members: splitItemList(members),
            globs: splitItemList(globs),
            nested: splitItemList(nested)
        });
      } finally {
        return false;
      }
    },
    rules: {
      'name': {
        required: true,
        groupName: true
      },
      'description': {
        required: true
      },
      'members': {
        memberList: true,
      },
      'globs': {
        globList: true,
      },
      'nested': {
        groupList: true,
      }
    }
  });
}


////////////////////////////////////////////////////////////////////////////////
// 'Create new group' form.


var NewGroupForm = function() {
  GroupForm.call(this, $(common.render('new-group-form-template')));

  // Will be called with Object {name: ..., description: ...}.
  this.onSubmitGroup = null;

  // Add validation and submit handler.
  var self = this;
  this.hookUpHandlers($('form', this.$element), function(group) {
    self.onSubmitGroup(group);
  });
}


// Inherit.
NewGroupForm.prototype = Object.create(GroupForm.prototype);


////////////////////////////////////////////////////////////////////////////////
// Form to view\edit existing group.


EditGroupForm = function(groupName) {
  GroupForm.call(this, null);
  // Name of the group this form edits.
  this.groupName = groupName;
  // Last-Modified header of content (once loaded).
  this.lastModified = null;
  // Called when 'Delete group' action is invoked.
  this.onDeleteGroup = null;
}


// Inherit.
EditGroupForm.prototype = Object.create(GroupForm.prototype);


// Load contents of this from from the server.
EditGroupForm.prototype.load = function() {
  var defer = api.groupRead(this.groupName);
  var self = this;
  defer.then(function(response) {
    self.buildForm(response.data.group, response.headers['Last-Modified']);
  });
  return defer;
}


// Builds $element with this form given group data.
EditGroupForm.prototype.buildForm = function(group, lastModified) {
  // Convert some fields to more usable representation.
  group = _.clone(group);
  group.created_ts = common.utcTimestampToString(group.created_ts);
  group.members = (group.members || []).join('\n') + '\n';
  group.globs = (group.globs || []).join('\n') + '\n';
  group.nested = (group.nested || []).join('\n') + '\n';

  var self = this;
  this.$element = $(common.render('edit-group-form-template', group));
  this.lastModified = lastModified;

  // Delete button handler.
  $('#delete-btn', this.$element).click(function() {
    common.confirm('Delete this group?').done(function() {
      self.onDeleteGroup(self.groupName, self.lastModified);
    });
  });

  // Add validation and submit handler.
  this.hookUpHandlers($('form', this.$element), function(group) {
    self.onUpdateGroup(group, self.lastModified)
  });
}


////////////////////////////////////////////////////////////////////////////////
// Main entry point, sets up all high-level UI logic.


var groupChooser;
var mainFrame;


// Blocks UI until request completes.
var waitForResult = function(defer, form) {

  // Helper functions that locks\unlocks UI.
  var lockUI = function() {
    form.setInteractionDisabled(true);
    groupChooser.setInteractionDisabled(true);
  }

  var unlockUI = function() {
    form.setInteractionDisabled(false);
    groupChooser.setInteractionDisabled(false);
  }

  // Result of this call.
  var done = $.Deferred();

  // Lock UI while running the request.
  form.hideMessage();
  lockUI();

  // Launch the request.
  defer.then(function(response) {
    // Refetch the list of groups and return the result.
    groupChooser.refetchGroups().then(function() {
      unlockUI(false);
      done.resolve(response);
    }, function(error) {
      unlockUI(false);
      common.presentError(error.text);
      done.reject(error);
    });
  }, function(error) {
    unlockUI(false);
    form.showMessage('error', 'Oh snap!', error.error.text || error.text);
    done.reject(error);
  });

  return done.promise();
}


exports.onContentLoaded = function() {
  // Add validator for a group name.
  var groupRe = /^[0-9a-zA-Z_\-\. ]{3,40}$/;
  var memberRe = /^(user|bot|service|anonymous)\:[\w\-\+\%\.\@]+$/;
  var globRe = /^(user|bot|service|anonymous)\:[\w\-\+\%\.\@\*]+$/;

  // Add validators.
  $.validator.addMethod('groupName', function(value, element) {
    return groupRe.test(value);
  }, 'Invalid group name');
  $.validator.addMethod('memberList', _.partial(validateItemList, memberRe),
      'Invalid member entry, expected format is <b>type</b>:<b>id</b>');
  $.validator.addMethod('globList', _.partial(validateItemList, globRe),
      'Invalid pattern entry, expected format is <b>type</b>:<b>glob</b>');
  $.validator.addMethod('groupList', _.partial(validateItemList, groupRe),
      'Invalid group name');

  // Setup global UI elements.
  groupChooser = new GroupChooser($('#group-chooser'));
  mainFrame = new ContentFrame($('#main-content-pane'));

  // Called to setup 'Create new group' flow.
  var startNewGroupFlow = function() {
    var form = new NewGroupForm();
    form.onSubmitGroup = function(group) {
      var request = api.groupCreate(group);
      waitForResult(request, form).done(function() {
        groupChooser.setSelection(group.name);
      });
    };
    mainFrame.setContent(form);
  }

  // Called to setup 'Edit the group' flow (including deletion of a group).
  var startEditGroupFlow = function(groupName) {
    var form = new EditGroupForm(groupName);
    form.onDeleteGroup = function(groupName, lastModified) {
      var request = api.groupDelete(groupName, lastModified);
      waitForResult(request, form).done(function() {
        groupChooser.selectDefault();
      });
    }
    form.onUpdateGroup = function(group, lastModified) {
      var request = api.groupUpdate(group, lastModified);
      waitForResult(request, form).done(function() {
        groupChooser.setSelection(group.name);
      });
    }
    mainFrame.loadContent(form);
  }

  // Wire event handlers.
  groupChooser.onSelectionChanged(function(selection) {
    if (selection === null)
      startNewGroupFlow();
    else
      startEditGroupFlow(selection);
  });

  // Load and show data.
  groupChooser.refetchGroups().then(function() {
    groupChooser.selectDefault();
    common.presentContent();
  }, function(error) {
    common.presentError(error.text);
  });

  // Enable XSRF token auto-updater.
  api.setXSRFTokenAutoupdate(true);
}

return exports;

}());
