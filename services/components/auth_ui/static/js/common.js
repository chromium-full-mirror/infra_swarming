var common = (function() {
var exports = {};
var templatesCache = {};


// Well... Taken from http://stackoverflow.com/a/4673436
if (!String.format) {
  String.format = function (format) {
    var args = Array.prototype.slice.call(arguments, 1);
    var sprintfRegex = /\{(\d+)\}/g;
    var sprintf = function (match, number) {
      return number in args ? args[number] : match;
    };
    return format.replace(sprintfRegex, sprintf);
  };
}


// Better than nothing...
exports.assert = function(condition, message) {
  if (!condition) {
    throw message || "Assertion failed";
  }
}


// Called during initial page load to show contents of a page once
// Javascript part fully forms it.
exports.presentContent = function() {
  $('#content-box').show();
  $('#error-box').hide();
}


// Fatal error happened during loading. Show it instead of a content.
exports.presentError = function(errorText) {
  $('#error-box #error-message').text(errorText);
  $('#error-box').show();
  $('#content-box').hide();
}


// Double checks with user and redirects to logout url.
exports.logout = function() {
  if (confirm('You\'ll be signed out from ALL your google accounts.'))
    window.location = config.logout_url;
}


// Fetches template code from #<templateId> element and renders it.
// Returns rendered string.
exports.render = function(templateId, context) {
  var template = templatesCache[templateId];
  if (!template) {
    var source = $('#' + templateId).html();
    template = Handlebars.compile(source);
    templatesCache[templateId] = template;
  }
  return template(context);
}


// Returns chunk of HTML code with form alert mark up.
exports.getAlertBoxHtml = function(type, title, message) {
  var cls = type == 'success' ? 'alert-success' : 'alert-danger';
  return exports.render(
      'alert-box-template', {cls: cls, title: title, message: message});
}


// Converts UTC timestamp (in milliseconds) to a readable string in local TZ.
exports.utcTimestampToString = function(utc) {
  return (new Date(Number(utc))).toLocaleString();
}


// Renders confirmation dialog. Returns deferred.
exports.confirm = function(message) {
  var defer = $.Deferred();
  if (window.confirm(message))
    defer.resolve();
  else
    defer.reject();
  return defer.promise();
}


// Wrapper around 'Im busy' UI indicator.
var ProgressSpinner = function() {
  this.$element = $('#progress-spinner');
  this.counter = 0;
}


// Shows progress indicator.
ProgressSpinner.prototype.show = function() {
  this.counter += 1;
  if (this.counter == 1)
    this.$element.removeClass('not-spinning').addClass('spinning');
}


// Hides progress indicator.
ProgressSpinner.prototype.hide = function() {
  if (this.counter == 0)
    return;
  this.counter -= 1;
  if (this.counter == 0)
    this.$element.removeClass('spinning').addClass('not-spinning');
}


// Setup common for all pages.
exports.onContentLoaded = function() {
  // Configure form validation plugin to work with bootstrap styles.
  // See http://stackoverflow.com/a/18754780
  $.validator.setDefaults({
    highlight: function(element) {
      $(element).closest('.form-group').addClass('has-error');
    },
    unhighlight: function(element) {
      $(element).closest('.form-group').removeClass('has-error');
    },
    errorElement: 'span',
    errorClass: 'help-block',
    errorPlacement: function(error, element) {
      if(element.parent('.input-group').length) {
        error.insertAfter(element.parent());
      } else {
        error.insertAfter(element);
      }
    }
  });


  // Install 'Ajax is running' indicator.
  var progressSpinner = new ProgressSpinner();
  $(document).ajaxStart(function() {
    progressSpinner.show();
  });
  $(document).ajaxStop(function() {
    progressSpinner.hide();
  });
}

return exports;

}());
