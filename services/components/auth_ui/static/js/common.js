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
}


// Fatal error happened during loading. Show it instead of a content.
exports.presentError = function(errorText) {
  // TODO(vadimsh): Improve.
  $('#error-box').text(errorText);
  $('#error-box').show();
  $('#content-box').show();
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


// Converts UTC timestamp (in milliseconds) to a readable string in local TZ.
// Based on http://stackoverflow.com/a/7412756
exports.utcTimestampToString = function(utc) {
  // Create a local date from the UTC.
  var t = new Date(Number(utc));
  // Subtract from the UTC time to get local.
  t.setTime(t.getTime() - t.getTimezoneOffset() * 60000);
  // Convert to string.
  var str = [t.getFullYear(), t.getMonth(), t.getDate()].join('/');
  str += ' ' + t.toLocaleTimeString();
  return str;
}


// Renders confirmation dialog. Returns deferred.
exports.confirm = function(message) {
  var defer = $.Deferred();
  // TODO: Reimplement using normal UI.
  if (window.confirm(message))
    defer.resolve();
  else
    defer.reject();
  return defer.promise();
}


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
}

return exports;

}());
