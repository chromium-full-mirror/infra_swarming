var common = (function() {
var exports = {};

// Double checks with user and redirect to logout url.
exports.logout = function() {
  if (confirm('You\'ll be signed out from ALL your google accounts.'))
    window.location = config.logout_url;
}

return exports;

}());
