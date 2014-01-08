var api = (function() {
var exports = {};

var xsrf_token = null;
var xsrf_token_timer = null;
var xsrf_update_interval = 30 * 60 * 1000;


// Return dict subset of response headers used by API.
// Keys are in camel case.
var extractHeaders = function(jqXHR) {
  var headers = {};
  _.each(['Last-Modified'], function(key) {
    headers[key] = jqXHR.getResponseHeader(key);
  });
  return headers;
}


// Makes an asynchronous call to API endpoint. Returns a promise.
// On success result value is
//    {status: 'success', code: <good HTTP code>, data: <whatever API returned>}
// On failure result value is
//    {status: 'error', code: <bad HTTP code>, error: <whatever API returned>}
var call = function(type, url, data, headers) {
  // Append XSRF token header to the request if known.
  headers = _.clone(headers || {});
  if (xsrf_token)
    headers['X-XSRF-Token'] = xsrf_token;

  // Launch the request.
  var request = $.ajax({
    type: type,
    url: url,
    data: (data != null) ? JSON.stringify(data) : null,
    cache: false,
    contentType: 'application/json; charset=UTF-8',
    dataType: 'json',
    headers: headers
  });

  // Future return value.
  var defer = $.Deferred();

  // Convert from jQuery odd signature to saner one.
  request.done(function(data, textStatus, jqXHR) {
    defer.resolve({
      status: textStatus,
      code: jqXHR.status,
      data: data,
      headers: extractHeaders(jqXHR)
    });
  });

  // Deal with few more oddities.
  request.fail(function(jqXHR, textStatus, errorThrown) {
    // Oddly jQuery doesn't parse JSON body of a failed response (like 403).
    var errorObj = jqXHR.responseText;
    var errorText = jqXHR.responseText;
    var contentType = jqXHR.getResponseHeader('content-type') || '';
    if (contentType.indexOf('application/json') != -1) {
      try {
        errorObj = $.parseJSON(jqXHR.responseText);
        if (_.has(errorObj, 'text'))
          errorText = errorObj.text;
      } catch (err) {
        // Server tricked us by giving incorrect content type...
        console.error(err);
      }
    }
    // Assemble all know information into human readable multiline string.
    var readableText = String.format(
        'Request to \'{0}\' failed ({1}) with code {2}.\n{3}',
        url, textStatus, jqXHR.status, errorText);
    console.error(readableText);
    // And return that to waiting caller.
    defer.reject({
      status: textStatus,
      code: jqXHR.status,
      error: errorObj,
      headers: extractHeaders(jqXHR),
      text: readableText
    });
  });

  return defer.promise();
}


// Sets XSRF token.
exports.setXSRFToken = function(token) {
  xsrf_token = token;
}


// Refetches XSRF token from server.
exports.updateXSRFToken = function() {
  var defer = $.Deferred();
  var endpoint = '/auth/api/v1/accounts/xsrf_token';
  var headers = {'X-XSRF-Token-Request': '1'};
  call('POST', endpoint, null, headers).then(function(response) {
    exports.setXSRFToken(response.data.xsrf_token);
    defer.resolve(response);
  }, function(error) {
    defer.reject(error);
  });
  return defer.promise();
}


// Enable XSRF token refresh timer.
exports.setXSRFTokenAutoupdate = function(autoUpdate) {
  if (!autoUpdate && xsrf_token_timer) {
    clearTimeout(xsrf_token_timer);
    xsrf_token_timer = null;
  }
  if (autoUpdate && !xsrf_token_timer) {
    xsrf_token_timer = setTimeout(function() {
      var timer_id = xsrf_token_timer;
      exports.updateXSRFToken().always(function() {
        if (timer_id == xsrf_token_timer) {
          xsrf_token_timer = null;
          exports.setXSRFTokenAutoupdate(true);
        }
      });
    }, xsrf_update_interval);
  }
}


// List all known user groups.
exports.groups = function() {
  return call('GET', '/auth/api/v1/groups');
}


// Create a new user group.
exports.groupCreate = function(group) {
  if (!group.name)
    throw 'Missing group name'
  return call('POST', '/auth/api/v1/groups/' + group.name, {
    name: group.name,
    description: group.description,
    members: group.members || [],
    globs: group.globs || [],
    nested: group.nested || []
  });
}


// Fetch detailed information about the group.
exports.groupRead = function(name) {
  return call('GET', '/auth/api/v1/groups/' + name);
}


// Update group information.
exports.groupUpdate = function(group, lastModified) {
  var headers = {};
  if (lastModified)
    headers['If-Unmodified-Since'] = lastModified;
  return call('PUT', '/auth/api/v1/groups/' + group.name, {
    name: group.name,
    description: group.description,
    members: group.members || [],
    globs: group.globs || [],
    nested: group.nested || []
  }, headers);
}


// Delete the group.
exports.groupDelete = function(name, lastModified) {
  var headers = {};
  if (lastModified)
    headers['If-Unmodified-Since'] = lastModified;
  return call('DELETE', '/auth/api/v1/groups/' + name, null, headers);
}


// Fetch all ACL rules.
exports.rulesRead = function() {
  return call('GET', '/auth/api/v1/rules');
}


// Update all ACL rules.
exports.rulesUpdate = function(rules, lastModified) {
  var headers = {};
  if (lastModified)
    headers['If-Unmodified-Since'] = lastModified;
  return call('PUT', '/auth/api/v1/rules', {rules: rules.rules}, headers);
}


// Perform a test query against ACL rules.
exports.rulesCheck = function(params) {
  return call('POST', '/auth/api/v1/rules/check', {
    rules: params.rules,
    identity: params.identity,
    resource: params.resource,
    action: params.action
  });
}


return exports;

}());
