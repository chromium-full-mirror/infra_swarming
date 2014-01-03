var api = (function() {
var exports = {};
var xsrf_token = null;


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
  headers = _.clone(headers || {});
  // TODO: add XSRF token header here.
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
    // TODO: extract new XSRF token here.
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


return exports;

}());
