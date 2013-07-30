"use strict";

/**
 * Module dependencies.
 */
var passport = require('passport'),
    util = require('util'),
    Netmask = require('netmask').Netmask;

/**
 * Framework version.
 */
require('pkginfo')(module, 'version');

/**
 * `ReverseProxyStrategy` constructor.
 *
 * The HTTP reverse proxy authentication strategy authenticates requests
 * based on arbitrary HTTP request header values.
 *
 * Applications can optionally supply a `verify` callback which accepts a
 * `headers` map of all configured request headers applicable
 * to the request proxy, a `user` object deserialized from the `headers` values
 * and any `headers` aliases, a `done` callback.
 * The `verify` callback invokes the `done` callback supplying a `user`,
 * which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Optionally, `options` can be used to change the authentication realm.
 *
 * If present, this strategy will validate that the IP address of the
 * client connection matches the whitelist network mask;
 * this is a cursory security check to verify the end user did not
 * circumvent the reverse proxy server.  Your deployment should used
 * this merely as a defense in depth layer alongside more robus
 * network access control techniques such as IPSec, VLANs, firewall rules, etc.
 * Advanced enterprise reverse proxy appliances may also include
 * a non-repudiatable token, like a digital signature, which you can
 * validate in the `verify` function.
 *
 *
 * Options:
 *   - `headers`  An object map describing the request header(s) injected by
 *                by the reverse proxy; the object map can be of type:
 *                 `{
 *                    // header-name1 is a required header 
 *                    'header-name1': true,
 *
 *                     // header-name2 is an optional header
 *                    'header-name2': false,
 *
 *                     // header-name3 is an optional header,
 *                     // aliased as `user.id`
 *                    'header-name3': 'id',
 *
 *                     // header-name4 is required, aliased as `user.email`
 *                    'header-name4': { 'alias': 'email', required: true }
 *                   }`
 *                     
 *                * `alias` (optional) the name of the `user` property to assign
 *                   using the header value; defaults to name of the header
 *
 *                * `required`: (optional) a boolean flag if authentication
 *                   should fail when this header is missing, or a zero length
 *                   string; defaults to false
 *
 *                options.headers defaults to
 *                `{ 'X-Forwarded-User': { alias: 'username', required: true }`
 *
 *   - `whitelist` (optional) The IP address of the reverse proxy in netmask format;
 *
 * Examples:
 *
 *     passport.use(new ReverseProxyStrategy(
 *       function(headers, user, done) {
 *          var err = null;
 *
 *          // verify that the username header matches the format for an email address
 *          if (! /^.*@.*$/.test(headers['X-Forwarded-User'])) { err = new Error('Username must be an email address.'); }
 *
 *          done(err, user);
 *       }
 *     ));
 *
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function ReverseProxyStrategy(options, verify) {
  if (typeof options === 'function') {
    verify = options;
    options = {};
  }

  // provide a default implementation of `verify` as needed
  if (!verify || typeof(verify) !== "function") {
    verify = function(headers, user, done) { console.log("done"); done(null, user); }
  }

  options = options || {};

  // default the list of required headers to 'X-Forwarded-User', set as the username
  if (!options.headers || !Object.keys(options.headers).length) {
    console.warn('ReverseProxyStrategy: the HTTP request header configuration was empty; defaulting to using the X-Forwarded-User request header for authentication');
    options.headers = { 'X-Forwarded-User': { alias: 'username', required: true } };
  } else {
    // normalize the each header option into a map, which can specified as a map, boolean, or string
    for (var name in options.headers) {
      var value = options.headers[name];

      if (typeof(value) === "boolean") {
        options.headers[name] = { required: value }
      } else if (typeof(value) === "string") {
        options.headers[name] = { alias: value, required: false }
      }
    }
  }

  if (options.whitelist && options.whitelist.length) {
    this._whitelist = new Netmask(options.whitelist);
  }

  passport.Strategy.call(this);
  this.name = 'reverseproxy';
  this._verify = verify;
  this._options = options;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(ReverseProxyStrategy, passport.Strategy);

/**
 * Authenticate request based on the contents of HTTP request header(s).
 *
 * @param {Object} req
 * @api protected
 */
ReverseProxyStrategy.prototype.authenticate = function(req) {
  var map = this._options.headers;
  var subset = {};    // a filtered subset of the req.headers; includes any headers described in _options.headers
  var user = {};      // a user object populated from the req.headers; uses the alias values in _options.headers
  var headerConfig;   // the config settings for a request header participating in reverse proxy authentication
  var headerValue;    // the raw value of a request header participating in reverse proxy authentication
  var reverseProxyIp; // the ip address of the reverse proxy server

  // if a whitelist is configured, verify that the requesting REMOTE_ADDR is in the expected IP range
  if (this._whitelist) {
    reverseProxyIp = req.connection.remoteAddress;

    if (!reverseProxyIp || !this._whitelist.contains(reverseProxyIp)) {
      console.warn('ReverseProxyStrategy: proxy server ip address  "' + reverseProxyIp + '" outside the allowed whitelist (' + this._whitelist.toString() + ').  Failing authentication');
      return this.fail(401);
    }
  }

  for(var headerName in map) {
    headerConfig = map[headerName];
    headerValue = req.headers[headerName.toLowerCase().trim()];
    subset[headerName] = headerValue;

    // fail authentication if any required headers are missing or are an empty string
    if (headerConfig && headerConfig.required === true) {
      if (!headerValue || !headerValue.trim().length)  {
        console.warn('ReverseProxyStrategy: required HTTP request header "' + headerName + '" not found.  Failing authentication.');
        return this.fail(401);
      }
    }

    // set the user object using the name or alias for the header and value of the header
    if (headerConfig && headerConfig.alias && headerConfig.alias.length) {
      user[headerConfig.alias] = headerValue || "";
    } else {
      user[headerName] = headerValue || "";
    }
  }

  var self = this;

  function done(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }

  this._verify(subset, user, done);
}


/**
 * Expose constructors.
 */
module.exports = ReverseProxyStrategy;
