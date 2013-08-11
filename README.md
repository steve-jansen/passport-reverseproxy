# Passport-ReverseProxy

HTTP reverse proxy authentication strategies for [Passport](https://github.com/jaredhanson/passport).

This module lets you authenticate HTTP requests using HTTP header values injected by a
HTTP reverse proxy server in front of your application server.  Reverse proxy authentication
is a technique for enterprise networks to provide Single Sign On (SSO) for enterprise users.

By plugging into Passport, support for these schemes can be easily and unobtrusively integrated into any
application or framework that supports [Connect](http://www.senchalabs.org/connect/)-style
middleware, including [Express](http://expressjs.com/).

## Install

    $ npm install passport-reverseproxy

## Usage of HTTP 

#### Using Apache as a reverse proxy

Here is an example of configuring Apache for use as a reverse proxy using a local passwd file.

Credit: [Jenkins Reverse Proxy Auth Plugin](https://wiki.jenkins-ci.org/display/JENKINS/Reverse+Proxy+Auth+Plugin)

    <Location />
        AuthName "Please sign in with your Apache user name and password"
        AuthType BASIC
        AuthUserFile /etc/apache2/passwd
        Require valid-user

        # prevent the client from setting this header
        RequestHeader unset X-Forwarded-User

        # Adds the X-Forwarded-User header that indicates the current user name.
        # this portion came from http://old.nabble.com/Forcing-a-proxied-host-to-generate-REMOTE_USER-td2911573.html#a2914465
        RewriteEngine On
        # see the Apache documentation on why this has to be lookahead
        RewriteCond %{LA-U:REMOTE_USER} (.+)
        # this actually doesn't rewrite anything. what we do here is to set RU to the match above
        RewriteRule .* - [E=RU:%1]
        RequestHeader set X-Forwarded-User %{RU}e
    </Location>

> Notes:
> * Make sure that clients cannot bypass the reverse proxy. If they can send requests directly to Jenkins, then a malicious client can send in arbitrary header name with arbitrary value, thus compromising the security of Jenkins
> * Make sure you configure the reverse proxy to erase the header that you use to pass the authenticated user name. This prevents malicious client from setting the header name with arbitrary value, which would ruin the security.


#### Configure Strategy

The HTTP Reverse proxy authentication strategy authenticates users by inspecting a
configurable set of HTTP request headers. 

By default, the strategy will look for a request header named 'X-Forwarded-User',
which will be used as the value for `req.user.username`.

Optionally, you can specify the request headers that should participate in 
authentication decisions via the `options.headers` map:

    var express = require('express'),
        passport = require('passport'),
        ReverseProxyStrategy = require('passport-reverseproxy');

    passport.use(new ReverseProxyStrategy({
        headers: {
          'X-Forwarded-User': { alias: 'username', required: true },
          'X-Forwarded-UserEmail': { alias: 'email', required: false }
        }
      })
    );

    // require authentication for all requests except favicon.ico
    app.configure(function() {
      app.use(express.favicon())
      app.use(express.bodyParser());
      app.use(passport.initialize());
      app.use(passport.authenticate('reverseproxy', { session: false }));
      app.use(express.static(path.join(__dirname, 'public')));
    });

You can also specify a network range as a whitelist of allowed client
connections to your app.  The whitelist is a cursory security check
to verify the end user did not circumvent the reverse proxy server.
Your deployment should use this setting merely as a defense in depth
layer alongside more robust network access control techniques 
(e.g.,  IPSec tunnels, VLANs, firewall rules). Advanced enterprise
reverse proxy appliances may also include a non-repudiatable
token, like a digital signature, that you should validate
in the `verify` function.

    passport.use(new ReverseProxyStrategy({
        headers: {
          'X-Forwarded-User': { alias: 'username', required: true },
          'X-Forwarded-UserId': { alias: 'id', required: false }
        },
         // only allow localhost to proxy requests
        whitelist: '127.0.0.1/0'
      })
    );

Unlike most Passport authentication strategies, it is unlikely you will need
session caching of the authentication ticket, since the reverse proxy should
inject the headers into every request to your server.

The strategy optinally supports a `verify` callback, which accepts these
reverse proxy header values and calls `done` providing a user.

    passport.use(new ReverseProxyStrategy({
       headers: { 
          'X-Forwarded-User': { alias: 'username', required: true },
          'X-Forwarded-UserId': { alias: 'id', required: false }
       },
       // only allow localhost to proxy requests
       whitelist: '127.0.0.1/0'
      },
      function(headers, user, done) {
        var err = null;

        // verify that the username is an email address
        if (! /^.*@.*$/.test(headers['X-Forwarded-User'])) { return done(err, false, 401); }

        return done(err, user);
      })
    );

#### Authenticate Requests

Use `passport.authenticate()`, specifying the `'reverseproxy'` strategy, to
authenticate requests.  Requests relying on request header values are inherently
stateless, and should not require session support, so the `session` option can be set to `false`.

For example, as route middleware in an [Express](http://expressjs.com/)
application:

    app.get('/private', 
      passport.authenticate('reverseproxy', { session: false }),
      function(req, res) {
        res.json(req.user);
      });

#### Examples

For a complete, working example, refer to the [Reverse Proxy example](https://github.com/steve-jansen/passport-reverseproxy/tree/master/examples).

## Credits

  - [Steve Jansen](http://github.com/steve-jansen)

## License

[The MIT License](http://opensource.org/licenses/MIT)

