  var express = require('express'),
      passport = require('passport'),
      util = require('util'),
      ReverseProxyStrategy = require('../lib/');


// Use the ReverseProxyStrategy within Passport.
//   Specify one required HTTP request header and one optional header;
//   include an optional verify callback to check that
//   the username is an email address;
//   also verify that the proxy server is on the localhost/loopback adapter
passport.use(new ReverseProxyStrategy({
   headers: { 
               'X-Forwarded-User': { alias: 'username', required: true},
               'X-Forwarded-UserId': { alias: 'id', required: false }
   },
   // only allow localhost to proxy requests
   whitelist: '127.0.0.1/0'
  }
  ,
  function(headers, user, done) {
    var err = null;

    // verify that the username is an email address
    if (! /^.*@.*$/.test(headers['X-Forwarded-User'])) { return done(err, false, 401); }

    return done(err, user);
  }
));


var app = express();

// configure Express
app.configure(function() {
  app.use(express.logger('dev'));
  // Initialize Passport!  Note: no need to use session middleware when each
  // request carries authentication credentials, as is the case with HTTP Revese Proxy.
  app.use(passport.initialize());
  app.use(app.router);
  app.use(express.static(__dirname + '/public'));
});

// curl -v -I http://127.0.0.1:3000/
// curl -v -I -H "X-Forwarded-User: alice@example.com" http://127.0.0.1:3000/
// curl -v -I -H "X-Forwarded-User: alice@example.com" -H "X-Forwarder-UserId: 1" http://127.0.0.1:3000/
app.get('/',
  // Authenticate using HTTP Basic credentials, with session support disabled.
  passport.authenticate('reverseproxy', { session: false }),
  function(req, res){
    res.json({ username: req.user.username, id: req.user.id });
  });

app.listen(3000);
