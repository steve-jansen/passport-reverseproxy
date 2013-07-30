var vows = require('vows');
var assert = require('assert');
var util = require('util');
var ReverseProxyStrategy = require('../lib/passport-reverseproxy');


vows.describe('ReverseProxyStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new ReverseProxyStrategy(function() {});
    },
    
    'should be named reverseproxy': function (strategy) {
      assert.equal(strategy.name, 'reverseproxy');
    },
  },
  
  'strategy using all defaults to process X-Forwarded-User and without a verify callback': {
    topic: function() {
      var strategy = new ReverseProxyStrategy();
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'john.doe@example.com');
      },
    },
  },

  'strategy handling a request with a verify callback': {
    topic: function() {
      var strategy = new ReverseProxyStrategy(function(headers, user, done) {
        user.name = 'John Doe';
        done(null, user);
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'john.doe@example.com');
        assert.equal(user.name, 'John Doe');
      },
    },
  },

  'strategy handling a request that is not verified by the callback': {
    topic: function() {
      var strategy = new ReverseProxyStrategy(function(headers, user, done) {
        done(null, false);
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should not authenticate' : function(err, user) {
        assert.isUndefined(user);
      }
    },
  },
  
  'strategy handling a request that encounters an error during verification': {
    topic: function() {
      var strategy = new ReverseProxyStrategy(function(headers, user, done) {
        done(new Error('something went wrong'));
      });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(new Error('should not be called'));
        }
        strategy.error = function(err) {
          self.callback(null, err);
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, e) {
        assert.isNull(err);
      },
      'should call error' : function(err, e) {
        assert.instanceOf(e, Error);
      },
    },
  },
  
  'strategy handling a request without authorization credentials': {
    topic: function() {
      var strategy = new ReverseProxyStrategy();
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.headers = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 401' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 401);
      },
    },
  },
  
  'strategy handling a request with Basic authorization credentials instead of custom headers': {
    topic: function() {
      var strategy = new ReverseProxyStrategy();
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.headers = {};
        req.headers.authorization = 'Basic Ym9iOnNlY3JldA==';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 401' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 401);
      },
    },
  },
  
  'strategy handling a request missing a required header': {
    topic: function() {
      var strategy = new ReverseProxyStrategy({
          headers: {
            'X-Forwarded-User': true,
            'X-Forwarded-UserId': true
          }
        });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        };
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        };
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with 401' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 401);
      },
    },
  },
  
  'strategy handling a request missing a required header #2': {
    topic: function() {
      var strategy = new ReverseProxyStrategy({
          headers: {
            'X-Forwarded-User': { alias: 'username', required: true },
            'X-Forwarded-UserId': { required: true }
          }
        });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 401);
      },
    },
  },
  
  'strategy handling a request with an empty string in a required authorization header': {
    topic: function() {
      var strategy = new ReverseProxyStrategy();
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = '';

        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 401);
      },
    },
  },
  
  'strategy handling a request with a null value for a required authorization header': {
    topic: function() {
      var strategy = new ReverseProxyStrategy();
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(status) {
          self.callback(null, status);
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = null;

        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should fail authentication with challenge' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 401);
      },
    },
  },

  'strategy using a whitelist to allow proxy forwarding from localhost only should fail for remote clients': {
    topic: function() {
      var strategy = new ReverseProxyStrategy({ whitelist: '127.0.0.1/0' });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should not be called'));
        }
        strategy.fail = function(challenge) {
          self.callback(null, challenge);
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        req.connection = { remoteAddress: '10.8.4.1' };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should fail authentication with 401' : function(err, challenge) {
        // fail action was called, resulting in test callback
        assert.isNull(err);
        assert.equal(challenge, 401);
      },
    },
  },

  'strategy using a whitelist to allow proxy forwarding from localhost only should succeed for localhost': {
    topic: function() {
      var strategy = new ReverseProxyStrategy({ whitelist: '127.0.0.1/0' });
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(null, user);
        }
        strategy.fail = function() {
          self.callback(new Error('should not be called'));
        }
        
        req.headers = {};
        req.headers['x-forwarded-user'] = 'john.doe@example.com';
        req.connection = { remoteAddress : '127.0.0.1' };
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not generate an error' : function(err, user) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, user) {
        assert.equal(user.username, 'john.doe@example.com');
      },
    },
  },

}).export(module);
