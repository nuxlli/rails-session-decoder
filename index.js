var crypto = require('crypto');

function RailsSessionDecode(secret) {
  // Old api support
  if (!(this instanceof arguments.callee) ) {
    return new arguments.callee(secret);
  }

  this.secret = secret;
  this.cookieSalt = 'encrypted cookie'; //Rails.application.config.action_dispatch.encrypted_cookie_salt
  this.signedCookieSalt = 'signed encrypted cookie'; //Rails.application.config.action_dispatch.encrypted_signed_cookie_salt
  this.iterations = 1000;
  this.keyLength = 64;
}

RailsSessionDecode.prototype = {
  decodeCookie: function(cookie, isSignedCookie, next) {
    if (typeof(isSignedCookie) === 'function') {
      next = isSignedCookie;
      isSignedCookie = false;
    }

    try {
      var opts = this.__prepare(cookie, isSignedCookie);
    } catch (err) {
      return next(err);
    }

    var self = this;
    crypto.pbkdf2(this.secret, opts.salt, this.iterations, this.keyLength, function(err, derivedKey) {
      if (err) return next(err);

      try {
        var decryptedData = self.__decodeWithDerivedKey(derivedKey, opts.iv, opts.data);
        next(null, decryptedData);
      } catch(e) {
        next(e);
      }
    });
  },

  decodeCookieSync: function(cookie, isSignedCookie) {
    if (typeof(isSignedCookie) === 'function') {
      next = isSignedCookie;
      isSignedCookie = false;
    }

    var opts = this.__prepare(cookie, isSignedCookie);
    var derivedKey    = crypto.pbkdf2Sync(this.secret, opts.salt, this.iterations, this.keyLength);
    return this.__decodeWithDerivedKey(derivedKey, opts.iv, opts.data);
  },

  decodeSignedCookie: function(cookie, next) {
    return this.decodeCookie(cookie, true, next);
  },

  decodeSignedCookieSync: function(cookie) {
    return this.decodeCookieSync(cookie, true);
  },

  setSecret: function(newSecret) {
    this.secret = newSecret;
  },

  setCookieSalt: function(newCookieSalt) {
    this.cookieSalt = newCookieSalt;
  },

  setSignedCookieSalt: function(newSignedCookieSalt) {
    this.signedCookieSalt = newSignedCookieSalt;
  },

  setIterations: function(newIterations) {
    this.iterations = newIterations;
  },

  setKeyLength: function(newKeyLength) {
    this.keyLength = newKeyLength;
  },

  __decodeWithDerivedKey: function(derivedKey, iv, data) {
    var decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey.slice(0, 32), iv.slice(0, 16));
    return decipher.update(data, 'binary', 'utf8') + decipher.final('utf8');
  },

  __prepare: function(cookie, isSignedCookie) {
    if (!cookie) {
      throw new Error('cookie was empty.');
    }

    var cookieSegments = cookie.split('--');
    if (cookieSegments.length != 2) {
      throw new Error('invalid cookie format.');
    }

    var sessionData = new Buffer(cookieSegments[0], 'base64');
    var sessionDataSegments = sessionData.toString('utf8').split('--');
    if (sessionDataSegments.length != 2) {
      throw new Error('invalid cookie format.');
    }

    return {
      data : new Buffer(sessionDataSegments[0], 'base64'),
      iv   : new Buffer(sessionDataSegments[1], 'base64'),
      salt : isSignedCookie ? this.signedCookieSalt : this.cookieSalt,
    }
  }
}

/**
 *
 * @param {String} secret
 */
module.exports = RailsSessionDecode;
