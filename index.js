var crypto = require('crypto');

function RailsSessionDecode(secret) {
  this.secret = secret;
  this.cookieSalt = 'encrypted cookie'; //Rails.application.config.action_dispatch.encrypted_cookie_salt
  this.signedCookieSalt = 'signed encrypted cookie'; //Rails.application.config.action_dispatch.encrypted_signed_cookie_salt
  this.iterations = 1000;
  this.keyLength = 64;
}

function decodeCookie(cookie, isSignedCookie, next) {
  if (!cookie) {
    return next(new Error('cookie was empty.'))
  }

  var cookieSegments = cookie.split('--');
  if (cookieSegments.length != 2) {
    return next(new Error('invalid cookie format.'));
  }

  var sessionData = new Buffer(cookieSegments[0], 'base64');
//    var signature = cookieSegments[1];

  var sessionDataSegments = sessionData.toString('utf8').split('--');
  if (sessionDataSegments.length != 2) {
    return next(new Error('invalid cookie format.'));
  }

  var data = new Buffer(sessionDataSegments[0], 'base64');
  var iv = new Buffer(sessionDataSegments[1], 'base64');
  var salt = isSignedCookie ? this.signedCookieSalt : this.cookieSalt;

  crypto.pbkdf2(this.secret, salt, this.iterations, this.keyLength, function(err, derivedKey) {
    if (err) return next(err);

    try {
      var decipher = crypto.createDecipheriv('aes-256-cbc', derivedKey.slice(0, 32), iv.slice(0, 16));
      var decryptedData = decipher.update(data, 'binary', 'utf8') + decipher.final('utf8');

      next(null, decryptedData);
    } catch(e) {
      next(e);
    }
  });
}

RailsSessionDecode.prototype = {
  decodeCookie: function(cookie, next) {
    return decodeCookie.call(this, cookie, false, next);
  },

  decodeSignedCookie: function(cookie, next) {
    return decodeCookie.call(this, cookie, true, next);
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
}

/**
 *
 * @param {String} secret
 */
module.exports = function(secret) {
  return new RailsSessionDecode(secret);
};

/**
 * Rails Session Decoder
 */
module.exports.RailsSessionDecode = RailsSessionDecode;
