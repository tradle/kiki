
/**
 * INSECURE secure element mock
 */

var find = require('array-find')
var toKey = require('midentity').toKey
var safe = require('safecb')
var utils = require('tradle-utils')
var KEY_NOT_FOUND_ERR = new Error('key not found')

module.exports = function kiki (keys) {
  keys = keys.map(toKey)

  function findKey (pub) {
    return find(this._keys, function (key) {
      return key.pubKeyString() === pub.value
    })
  }

  return {
    sign: function (pub, msg, cb) {
      cb = safe(cb)
      var key = findKey(pub)
      if (key) cb(null, key.sign(msg))
      else cb(KEY_NOT_FOUND_ERR)
    },
    // decrypt: function (pub, msg, cb) {
    //   cb = safe(cb)
    //   var key = findKey(pub)
    //   if (key) cb(null, key.decrypt(msg))
    //   else cb(KEY_NOT_FOUND_ERR)
    // },
    ecdh: function (pub1, pub2, cb) {
      cb = safe(cb)
      var priv = findKey(pub1)
      var pub
      if (priv) {
        pub = pub2
      } else {
        priv = findKey(pub2)
        if (!priv) return cb(KEY_NOT_FOUND_ERR)

        pub = pub1
      }

      return utils.sharedEncryptionKey(priv, pub)
    }
  }
}
