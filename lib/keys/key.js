var crypto = require('crypto')
var extend = require('extend')
var debug = require('debug')('key')
var stringify = require('@tradle/utils').stringify
var safe = require('safecb')
var hash = require('../utils').hash
var DIFF_KEY_ERR = 'This is a certificate for a different key'

function Key (props) {
  this._props = props = extend(true, {
    type: this.type()
  }, props)

  var priv = props.priv
  var pub = props.pub || props.value
  if (priv) {
    if (typeof priv === 'string') {
      this._priv = this.parsePriv(priv)
    } else {
      this._priv = priv
      props.priv = this.stringifyPriv(priv)
    }
  }

  if (pub) {
    if (typeof pub === 'string') {
      this._pub = this.parsePub(pub)
    } else {
      this._pub = pub
    }
  } else {
    this._pub = this.pubFromPriv(this._priv)
  }

  if (typeof pub !== 'string') pub = this.stringifyPub(pub)

  props.pub = props.value = pub

  var print = props.fingerprint || this.fingerprintFromPub(this._pub)
  props.fingerprint = print
  this._fingerprint = print
}

Key.prototype.toJSON =
Key.prototype.exportPublic = function () {
  var json = {
    type: this.constructor.type
  }

  for (var p in this._props) {
    if (this._props.hasOwnProperty(p) && p !== 'priv') {
      var val = this._props[p]
      if (val != null) json[p] = val
    }
  }

  // export json.value a la openname
  json.value = json.pub
  delete json.pub
  return json
}

Key.prototype.exportPrivate = function () {
  var json = this.exportPublic()
  json.priv = this.stringifyPriv(this._priv)
  return json
}

Key.prototype._debug = function () {
  var args = [].slice.call(arguments)
  args.unshift(this.type())
  return debug.apply(null, args)
}

Key.prototype.priv = function () {
  return this._priv
}

Key.prototype.pub = function (val) {
  return this._pub
}

Key.prototype.pubKeyString = function () {
  return this._props.pub || this._props.value
}

Key.prototype.fingerprint = function () {
  return this._fingerprint
}

Key.prototype.get = function (prop) {
  return this._props[prop]
}

Key.prototype.equals = function (key) {
  return key && this.pubKeyString() === key.pubKeyString()
}

Key.prototype.sign = function (msg, cb) {
  return this._sign(hash(msg), cb)
}

Key.prototype.signSync = function (msg) {
  return this._signSync(hash(msg))
}

Key.prototype.verify = function (msg, sig, cb) {
  return this._verify(hash(msg), sig, cb)
}

Key.prototype.verifySync = function (msg, sig) {
  try {
    return this._verifySync(hash(msg), sig)
  } catch (err) {
    this._debug('failed to verify sig:', err.message)
    return false
  }
}

/**
 * default implementation
 */
Key.prototype._sign = function (msg, cb) {
  cb = safe(cb)
  try {
    var ret = this._signSync(msg)
    cb(null, ret)
    return ret
  } catch (err) {
    cb(err)
  }
}

Key.prototype._signSync = function (msg) {
  return this._priv.sign(msg)
}

/**
 * default implementation
 */
Key.prototype._verify = function (msg, sig, cb) {
  cb = safe(cb)
  try {
    var ret = this._verifySync(msg, sig)
    cb(null, ret)
    return ret
  } catch (err) {
    cb(err)
  }
}

/**
 * default implementation
 */
Key.prototype._verifySync = function (msg, sig) {
  return this._pub.verify(msg, sig)
}

Key.prototype.encrypt = function (msg) {
  throw new Error('override this')
}

Key.prototype.decrypt = function (msg) {
  throw new Error('override this')
}

Key.prototype.validate = function () {
  return {
    result: true,
    reason: null
  }
}

Key.prototype.toString = function () {
  return stringify(this.toJSON())
}

Key.prototype.hash = function () {
  return crypto
    .createHash('sha256')
    .update(this.pub())
    .digest('hex')
}

Key.prototype.parsePriv = function (str) {
  throw new Error('override this')
}

Key.prototype.parsePub = function (str) {
  throw new Error('override this')
}

Key.prototype.stringifyPriv = function (key) {
  throw new Error('override this')
}

Key.prototype.stringifyPub = function (key) {
  throw new Error('override this')
}

Key.prototype.pubFromPriv = function (key) {
  throw new Error('override this')
}

Key.prototype.fingerprintFromPub = function (pub) {
  throw new Error('override this')
}

Key.prototype.validateRevocation = function (cert, cb) {
  cb = safe(cb)
  var result = {
    result: false,
    reason: null
  }

  cert = extend(true, {}, cert)
  var sig = cert._sig
  delete cert._sig
  if (cert.value !== this.pubKeyString()) {
    result.reason = DIFF_KEY_ERR
  } else if (!isValidRevocationReason(cert.reason)) {
    result.reason = 'Invalid revocation reason'
  }

  if (result.reason) return cb(null, result)

  this.verify(stringify(cert), sig, function (err, verified) {
    if (err) return cb(err)

    if (verified) result.result = true
    else result.reason = DIFF_KEY_ERR

    cb(null, result)
  })
}

Key.prototype.addRevocation = function (reason, cb) {
  var revocations = this._props.revocations = this._props.revocations || []
  this.generateRevocation(reason, function (err, revocation) {
    if (err) return cb(err)

    revocations.push(revocation)
    cb()
  })
}

Key.prototype.generateRevocation = function (reason, cb) {
  if (!isValidRevocationReason(reason)) throw new Error('Invalid revocation reason')

  var data = {
    reason: reason,
    value: this.pubKeyString(),
    nonce: crypto.randomBytes(16).toString('hex')
  }

  this.sign(stringify(data), function (err, sig) {
    if (err) return cb(err)

    data._sig = sig
    cb(null, data)
  })
}

Key.prototype.type = function () {
  return this.constructor.type
}

Key.hasDeterministicSig =
Key.prototype.hasDeterministicSig = function () {
  return false
}

Key.REVOCATION_REASONS = extend(Object.create(null), {
  unspecified: 0,
  keyCompromise: 1,
  CACompromise: 2,
  affiliationChanged: 3,
  superseded: 4,
  cessationOfOperation: 5,
  certificateHold: 6,
  removeFromCRL: 8,
  privilegeWithdrawn: 9,
  AACompromise: 10
})

function isValidRevocationReason (num) {
  for (var p in Key.REVOCATION_REASONS) {
    if (Key.REVOCATION_REASONS[p] === num) return true
  }
}

module.exports = Key
