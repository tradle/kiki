# kiki

Wrappers for DSA, EC, Bitcoin and other keys to provide a common API for signing/verifying/importing/exporting

_this module is used by [Tradle](https://github.com/tradle/about/wiki)_

## Usage

```js
var kiki = require('kiki');
var Keys = kiki.Keys

// load ec public key
var ecPubKey = new Keys.EC({
  pub: '022ee9fefd1b275d4ee1e7c41157cd4753ad4cbd0cbfdc76eef85ebae230bf27ee'
})

// load ec private key
var ecPrivKey = new Keys.EC({
  priv: '01762d59097688a1f1cd241aadee4cb1bd3d37017f71501b28e85ecdab5349c2'
})

// new ec private key
var newECKey = Keys.EC.gen({
  curve: 'ed25519'
})

// new bitcoin key
var btcKey = Keys.Bitcoin.gen({
  networkName: 'bitcoin'
})

// new dsa key
var dsaKey = Keys.DSA.gen()

// keys with metadata
btcKey = Keys.Bitcoin.gen({
  networkName: 'testnet',
  // arbitrary metadata
  label: 'most excellent key',
  purpose: 'messaging'
})

```

## sync API (may not be supported for some keys)

```js
var sig = ecKey.signSync('hey ho') 
var verified = ecKey.verifySync('hey ho', sig)
```

## async API (supported for all keys)

```js
ecKey.sign('hey ho', function (err, sig) {
  // async is supported for all
  ecKey.verify('hey ho', function (err, verified) {
    // verified is a boolean
  })
})
```

## export

```js
var pub = ecKey.exportPublic()
var priv = ecKey.exportPrivate()
```

### pub

```json
{
  "curve": "ed25519",
  "fingerprint": "de26dffa5dc9e3866ea23d9120578b768b945b1385d8393d275d715470dd6056",
  "type": "ec",
  "value": "022ee9fefd1b275d4ee1e7c41157cd4753ad4cbd0cbfdc76eef85ebae230bf27ee",
  // whatever metadata you added
  "purpose": "sign",
  "label": "one key to rule them all"
}
```

### priv

```json
{
  "curve": "ed25519",
  "fingerprint": "de26dffa5dc9e3866ea23d9120578b768b945b1385d8393d275d715470dd6056",
  "priv": "01762d59097688a1f1cd241aadee4cb1bd3d37017f71501b28e85ecdab5349c2",
  "type": "ec",
  "value": "022ee9fefd1b275d4ee1e7c41157cd4753ad4cbd0cbfdc76eef85ebae230bf27ee",
  // whatever metadata you added
  "purpose": "sign",
  "label": "one key to rule them all"
}
```

## import

```js
// recover to typed instance (ECKey/DSAKey/etc.)
var ecKey = kiki.toKey(pub || priv) 
```

## Key API

### (static) gen(options)

Generate a new key. Different keys may have different required properties (this asymmetry can't be avoided.)

### hasDeterministicSig()

Some keys have deterministic signatures - same outputs for the same inputs. Some don't.

### parsePub(pubKeyString)

### parsePriv(privKeyString)

### fingerprint()

### pubKeyString()

### exportPublic()

### exportPrivate()

## mock "secure element" API

Simple mock for a "secure element" type API, where you don't have access to the private keys. Give it a public key, an operation and data, and it will perform signing, decrypting, etc.

```js
var kiki = require('kiki').kiki
var secureEl = kiki(privKeys) // setup the mock secure element
secureEl.sign(pubKey, msg, callback)
secureEl.ecdh(ecPubKey1, ecPubKey2, callback)
```
