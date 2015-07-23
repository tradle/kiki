# kiki

Wrappers for DSA, EC, Bitcoin and other keys to provide a common API for signing/verifying/importing/exporting

_this module is used by [Tradle](https://github.com/tradle/about/wiki)_

## Usage

```js
var kiki = require('kiki');
var Keys = kiki.Keys

var ecKey = Keys.EC.gen({
  purpose: 'sign'
})

var btcKey = Keys.Bitcoin.gen({
  purpose: 'payment',
  networkName: 'bitcoin',
  label: 'most excellent key'
})

var dsaKey = Keys.DSA.gen({
  purpose: 'payment',
  label: 'OTR master key'
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

#### pub

```json
{
  "curve": "ed25519",
  "fingerprint": "de26dffa5dc9e3866ea23d9120578b768b945b1385d8393d275d715470dd6056",
  "purpose": "encrypt",
  "type": "ec",
  "value": "022ee9fefd1b275d4ee1e7c41157cd4753ad4cbd0cbfdc76eef85ebae230bf27ee"
}
```

#### priv

```json
{
  "curve": "ed25519",
  "fingerprint": "de26dffa5dc9e3866ea23d9120578b768b945b1385d8393d275d715470dd6056",
  "priv": "01762d59097688a1f1cd241aadee4cb1bd3d37017f71501b28e85ecdab5349c2",
  "purpose": "encrypt",
  "type": "ec",
  "value": "022ee9fefd1b275d4ee1e7c41157cd4753ad4cbd0cbfdc76eef85ebae230bf27ee"
}
```

## import

```js
// recover to typed instance (ECKey/DSAKey/etc.)
var ecKey = kiki.toKey(pub || priv) 
```
