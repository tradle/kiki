# kiki

Wrappers for DSA, EC, Bitcoin and other keys to provide a common API for signing/verifying/importing/exporting

_this module is used by [Tradle](https://github.com/tradle/about/wiki)_

## Usage

```js
var kiki = require('kiki');
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

var sig = ecKey.signSync('hey ho') // sync ops may not be supported
ecKey.sign('hey ho', function (err, sig) {
  // async is supported for all
})
```

### sign/verify

```js
var kiki = require('kiki');
var ecKey = Keys.EC.gen({
  purpose: 'sign'
})

```
