var types = require('./keys')
var Key = require('./keys/key')

module.exports = function toKey (key, gen) {
  if (key instanceof Key) return key

  var cl

  for (var p in types) {
    var KeyCl = types[p]
    if (KeyCl.type === key.type) {
      cl = KeyCl
      break
    }
  }

  if (!cl) {
    throw new Error('unrecognized key type: ' + key.type)
  }

  return gen ? KeyCl.gen(key) : new KeyCl(key)
}
