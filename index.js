const vapUtil = require('vaporyjs-util')
const vapAbi = require('vaporyjs-abi')

module.exports = {

  concatSig: function (v, r, s) {
    const rSig = vapUtil.fromSigned(r)
    const sSig = vapUtil.fromSigned(s)
    const vSig = vapUtil.bufferToInt(v)
    const rStr = padWithZeroes(vapUtil.toUnsigned(rSig).toString('hex'), 64)
    const sStr = padWithZeroes(vapUtil.toUnsigned(sSig).toString('hex'), 64)
    const vStr = vapUtil.stripHexPrefix(vapUtil.intToHex(vSig))
    return vapUtil.addHexPrefix(rStr.concat(sStr, vStr)).toString('hex')
  },

  normalize: function (input) {
    if (!input) return

    if (typeof input === 'number') {
      const buffer = vapUtil.toBuffer(input)
      input = vapUtil.bufferToHex(buffer)
    }

    if (typeof input !== 'string') {
      var msg = 'vap-sig-util.normalize() requires hex string or integer input.'
      msg += ' received ' + (typeof input) + ': ' + input
      throw new Error(msg)
    }

    return vapUtil.addHexPrefix(input.toLowerCase())
  },

  personalSign: function (privateKey, msgParams) {
    var message = vapUtil.toBuffer(msgParams.data)
    var msgHash = vapUtil.hashPersonalMessage(message)
    var sig = vapUtil.ecsign(msgHash, privateKey)
    var serialized = vapUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
    return serialized
  },

  recoverPersonalSignature: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    const sender = vapUtil.publicToAddress(publicKey)
    const senderHex = vapUtil.bufferToHex(sender)
    return senderHex
  },

  extractPublicKey: function (msgParams) {
    const publicKey = getPublicKeyFor(msgParams)
    return '0x' + publicKey.toString('hex')
  },

  typedSignatureHash: function (typedData) {
    const hashBuffer = typedSignatureHash(typedData)
    return vapUtil.bufferToHex(hashBuffer)
  },

  signTypedData: function (privateKey, msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const sig = vapUtil.ecsign(msgHash, privateKey)
    return vapUtil.bufferToHex(this.concatSig(sig.v, sig.r, sig.s))
  },

  recoverTypedSignature: function (msgParams) {
    const msgHash = typedSignatureHash(msgParams.data)
    const publicKey = recoverPublicKey(msgHash, msgParams.sig)
    const sender = vapUtil.publicToAddress(publicKey)
    return vapUtil.bufferToHex(sender)
  }

}

/**
 * @param typedData - Array of data along with types, as per EIP712.
 * @returns Buffer
 */
function typedSignatureHash(typedData) {
  const error = new Error('Expect argument to be non-empty array')
  if (typeof typedData !== 'object' || !typedData.length) throw error

  const data = typedData.map(function (e) {
    return e.type === 'bytes' ? vapUtil.toBuffer(e.value) : e.value
  })
  const types = typedData.map(function (e) { return e.type })
  const schema = typedData.map(function (e) {
    if (!e.name) throw error
    return e.type + ' ' + e.name
  })

  return vapAbi.soliditySHA3(
    ['bytes32', 'bytes32'],
    [
      vapAbi.soliditySHA3(new Array(typedData.length).fill('string'), schema),
      vapAbi.soliditySHA3(types, data)
    ]
  )
}

function recoverPublicKey(hash, sig) {
  const signature = vapUtil.toBuffer(sig)
  const sigParams = vapUtil.fromRpcSig(signature)
  return vapUtil.ecrecover(hash, sigParams.v, sigParams.r, sigParams.s)
}

function getPublicKeyFor (msgParams) {
  const message = vapUtil.toBuffer(msgParams.data)
  const msgHash = vapUtil.hashPersonalMessage(message)
  return recoverPublicKey(msgHash, msgParams.sig)
}


function padWithZeroes (number, length) {
  var myString = '' + number
  while (myString.length < length) {
    myString = '0' + myString
  }
  return myString
}
