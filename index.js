
const hdkey = require('hdkey')
const bip39 = require('bip39')
const secp256k1 = require('secp256k1')
const secrets = require('secrets.js-grempe')
const eccrypto = require('eccrypto')
const crypto = require('crypto')

// generates device local key, ideally in security chip
let deviceLocalPrivKey
do {
  deviceLocalPrivKey = crypto.randomBytes(32)
} while (!secp256k1.privateKeyVerify(deviceLocalPrivKey))

const deviceLocalPubKey = secp256k1.publicKeyCreate(deviceLocalPrivKey)

console.log("Device local private key (STORE ON DEVICE): " + deviceLocalPrivKey.toString('hex'))
console.log("Device local public key (not shared anywhere): " + deviceLocalPubKey.toString('hex'))

// generates device auth key, ideally in security chip

let deviceLocalAuthPrivKey
do {
  deviceLocalAuthPrivKey = crypto.randomBytes(32)
} while (!secp256k1.privateKeyVerify(deviceLocalAuthPrivKey))

const deviceLocalAuthPubKey = secp256k1.publicKeyCreate(deviceLocalAuthPrivKey)

console.log("Device local auth private key (STORE ON DEVICE): " + deviceLocalAuthPrivKey.toString('hex'))
console.log("Device local auth public key (sent to ForgetMe server): " + deviceLocalAuthPubKey.toString('hex'))

// generates mnemonic
var mnemonic = bip39.generateMnemonic()

console.log("Mnemonic: " + mnemonic)

// splits mnemonic into two, m_1 and m_2
var mnemonicShares = secrets.share(secrets.str2hex(mnemonic), 2, 2)
var m_1 = mnemonicShares[0]
var m_2 = mnemonicShares[1]

console.log("m_1: " + m_1)
console.log("m_2: " + m_2)

// encrypt m_1 with device local public key
eccrypto.encrypt(secp256k1.publicKeyConvert(deviceLocalPubKey, false), Buffer.from(secrets.str2hex(m_1), 'hex')).then(function(response) {
  console.log("e_DLPubKey(m_1): response (store on device): " + JSON.stringify(response))
  
  // check if it decrypts too with device local private key
  eccrypto.decrypt(deviceLocalPrivKey, response).then(function(plaintext) {
    console.log("d_DLPrivKey(above): " + secrets.hex2str(plaintext.toString('hex')))
    console.log("encrypted equals decrypted: " + (secrets.hex2str(plaintext.toString('hex')) === m_1))
  })
})

// encrypt m_2 with device local public key
eccrypto.encrypt(secp256k1.publicKeyConvert(deviceLocalPubKey, false), Buffer.from(secrets.str2hex(m_2), 'hex')).then(function(response) {
  console.log("e_DLPubKey(m_2): response (store on ForgetMe): " + JSON.stringify(response))
  eccrypto.decrypt(deviceLocalPrivKey, response).then(function(plaintext) {
    console.log("d_DLPrivKey(above): " + secrets.hex2str(plaintext.toString('hex')))
    console.log("encrypted equals decrypted: " + (secrets.hex2str(plaintext.toString('hex')) === m_2))
  })
})

// generate device revoke key for this device, it's the first one; we don't need to keep it?
var deviceRevokeSeed = bip39.mnemonicToSeed(mnemonic, 'device:initial')
// XXX fixme use versions specific for this purpose, see 'coininfo'
var deviceRevokeHDKey = hdkey.fromMasterSeed(deviceRevokeSeed).derive('m/0/0')
var deviceRevokePubKey = deviceRevokeHDKey.publicKey

console.log("device revoke pub key (set as auth key w/ forgetme): " + deviceRevokePubKey.toString('hex'))

// sign a nonce that forget me server gave us in order to authenticate us (and get us e_DLPubKey(m_2)
var nonce = crypto.randomBytes(32)
var hash = crypto.createHash('sha256').update(nonce).digest()
var sig = secp256k1.sign(hash, deviceRevokeHDKey.privateKey)

// forget me server-side check of signature / recovery of pubkey
console.log("signature of nonce done with device revoke pub key: " + JSON.stringify(sig))
console.log("who signed it? " + secp256k1.recover(hash, sig.signature, sig.recovery).toString('hex'))
console.log("does signature match? " + secp256k1.verify(hash, sig.signature, secp256k1.recover(hash, sig.signature, sig.recovery)))
