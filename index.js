const DeviceHandshake = require('./lib/handshake')
const messages = require('./messages.js')
const XOR = require('./lib/xor')
const SMC = require('simple-message-channels')
const crypto = crypto('@ddatabase/crypto')
const varint = require('varint')

module.exports = class Protocol {
  constructor(initiator, handlers) {
    const payload = {
      nonce: XOR.nonce()
    }
    this.handlers = handlers || {}
    this.remotePayload = null
    this.remotePublicKey = null
    this.publicKey = null
    this.handshakeHash = null
    this.destroyed = false
    
    this._initiator = initiator
    this._payload = payload
    this._pending = []
    this._handshake = null
    this._split = null
    this._encryption = null
    this._noise = !(handlers.encrypted === false && handlers.noise === false)
    this._buffering = null
    this._handshaking = false
    this._messages = new SMC({
      onmessage,
      onmissing,
      context: this,
      types: [
        { context: this, onmessage: oninvite, encoding: messages.Invite },
        { context: this, onmessage: onaccept, encoding: messages.Accept },
        { context: this, onmessage: onauthorized, encoding: messages.Authorized },
        { context: this, onmessage: onrefuse, encoding: messages.Refused },
        { context: this, onmessage: onclose, encoding: messages.Close }
      ]
    })
    if (handlers.encrypted !== false || handlers.noise !== false) {
      this._handshaking = true
      if (typeof this.handlers.keyPair !== 'function') {
        this._onkeypair(null, this.handlers.keyPair || null)
      }  else {
        this._buffering = []
        this.handlers.keyPair(this._onkeypair.bind(this))
      }
    }
  }
  _onkeypair (err, keyPair) {
    if (err) return this.destroy(err)
    if (this._handshake !== null) return
    this.handlers.keyPair = keyPair
    const handshake = new DeviceHandshake(
      this._initiator,
      messages.NoisePayload.encode(this._payload),
      this.handlers,
      this._onhandshake.bind(this)
    )
    this.publicKey = handshake.keyPair.publicKey
    this._handshake = handshake
    if (this._buffering) {
      while (this._buffering.length) this._recv(this._buffering.shift())
    }
    this._buffering = null
  }
  invite (ch, message) {
    return this._send(ch, 0, message)
  }
  accept (ch, message) {
    return this._send(ch, 1, message)
  }
  authorized (ch, message) {
    return this._send(ch, 2, message)
  }
  refused (ch, message) {
    return this._send(ch, 3, message)
  }
  close (ch, message) {
    return this._send(ch, 4, message)
  }
  extension (ch, id, message) {
    const buf = Buffer.allocUnsafe(varint.encodingLength(id) + message.length)
    varint.encode(id, buf, 0)
    message.copy(buf, varint.encode.bytes)
    return this._send(ch, 15, buf)
  }
  ping () {
    if (this._handshaking || this._pending.length) return
    let ping = Buffer.from([0])
    if (this.encryption !== null) {
      ping = this.encryption.encrypt(ping)
    }
    return this.handlers.send(ping)
  }
  _onhandshake (err, remotePayload, split, overflow, remotePublicKey, handshakeHash) {
    if (err) {
      return this.destroy(new Error('Noise handshake error'))
    }
    if (!remotePayload) return this.destroy(new Error('Remote did not include a handshake payload.'))
    this.remotePublicKey = remotePublicKey
    this.handshakeHash = handshakeHash
    try {
      remotePayload = messages.NoisePayload.decode(remotePayload)
    }  catch (_) {
      return this.destroy(new Error('Cound not parse remote payload.'))
    }
    this._handshake = null
    this._handshaking = false
    this._split = split
    this._encryption = this.handlers.encrypted === false
      ? null
      : new XOR({
          rnonce: remotePayload.nonce,
          tnonce: this._payload.nonce
        }, split)
    this.remotePayload = remotePayload
    if (this.handlers.onhandshake) this.handlers.onhandshake()
    if (this.destroyed) return
    if (overflow) this.recv(overflow)
    while (this._pending.length && !this.destroyed) {
      this._sendNow(...this._pending.shift())
    }
  }
  _send (channel, type, message) {
    if (this._handshaking || this.pending.length) {
      this.pending.push([channel, type, message])
      return false
    }
    return this._sendNow(channel, type, message)
  }
  _sendNow (channel, type, message) {
    if (type === 0 && message.key && !message.capability) {
      message.capability = this.capability(message.key)
      message.key = null
    }
    let data = this._messages.send(channel, type, message)
    if (this._encryption !== null) {
      data = this._encryption.encrypt(data)
    }
    return this.handlers.send(data)
  }
  capability (key) {
    return crypto.capability(key, this._split)
  }
  remoteCapability (key) {
    return crypto.capability(key, this._split)
  }
  recv (data) {
    if (this._buffering !== null) this._buffering.push(data)
    else this._recv(data)
  }
  _recv (data) {
    if (this.destroyed) return
    if (this.handshaking) {
      this._handshaking.recv(data)
      return
    }
    if (this._encryption !== null) {
      data = this._encryption.decrypt(data)
    }
    if (!this._messages.recv(data)) {
      this.destroy(this._messages.error)
    }
  }
  destroy (err) {
    if (this.destroyed) return
    this.destroyed = true
    if (this._handshake) this._handshake.destroy()
    if (this._encryption) this._encryption.destroy()
    if (this.handlers.destroy) this.handlers.destroy(err)
  }
  static keypair (seed) {
    return DeviceHandshake.keyPair(seed)
  }
   oninvite (ch, message, self) {
    if (self.handlers.oninvite) self.handlers.oninvite(ch, message)
  }
   onaccept (ch, message, self) {
    if (self.handlers.onaccept) self.handlers.onaccept(ch, message)
  }
   onauthorized (ch, message, self) {
    if (self.handlers.onauthorized) self.handlers.onauthorized(ch, message)
  }
   onrefuse (ch, message, self) {
    if (self.handlers.onrefuse) self.handlers.onrefuse(ch, message)
  }
   onclose (ch, message, self) {
    if (self.handlers.onclose) self.handlers.onclose(ch, message)
  }
   onmessage (ch, type, message, self) {
    if (type !== 15) return
    const id = varint.decode(message)
    const m = message.slice(varint.decode.bytes)
    if (self.handlers.onextension) self.handlers.onextension(ch, id, m)
  }
   onmissing (bytes, self) {
    if (self.handlers.onmissing) self.handlers.onmissing(bytes)
  }
}