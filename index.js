// Detect if we are running in the browser.
const isBrowser = typeof window !== 'undefined'

// Import our required packages.
const { schnorr } = isBrowser ? window.nobleSecp256k1 : require('@noble/secp256k1')
const WebSocket   = isBrowser ? window.WebSocket      : require('ws')
const crypto      = globalThis.crypto

// Specify our base64 encoders.
const b64encode = isBrowser
  ? (bytes) => btoa(bytesToHex(bytes)).replace('+', '-').replace('/', '_')
  : (bytes) => Buffer.from(bytesToHex(bytes)).toString('base64url')

const b64decode = isBrowser
  ? (str) => hexToBytes(atob(str.replace('-', '+').replace('_', '/')))
  : (str) => hexToBytes(Buffer.from(str, 'base64url').toString('utf8'))

// Specify our text encoders.
const ec = new TextEncoder()
const dc = new TextDecoder()

// Default options to use.
const DEFAULT_OPT = {
  filter  : { since : Math.floor(Date.now() / 1000) },
  kind    : 29001,  // Default event type.
  tags    : [],     // Global tags for events.
  selfsub : false,  // React to self-published events.
  silent  : false,  // Silence noisy output.
  verbose : false,  // Show verbose log output.
}

class NostrEmitter {

  constructor(opt = {}) {
    this.connected  = false
    this.subscribed = false
    this.subId      = getRandomHex(16)
    this.events     = {}
    this.tags       = []
    this.privkey    = opt.privkey || getRandomHex(32)
    this.opt        = { ...DEFAULT_OPT, ...opt }
    this.filter     = { kinds: [ this.opt.kind ], ...opt.filter }
    this.log        = (...s) => (opt.log)     ? opt.log(...s) : console.log(...s)
    this.info       = (...s) => (opt.silent)  ? null : this.log(...s)
    this.debug      = (...s) => (opt.verbose) ? this.log(...s) : null
  }

  async importSeed(string) {
    this.privkey = await Hash.from(string).toBytes()
  }

  async subscribe() {
    /** Send a subscription message to the socket peer. */
    const subscription = ['REQ', this.subId, this.filter]
    this.socket.send(JSON.stringify(subscription))
  }

  async connect(address, secret) {
    /** Configure our emitter for connecting to the relay network. */

    // If provided, update the current config.
    this.address = address || this.address
    this.secret  = secret  || this.secret

    if (!this.address) {
      throw new Error('Must provide url to a relay!')
    }

    if (!this.secret) {
      throw new Error('Must provide a shared secret!')
    }

    this.address = (this.address.includes('://'))
      ? this.address
      : 'wss://' + this.address

    this.socket = new WebSocket(this.address)

    // Setup our main socket event listeners.
    this.socket.addEventListener('open', (event) => this.openHandler(event))
    this.socket.addEventListener('message', (event) => this.messageHandler(event))

    this.pubkey = await schnorr.getPublicKey(this.privkey, true)
    this.topic  = await Hash.from(this.secret, 2).toHex(),
    
    // Configure our event tags and filter.
    this.tags.push([ 't', this.topic ])
    this.filter['#t'] = [ this.topic ]

    // Return a promise that includes a timeout.
    return new Promise((res, rej) => {
      let count = 0, retries = 10
      let interval = setInterval(() => {
        if (this.connected && this.subscribed) {
          this.info('Connected and subscribed!')
          res(clearInterval(interval))
        } else if (count > retries) {
          this.info('Failed to connect!')
          rej(clearInterval(interval))
        } else { count++ }
      }, 500)
    })
  }

  async fromLink(string) {
    const decoded = dc.decode(b64decode(string))
    const [ secret, address ] = decoded.split('@')
    return this.connect(address, secret)
  }

  decodeEvent(event) {
    // Decode an incoming event.
    return event instanceof Uint8Array
      ? JSON.parse(event.toString('utf8'))
      : JSON.parse(event.data)
  }

  async decryptContent(content) {
    // Decrypt content of a message.
    return decrypt(content, this.secret)
      .then((data) => JSON.parse(data))
      .catch((err) => console.error(err))
  }

  async openHandler(_event) {
    /** Handle the socket open event. */
    this.info('Socket connected to: ', this.address)
    this.connected = true
    this.subscribe()
  }

  messageHandler(event) {
    /** Handle the socket message event. */
    const [ type, subId, data ] = this.decodeEvent(event)

    this.debug('messageEvent:', [ type, subId, data ])

    // Check if event is a response to a subscription.
    if (type === 'EOSE') {
      this.subscribed = true
      this.info('Subscription Id:', this.subId)
      return
    }

    if (type === 'EVENT') {
      this.eventHandler(data)
      return
    }
  }

  async eventHandler(data) {
    const { content, ...metaData } = data

    // Verify that the signature is valid.
    const { id, pubkey, sig } = metaData

    if (!schnorr.verify(sig, id, pubkey)) {
      throw 'Event signature failed verification!'
    }

    // If the event is from ourselves, 
    if (metaData?.pubkey === this.pubkey) {
      // check the filter rules.
      if (!this.opt.selfsub) return
    }

    // Decrypt the message content.
    const decryptedContent = await this.decryptContent(content)
   
    this.debug('content: ' + JSON.stringify(decryptedContent, null, 2))
    this.debug('metaData: ' + JSON.stringify(metaData, null, 2))

    // If the decrypted content is empty, destroy the event.
    if (!decryptedContent) {
      return this.emit('destroy', null, {
        kind: 5,
        tags: [[ 's', metaData.id ]]
      })
    }

    // Unpack the decrypted content.
    const [ eventName, eventData ] = decryptedContent

    // Apply the event to our subscribed functions.
    for (const fn of this._getEventListByName(eventName)) {
      const args = [ eventData, { eventName, ...metaData }]
      fn.apply(this, args)
    }
  }

  async send(eventName, eventData, eventMsg = { tags: [] }) {
    /** Send a data message to the relay. */
    const serialData = JSON.stringify([ eventName, eventData ])
    
    const event = {
      content    : await encrypt(serialData, this.secret),
      created_at : Math.floor(Date.now() / 1000),
      kind       : eventMsg.kind || this.opt.kind,
      tags       : [...this.tags, ...this.opt.tags, ...eventMsg.tags],
      pubkey     : this.pubkey
    }

    // Sign our message.
    const signedEvent = await this.getSignedEvent(event)

    this.debug('sendEvent:', signedEvent)

    // Serialize and send our message.
    this.socket.send(JSON.stringify(['EVENT', signedEvent]))
  }

  async getSignedEvent(event) {
    /** Produce a signed hash of our event, 
     *  then attach it to the event object.
     * */
    const eventData = JSON.stringify([
      0,
      event['pubkey'],
      event['created_at'],
      event['kind'],
      event['tags'],
      event['content'],
    ])

    // Append event ID and signature
    event.id  = await Hash.from(eventData).toHex()
    event.sig = await schnorr.sign(event.id, this.privkey)

    // Verify that the signature is valid.
    if (!schnorr.verify(event.sig, event.id, event.pubkey)) {
      throw 'event signature failed verification!'
    }

    // If the signature is returned in bytes, convert to hex.
    if (event.sig instanceof Uint8Array) {
      event.sig = bytesToHex(event.sig)
    }

    return event
  }

  _getEventListByName(eventName) {
    /** If key undefined, create a new set for the event,
     *  else return the stored subscriber list.
     * */
    if (typeof this.events[eventName] === 'undefined') {
      this.events[eventName] = new Set()
    }
    return this.events[eventName]
  }

  on(eventName, fn) {
    /** Subscribe function to run on a given event. */
    this._getEventListByName(eventName).add(fn)
  }

  once(eventName, fn) {
    /** Subscribe function to run once, using
     *  a callback to cancel the subscription.
     * */
    const self = this

    const onceFn = function (...args) {
      self.remove(eventName, onceFn)
      fn.apply(self, args)
    }

    this.on(eventName, onceFn)
  }

  within(eventName, fn, timeout) {
    /** Subscribe function to run within a given,
     *  amount of time, then cancel the subscription.
     * */
    const withinFn = (...args) => fn.apply(this, args)
    setTimeout(() => this.remove(eventName, withinFn), timeout)
    
    this.on(eventName, withinFn)
  }

  emit(eventName, args, eventMsg) {
    /** Emit a series of arguments for the event, and
     *  present them to each subscriber in the list.
     * */
    this.send(eventName, args, eventMsg)
  }

  remove(eventName, fn) {
    /** Remove function from an event's subscribtion list. */
    this._getEventListByName(eventName).delete(fn)
  }

  close() {
    this.emit('close', this.id)
    this.socket.close()
    this.connected = false
    this.subscribed = false
  }

  shareLink() {
    const str = `${this.secret}@${this.address}`
    return b64encode(ec.encode(str))
  }
}

/** Crypto library. */

const Hash = class {
  /** Digest a message with sha256, using x number of rounds. */
  static from(data, rounds) {
    if (!(data instanceof Uint8Array)) {
      data = ec.encode(String(data))
    }
    return new Hash(data, rounds)
  }

  constructor(data, rounds = 1) {
    if (!(data instanceof Uint8Array)) {
      throw new Error('Must pass an Uint8Array to new Hash object!')
    }
    this.init   = false
    this.data   = data
    this.rounds = rounds
  }
  
  async digest() {
    if (!this.init) {
      for (let i = 0; i < this.rounds; i++) {
        this.data = await crypto.subtle.digest('SHA-256', this.data)
      }
      this.data = new Uint8Array(this.data)
      this.init = true
    }
  }

  async toHex() {
    await this.digest()
    return bytesToHex(this.data)
  }

  async toBytes() {
    await this.digest()
    return this.data
  }
}

const getCryptoKey = async (string) => {
  /** Derive a CryptoKey object (for Webcrypto library). */
  const secret  = await Hash.from(string).toBytes()
  const options = { name: 'AES-CBC' }
  const usage   = ['encrypt', 'decrypt']
  return crypto.subtle.importKey('raw', secret, options, true, usage)
}

const encrypt = async (message, secret) => {
  /** Encrypt a message using a CryptoKey object. */
  const key = await getCryptoKey(secret)
  const iv  = crypto.getRandomValues(new Uint8Array(16))
  const cipherBytes = await crypto.subtle
    .encrypt({ name: 'AES-CBC', iv }, key, ec.encode(message))
    .then((bytes) => new Uint8Array(bytes))
  // Return a concatenated and base64 encoded array.
  return b64encode(new Uint8Array([...iv, ...cipherBytes]))
}

const decrypt = async (encodedText, secret) => {
  /** Decrypt an encrypted message using a CryptoKey object. */
  const key   = await getCryptoKey(secret)
  const bytes = b64decode(encodedText)
  const plainText = await crypto.subtle.decrypt(
    { name: 'AES-CBC', iv: bytes.slice(0, 16) },
    key,
    bytes.slice(16)
  )
  return dc.decode(plainText)
}

const bytesToHex = (byteArray) => {
  const arr = []; let i
  for (i = 0; i < byteArray.length; i++) {
    arr.push(byteArray[i].toString(16).padStart(2, '0'))
  }
  return arr.join('')
}

const hexToBytes = (str) => {
  const arr = []; let i
  for (i = 0; i < str.length; i += 2) {
    arr.push(parseInt(str.substr(i, 2), 16))
  }
  return Uint8Array.from(arr)
}

const getRandomBytes = (size = 32) => {
  return crypto.getRandomValues(new Uint8Array(size))
}

const getRandomHex = (size = 32) => {
  return bytesToHex(getRandomBytes(size))
}

// Handle exports between browser and node.
if (isBrowser) {
  window.NostrEmitter = NostrEmitter
} else { module.exports = NostrEmitter }