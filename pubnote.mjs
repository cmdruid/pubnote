/* Imports */

import WebSocket     from 'ws'
import { parseArgs } from '@pkgjs/parseargs'
import { schnorr }   from '@noble/secp256k1'
import { webcrypto as crypto } from 'node:crypto'

const DEFAULT_RELAY   = 'relay.nostrich.de',
      DEFAULT_TIMEOUT = 500

// Define our base64 encoders.
const b64encode = (bytes) => btoa(bytesToHex(bytes)).replace('+', '-').replace('/', '_')
const b64decode = (str) => hexToBytes(atob(str.replace('-', '+').replace('_', '/')))

// Define our text encoders.
const ec = new TextEncoder()
const dc = new TextDecoder()

// Emitter Library

// Default options to use.
const DEFAULTS = {
  filter  : { since : Math.floor(Date.now() / 1000) },
  kind    : 29001,  // Default event type.
  tags    : [],     // Global tags for events.
  selfsub : false,  // React to self-published events.
  silent  : false,  // Silence noisy output.
  timeout : 500,    // Timeout for network events.
  verbose : false,  // Show verbose log output.
}

class NostrEmitter {
  constructor(opt = {}) {
    const { filter, ...options } = { ...DEFAULTS, ...opt }
    this.subscribed = false
    this.events     = {}
    this.tags       = []
    this.subId      = getRandomHex(16)
    this.privkey    = options.privkey || getRandomHex(32)
    this.opt        = options
    this.filter     = { kinds: [ this.opt.kind ], ...opt.filter }
    this.log        = (...s) => (opt.log)     ? opt.log(...s) : console.log(...s)
    this.info       = (...s) => (opt.silent)  ? null : this.log(...s)
    this.debug      = (...s) => (opt.verbose) ? this.log(...s) : null
  }

  get connected () {
    return this.socket?.readyState === 1
  }

  async importSeed(string) {
    /** Import private key from a seed phrase. */
    this.privkey = await Hash.from(string).toBytes()
  }

  async subscribe() {
    /** Send a subscription message to the socket peer. */
    const subscription = ['REQ', this.subId, this.filter]
    this.socket.send(JSON.stringify(subscription))
    this.debug('Subscribed with filter:', this.filter)
  }

  async connect(address, secret) {
    /** Connect our emitter to a relay and topic. */
    if (address) {
      if (address.includes('://')) {
        address = address.split('://')[1]
      }
      this.address = address
    }
    
    if (secret) this.secret = await sha256(secret)

    if (this.address === undefined) {
      throw new Error('Must provide a valid relay address!')
    }

    if (this.secret === undefined) {
      throw new Error('Must provide a shared secret!')
    }

    if (address !== undefined || this.socket.readyState > 1) {
      this.socket = new WebSocket('wss://' + this.address)

      // Setup our main socket event listeners.
      this.socket.addEventListener('open', (event) => this.openHandler(event))
      this.socket.addEventListener('message', (event) => this.messageHandler(event))

      // Calculate our pubkey and topic.
      this.pubkey = schnorr.getPublicKey(this.privkey, true)
      this.topic  = bytesToHex(await sha256(this.secret, 2))

      if (typeof this.pubkey !== 'string') {
        // If the pubkey is not a string, convert it.
        this.pubkey = bytesToHex(this.pubkey)
      }
      
      // Configure our event tags and filter.
      this.tags.push([ 'h', this.topic ])
      this.filter['#h'] = [ this.topic ]
    }

    if (this.connected && this.subscribed) return

    // Return a promise that includes a timeout.
    return new Promise((res, rej) => {
      let count = 0, retries = 10
      let interval = setInterval(() => {
        if (this.connected && this.subscribed) {
          res(clearInterval(interval))
        } else if (count > retries) {
          this.info('Failed to connect!')
          rej(clearInterval(interval))
        } else { count++ }
      }, this.opt.timeout)
    })
  }

  normalizeEvent(event) {
    /** Normalize the format of an incoming event. */
    return event instanceof Uint8Array
      ? JSON.parse(event.toString('utf8'))
      : JSON.parse(event.data)
  }

  async decryptContent(content) {
    /** Decrypt content of a message. */
    return decrypt(content, this.secret)
      .then((data) => JSON.parse(data))
      .catch((err) => console.error(err))
  }

  async openHandler(_event) {
    /** Handle the socket open event. */
    this.info('Socket connected to: ', this.address)
    this.subscribe()
  }

  messageHandler(event) {
    /** Handle the socket message event. */
    const [ type, subId, data ] = this.normalizeEvent(event)

    this.debug('messageEvent:', [ type, subId, data ])

    if (type === 'EOSE') {
      // If an EOSE message, mark subscription as active.
      this.subscribed = true
      this.info('Subscription Id:', this.subId)
      return
    }

    if (type === 'EVENT') {
      // If an EVENT message, pass to event handler.
      this.eventHandler(data)
      return
    }
  }

  async eventHandler(data) {
    const { content, ...metaData } = data
    const { id, pubkey, sig } = metaData

    if (!schnorr.verify(sig, id, pubkey)) {
       // Verify that the signature is valid.
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
        tags: [[ 'e', metaData.id ]]
      })
    }

    // Unpack the decrypted content.
    const [ eventName, eventData ] = decryptedContent

    // Emit the event to our subscribed functions.
    this.emit(eventName, eventData, { eventName, ...metaData })
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
    if (!this.connected) await this.connect()
    this.socket.send(JSON.stringify(['EVENT', signedEvent]))
  }

  async getSignedEvent(event) {
    /** Create a has and signature for our 
     *  event, then return it with the event.
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
    event.id  = bytesToHex(await sha256(eventData))
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

  _getFn(eventName) {
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
    this._getFn(eventName).add(fn)
  }

  once(eventName, fn) {
    /** Subscribe function to run once, using
     *  a callback to cancel the subscription.
     * */

    const onceFn = (...args) => {
      this.remove(eventName, onceFn)
      fn.apply(this, args)
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

  emit(eventName, ...args) {
    /** Emit a series of arguments for the event, and
     *  present them to each subscriber in the list.
     * */
    const fns = [ ...this._getFn('*'), ...this._getFn(eventName) ]

    for (const fn of fns) {
      fn.apply(this, args)
    }
  }

  publish(eventName, args, eventMsg) {
    /** Emit a series of arguments for the event, and
     *  present them to each subscriber in the list.
     * */
    this.send(eventName, args, eventMsg)
  }

  remove(eventName, fn) {
    /** Remove function from an event's subscribtion list. */
    this._getFn(eventName).delete(fn)
  }

  close() {
    return new Promise(res => {
      setTimeout(() => {
        this.socket.close()
        this.subscribed = false
        this.emit('close', this.subId)
        res()
      }, this.opt.timeout)
    })
  }
}

/** Crypto library. */

async function sha256(data) {
  if (typeof data === 'string') data = ec.encode(data)
  const digest = await crypto.subtle.digest('SHA-256', data)
  return new Uint8Array(digest)
}

async function getCryptoKey (string) {
  /** Derive a CryptoKey object (for Webcrypto library). */
  const secret  = await sha256(string)
  const options = { name: 'AES-CBC' }
  const usage   = ['encrypt', 'decrypt']
  return crypto.subtle.importKey('raw', secret, options, true, usage)
}

async function encrypt (message, secret) {
  /** Encrypt a message using a CryptoKey object. */
  const key = await getCryptoKey(secret)
  const iv  = crypto.getRandomValues(new Uint8Array(16))
  const cipherBytes = await crypto.subtle
    .encrypt({ name: 'AES-CBC', iv }, key, ec.encode(message))
    .then((bytes) => new Uint8Array(bytes))
  // Return a concatenated and base64 encoded array.
  return b64encode(new Uint8Array([...iv, ...cipherBytes]))
}

async function decrypt (encodedText, secret) {
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

function bytesToHex (byteArray) {
  const arr = []; let i
  for (i = 0; i < byteArray.length; i++) {
    arr.push(byteArray[i].toString(16).padStart(2, '0'))
  }
  return arr.join('')
}

function hexToBytes (str) {
  const arr = []; let i
  for (i = 0; i < str.length; i += 2) {
    arr.push(parseInt(str.substr(i, 2), 16))
  }
  return Uint8Array.from(arr)
}

function getRandomBytes (size = 32) {
  return crypto.getRandomValues(new Uint8Array(size))
}

function getRandomHex (size = 32) {
  return bytesToHex(getRandomBytes(size))
}

const usage = `
Send encrypted notes between terminals, from anywhere to anywhere, using the power of nostr.

Usage: 
  Machine A: pubnote -p 'secretphrase' recv
  Machine B: pubnote -p 'secretphrase' send "whatever" "you" "want"

Options:
  --key     -k privkey  : Specify a 32 byte private key to use for signatures.
                          Must provide in string hex format.

  --pass    -p password : Specify the secret passphrase to use. The secret is
                          hashed and used for end-to-end routing and encryption.
  --relay   -r address  : Set the relay to use. Default relay is currently set
                          to ${DEFAULT_RELAY}
  
  --silent  -s          : Enable silent output (for better use in scripts).

  --timeout -t          : Time to keep connection open (in milliseconds).
                          Default is ${DEFAULT_TIMEOUT}ms.
  
  --verbose -v          : Enable verbose debug output.  
`

const options = {
  'key'     : { type: 'string',  short: 'k' },
  'pass'    : { type: 'string',  short: 'p' },
  'relay'   : { type: 'string',  short: 'r' },
  'silent'  : { type: 'boolean', short: 's' },
  'timeout' : { type: 'string',  short: 't' },
  'verbose' : { type: 'boolean', short: 'v' },
}

const config = { options, args: process.argv.slice(2), allowPositionals: true }
const { values: opt, positionals: arg } = parseArgs(config)

if (opt.timeout) opt.timeout = Number(opt.timeout)
if (opt.verbose) console.log('Configuration:', opt ?? '{}', arg)

async function main() {
  let relay  = opt.relay || 'relay.nostrich.de',
      secret = opt.pass  || b64encode(getRandomBytes(6))

  if (relay === undefined || secret === undefined) {
    console.log('Invalid arguments!')
    exit(1)
  }

  const emitter = new NostrEmitter({ 
    prvkey  : opt.key,
    silent  : !opt.verbose,
    timeout : opt.timeout || DEFAULT_TIMEOUT,
    verbose : opt.verbose || false
  })

  try {
    switch (arg[0]) {
      case 'recv':
        emitter.on('send', (content, meta) => {
          if (!opt.silent) console.log(`From [${meta.pubkey.slice(0, 6)}]:`)
          console.log(content)
          emitter.close()
          process.exit()
        })
        await emitter.connect(relay, secret)
        if (opt.pass === undefined) console.log('Using pass:', secret)
        if (!opt.silent) console.log('Listening for notes ...\n')
        break
      case 'send':
        if (opt.pass === undefined) throw 'Missing a passphrase!'
        await emitter.connect(relay, secret)
        emitter.publish('send', arg.slice(1).join(' '))
        if (!opt.silent) console.log(`Note sent as [${emitter.pubkey.slice(0, 6)}].`)
        await emitter.close()
        process.exit()
      default:
        console.log(usage)
    }
  } catch(err) {
    console.log(err)
    process.exit(1)
  }
}

main()
