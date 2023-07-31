const crypto = require('crypto')
const { magenta, blue, green, red } = require('colorette')
const { EventEmitter } = require('eventemitter3')
const WebSocket = require('ws')

const COMMON_FETCH = {
  headers: {
    'accept-language': 'en-US,en;q=0.8',
    'cache-control': 'no-cache',
    'Content-Type': 'application/json',
    'pragma': 'no-cache',
    'referer': 'https://discord.com/login',
    'sec-fetch-dest': 'empty',
    'sec-fetch-mode': 'cors',
    'sec-fetch-site': 'same-origin',
    'sec-gpc': 1,
    'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36'
  },
  referrer: 'https://discord.com/login',
}

class RemoteAuthClient extends EventEmitter {
  constructor(options) {
    super()
    options = Object.assign({
      debug: false
    }, options)
    this.debug = options.debug
    this.intervals = []
    this.keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength: 2048,
      e: 0x010001
    })
    this.canceled = false
    this._ping = null
    this._lastHeartbeat = null
    this._pendingCaptcha = null
  }
  log(info) {
    console.log(magenta('[RemoteAuthClient]'), info)
  }
  connect() {
    this.ws = new WebSocket('wss://remote-auth-gateway.discord.gg/?v=2', {
      headers: {
        'Origin': 'https://discord.com'
      }
    })
    this.ws.onmessage = message => {
      if (this.debug) this.log(blue(`<- ${message.data}}`))
      try {
        this.onMessage(JSON.parse(message.data))
      } catch (error) {
        if (this.debug) this.log(red(error.message))
        else throw error
      }
    }
    this.ws.onclose = () => {
      if (this.debug) this.log(red('DISCONNECTED'))
      this.intervals.forEach(x => clearInterval(x))
      this.emit('close')
    }
  }
  disconnect() {
    if (this.ws.readyState === WebSocket.OPEN) this.ws.close()
  }
  send(data) {
    const dataStr = JSON.stringify(data)
    if (this.debug) this.log(green(`-> ${dataStr}`))
    this.ws.send(dataStr)
  }
  sendHeartbeat() {
    this._lastHeartbeat = Date.now()
    this.send({ op: 'heartbeat' })
  }
  decryptPayload(payload) {
    return crypto.privateDecrypt({
      oaepHash: 'sha256',
      key: this.keyPair.privateKey
    }, Buffer.from(payload, 'base64'))
  }
  onMessage(p) {
    switch (p.op) {
      case 'hello':
        const encodedPublicKey = this.keyPair.publicKey.export({
          type: 'spki',
          format: 'pem'
        }).trim().split('\n').slice(1, -1).join('')
        this.intervals.push(setInterval(this.sendHeartbeat.bind(this), p.heartbeat_interval))
        this.send({
          op: 'init',
          encoded_public_key: encodedPublicKey
        })
        break
      case 'nonce_proof':
        const decryptedNonce = this.decryptPayload(p.encrypted_nonce)
        const nonceHash = crypto.createHash('sha256')
        nonceHash.update(decryptedNonce)
        this.send({
          op: 'nonce_proof',
          proof: nonceHash.digest('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
        })
        break
      case 'pending_remote_init':
        this.emit('pendingRemoteInit', p.fingerprint)
        break
      case 'pending_ticket':
        const decryptedUser = this.decryptPayload(p.encrypted_user_payload)
        const userData = decryptedUser.toString().split(':')
        this.emit('pendingFinish', {
          id: userData[0],
          discriminator: userData[1],
          avatar: userData[2],
          username: userData[3]
        })
        break
      case 'pending_login':
        const fetch = globalThis.fetch || require('node-fetch')

        const headers = { ...COMMON_FETCH.headers }
        if (this._pendingCaptcha?.service === 'hcaptcha') {
          headers['x-captcha-key'] = this._pendingCaptcha.data.key
          headers['x-captcha-rqtoken'] = this._pendingCaptcha.data.rqtoken
        }

        fetch('https://discord.com/api/v9/users/@me/remote-auth/login', {
          body: JSON.stringify({ ticket: p.ticket }),
          method: 'POST',
          referrer: COMMON_FETCH.referrer,
          headers,
        }).then(async response => {
          const data = await response.json()

          if (response.status === 200) {
            this._pendingCaptcha = null
            const decryptedToken = this.decryptPayload(data.encrypted_token).toString()
            this.emit('finish', decryptedToken)
          } if (response.status === 400 && ['captcha-required', 'invalid-response'].includes(data.captcha_key?.[0])) {
            switch (data.captcha_service) {
              case 'hcaptcha':
                if (this._pendingCaptcha) {
                  this._pendingCaptcha.data.key = null
                  this._pendingCaptcha.retries++
                  this._pendingCaptcha.data.rqtoken = data.captcha_rqtoken
                } else {
                  this._pendingCaptcha = {
                    ticket: p.ticket,
                    service: 'hcaptcha',
                    retries: 0,
                    data: {
                      key: null,
                      rqtoken: data.captcha_rqtoken,
                    },
                  }
                }
                this.emit('hcaptcha', {
                  sitekey: data.captcha_sitekey,
                  rqdata: data.captcha_rqdata,
                  pageurl: 'https://discord.com/login',
                  userAgent: COMMON_FETCH.headers['user-agent'],
                  retries: this._pendingCaptcha.retries,
                })
                break
              default:
                throw new Error(`Unknown captcha service: "${data.captcha_service}"`)
            }
          }
        }).catch(e => {
          new Error('Failed to get token from remote auth', e.toString())
        })
        break
      case 'cancel':
        this.canceled = true
        this.emit('cancel')
        break
      case 'heartbeat_ack':
        this._ping = Date.now() - this._lastHeartbeat
        break
    }
    this.emit('raw', p)
  }
  solveCaptcha(key) {
    if (!this._pendingCaptcha) throw new Error('No captcha pending')
    switch (this._pendingCaptcha.service) {
      case 'hcaptcha':
        this._pendingCaptcha.data.key = key
        this.onMessage({
          op: 'pending_login',
          ticket: this._pendingCaptcha.ticket,
        })
        break
    }
  }
}

module.exports = RemoteAuthClient
