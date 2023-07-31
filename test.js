const { RemoteAuthClient } = require('./')
const https = require('https')
const fs = require('fs')
const Captcha = require("2captcha")

const [, , captchaKey] = process.argv
const solver = new Captcha.Solver(captchaKey)
const client = new RemoteAuthClient({
  debug: true
})

client.on('pendingRemoteInit', fingerprint => {
  const qrCodeStream = fs.createWriteStream('code.png')
  const data = `https://discord.com/ra/${fingerprint}`
  https.get(`https://kissapi-qrcode.vercel.app/api/qrcode?chs=250x250&chl=${data}`, res => {
    res.pipe(qrCodeStream)
  })
  qrCodeStream.once('close', () => {
    console.log('Scan ./code.png')
  })
})
client.on('pendingFinish', user => {
  fs.unlinkSync('code.png')
  console.log('Incoming User:', user)
})
client.on('hcaptcha', async ({ sitekey, pageurl, rqdata, userAgent, retries }) => {
  console.log('Solving captcha...', retries ? `(${retries} retries)` : '')
  solver.hcaptcha(sitekey, pageurl, {
    data: rqdata,
    userAgent,
  }).then(({ id, data }) => {
    console.log('Solved Captcha (ID: %s)', id)
    client.solveCaptcha(data)
  }).catch(error => {
    console.error(error.message)
    client.disconnect()
  })
})
client.on('finish', token => {
  console.log('Token:', token)
})
client.on('close', () => {
  if (fs.existsSync('code.png')) fs.unlinkSync('code.png')
})

client.connect()
