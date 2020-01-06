const { RemoteAuthClient } = require('./')
const https = require('https')
const fs = require('fs')

const client = new RemoteAuthClient({
  debug: true
})
client.on('pendingRemoteInit', fingerprint => {
  const qrCodeStream = fs.createWriteStream('code.png')
  https.get(`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=https://discordapp.com/ra/${fingerprint}`, (res) => {
    res.pipe(qrCodeStream)
  })
  qrCodeStream.once('close', () => {
    console.log('Scan ./code.png')
  })
})
client.on('pendingFinish', user => {
  console.log('Incoming User:', user)
})
client.on('finish', token => {
  console.log('Token:', token)
})
client.connect()
