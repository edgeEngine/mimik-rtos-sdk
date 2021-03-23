const fs = require('fs');
const https = require('https');
const express = require('express');

const app = express();

const SERVER_KEY_PATH = '../test-data/server-key.pem';
const SERVER_CERTIFICATE_PATH = '../test-data/server-crt.pem';
const CA_CERTIFICATE_PATH = '../test-data/ca-crt.pem';
const RESPONSE_JSON_PATH = 'response.json';

const options = {
  key: fs.readFileSync(SERVER_KEY_PATH),
  cert: fs.readFileSync(SERVER_CERTIFICATE_PATH),
  ca: fs.readFileSync(CA_CERTIFICATE_PATH),
  requestCert: true,
  rejectUnauthorized: false,
};

app.get('/tenants/me/services', (req, res) => {
  const crt = req.socket.getPeerCertificate();
  console.log(crt);
  if (!req.client.authorized) {
    return res.status(401).send('Invalid client certificate authentication.');
  }

  const txt = fs.readFileSync(RESPONSE_JSON_PATH);
  const obj = JSON.parse(txt);
  return res.send(JSON.stringify(obj, null, 2));
});

function callback(req, res) { 
  const crt = req.socket.getPeerCertificate();
  if (crt) {
    const { subject } = crt;
   
    console.log(new Date() + ' ' + 
      req.connection.remoteAddress + ' ' + 
      (subject ? subject.CN : '') + ' ' + 
      req.method + ' ' + req.url);
  }
  
  res.writeHead(200); 
  res.end("hello world\n"); 
}

https.createServer(options, app).listen(4433,"0.0.0.0");
//https.createServer(options, app).listen(4433);
