const fs = require('fs');
const https = require('https');
const CLIENT_KEY_PATH = '../test-data/client1-key.pem';
const CLIENT_CERTIFICATE_PATH = '../test-data/client1-crt.pem';
const CA_CERTIFICATE_PATH = '../test-data/ca-crt.pem';

const options = { 
    hostname: 'localhost', 
    port: 4433,
    path: '/tenants/me/services',
    method: 'GET', 
    key: fs.readFileSync(CLIENT_KEY_PATH), 
    cert: fs.readFileSync(CLIENT_CERTIFICATE_PATH), 
    ca: fs.readFileSync(CA_CERTIFICATE_PATH) };

const req = https.request(options, function(res) { 
    res.on('data', function(data) { 
        process.stdout.write(data); 
    }); 
});
req.end(); 
req.on('error', function(e) { 
    console.error(e); 
});
