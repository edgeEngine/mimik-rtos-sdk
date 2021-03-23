Both mock server and client are developed using nodejs.

Thus, in order to use them, nodejs are npm are required.


Steps

- Start the server first
```javascript
cd server
npm i
node ./index
```

The client is used to show that the server is working.
- Start the client 
```javascript
cd client
npm i
node ./index
```


You can also use curl as a test client
```
curl -i --key ./test-data/client1-key.pem --cert ./test-data/client1-crt.pem --cacert ./test-data/ca-crt.pem https://localhost:4433/tenants/me/services

```
