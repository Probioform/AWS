// index.js
const express = require('express');
const crypto = require('crypto');
const app = express();
app.use(express.json());

function hash(payload) {
  return crypto.createHash('sha256').update(payload, 'utf8').digest('hex');
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function getSignatureKey(secret, date, region, service) {
  const kDate = hmac(`AWS4${secret}`, date);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

app.post('/sign', (req, res) => {
  const {
    awsAccessKeyId,
    awsSecretAccessKey,
    awsSessionToken, // optional
    region,
    service,
    method,
    host,
    path,
    payload = ''
  } = req.body;

  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\..*/g, '');
  const dateStamp = amzDate.slice(0, 8);

  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = hash(payload);
  const canonicalRequest = [
    method,
    path,
    '',
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    hash(canonicalRequest)
  ].join('\n');

  const signingKey = getSignatureKey(awsSecretAccessKey, dateStamp, region, service);
  const signature = crypto.createHmac('sha256', signingKey).update(stringToSign, 'utf8').digest('hex');

  const authorizationHeader = `AWS4-HMAC-SHA256 Credential=${awsAccessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const response = {
    Authorization: authorizationHeader,
    'x-amz-date': amzDate,
    Host: host
  };

  if (awsSessionToken) {
    response['x-amz-security-token'] = awsSessionToken;
  }

  res.json(response);
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`Signer API running on port ${PORT}`));
