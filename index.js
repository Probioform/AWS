import express from 'express';

const app = express();
app.use(express.json());

app.post('/sign', async (req, res) => {
  try {
    const {
      awsAccessKeyId,
      awsSecretAccessKey,
      awsSessionToken = '',
      region = 'us-east-1',
      service = 'execute-api',
      method = 'GET',
      host,
      path,
      queryString = '',
      payload = '',
    } = req.body;

    if (!awsAccessKeyId || !awsSecretAccessKey || !host || !path) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const now = new Date();
    const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
    const dateStamp = amzDate.substr(0, 8);

    const enc = new TextEncoder();

    const sha256 = async (str) => {
      const data = enc.encode(str);
      const hashBuffer = await crypto.subtle.digest('SHA-256', data);
      return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    };

    const hmac = async (key, data) => {
      const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
      return await crypto.subtle.sign('HMAC', cryptoKey, enc.encode(data));
    };

    const getSignatureKey = async (key, date, region, service) => {
      const kDate = await hmac(enc.encode('AWS4' + key), date);
      const kRegion = await hmac(kDate, region);
      const kService = await hmac(kRegion, service);
      const kSigning = await hmac(kService, 'aws4_request');
      return kSigning;
    };

    const payloadHash = await sha256(payload);
    const canonicalHeaders = `host:${host}\n`;
    const signedHeaders = 'host';
    const canonicalRequest = [
      method.toUpperCase(),
      path,
      queryString,
      canonicalHeaders,
      signedHeaders,
      payloadHash
    ].join('\n');

    const credentialScope = `${dateStamp}/${region}/${service}/aws4_request`;
    const stringToSign = [
      'AWS4-HMAC-SHA256',
      amzDate,
      credentialScope,
      await sha256(canonicalRequest)
    ].join('\n');

    const signingKey = await getSignatureKey(awsSecretAccessKey, dateStamp, region, service);
    const sigKey = await crypto.subtle.importKey('raw', signingKey, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = await crypto.subtle.sign('HMAC', sigKey, enc.encode(stringToSign));
    const signature = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');

    const authorizationHeader = `AWS4-HMAC-SHA256 Credential=${awsAccessKeyId}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const result = {
      Authorization: authorizationHeader,
      'x-amz-date': amzDate,
      Host: host,
    };

    if (awsSessionToken) {
      result['x-amz-security-token'] = awsSessionToken;
    }

    res.json(result);
  } catch (err) {
    console.error('Signing failed:', err);
    res.status(500).json({ error: err.message });
  }
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`Signer running on http://localhost:${PORT}`);
});
