const express = require('express');
const AWS = require('aws-sdk');
const axios = require('axios');

const app = express();
const port = process.env.PORT || 10000;

// Configure AWS SDK
AWS.config.update({
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  region: 'us-east-1',
});

const sts = new AWS.STS();

app.get('/get-temp-creds', async (req, res) => {
  try {
    const data = await sts.getSessionToken({ DurationSeconds: 3600 }).promise();

    const credentials = {
      awsAccessKeyId: data.Credentials.AccessKeyId,
      awsSecretAccessKey: data.Credentials.SecretAccessKey,
      awsSessionToken: data.Credentials.SessionToken,
    };

    console.log('✅ Temporary credentials:', credentials);

    // Optional: Send to n8n
    await axios.post('https://YOUR-N8N-URL/webhook/send-creds', credentials);

    res.json({ status: 'sent to n8n', credentials });
  } catch (err) {
    console.error('❌ Error:', err);
    res.status(500).send('Failed to get credentials');
  }
});

app.listen(port, () => {
  console.log(`Running on port ${port}`);
});
