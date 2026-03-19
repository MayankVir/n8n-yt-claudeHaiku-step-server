const http = require('http');
const https = require('https');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY || 'changeme';

function sha256(data) {
  return crypto.createHash('sha256').update(data, 'utf8').digest('hex');
}

function hmac(key, data, encoding) {
  return crypto.createHmac('sha256', key).update(data).digest(encoding || undefined);
}

function getSignatureKey(secretKey, dateStamp, region, service) {
  const kDate = hmac('AWS4' + secretKey, dateStamp);
  const kRegion = hmac(kDate, region);
  const kService = hmac(kRegion, service);
  return hmac(kService, 'aws4_request');
}

function callBedrock({ accessKey, secretKey, region, modelId, body }) {
  return new Promise((resolve, reject) => {
    const host = `bedrock-runtime.${region}.amazonaws.com`;
    const singleEncoded = `/model/${modelId.replace(/:/g, '%3A')}/invoke`;
    const doubleEncoded = `/model/${modelId.replace(/:/g, '%253A')}/invoke`;
    const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);

    const now = new Date();
    const amzDate = now.toISOString().replace(/[:\-]|\.\d{3}/g, '').slice(0, 15) + 'Z';
    const dateStamp = amzDate.slice(0, 8);
    const payloadHash = sha256(bodyStr);

    const canonicalHeaders = `content-type:application/json\nhost:${host}\nx-amz-date:${amzDate}\n`;
    const signedHeaders = 'content-type;host;x-amz-date';
    const canonicalRequest = `POST\n${doubleEncoded}\n\n${canonicalHeaders}\n${signedHeaders}\n${payloadHash}`;

    const credentialScope = `${dateStamp}/${region}/bedrock/aws4_request`;
    const stringToSign = `AWS4-HMAC-SHA256\n${amzDate}\n${credentialScope}\n${sha256(canonicalRequest)}`;

    const signingKey = getSignatureKey(secretKey, dateStamp, region, 'bedrock');
    const signature = hmac(signingKey, stringToSign, 'hex');
    const authHeader = `AWS4-HMAC-SHA256 Credential=${accessKey}/${credentialScope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

    const options = {
      method: 'POST',
      hostname: host,
      path: singleEncoded,
      headers: {
        'Content-Type': 'application/json',
        'X-Amz-Date': amzDate,
        'Authorization': authHeader,
        'Content-Length': Buffer.byteLength(bodyStr)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch(e) { parsed = { raw: data }; }
        if (res.statusCode >= 400) {
          reject({ statusCode: res.statusCode, awsError: parsed });
        } else {
          resolve(parsed);
        }
      });
    });

    req.on('error', (e) => reject({ statusCode: 503, awsError: e.message }));
    req.setTimeout(30000, () => {
      req.destroy();
      reject({ statusCode: 504, awsError: 'Bedrock request timed out after 30s' });
    });

    req.write(bodyStr);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {

  // Health check
  if (req.method === 'GET' && req.url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
    return;
  }

  // Auth check
  const apiKey = req.headers['x-api-key'];
  if (apiKey !== API_KEY) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: false, error: 'Unauthorized — invalid or missing x-api-key header' }));
    return;
  }

  // Main invoke endpoint
  if (req.method === 'POST' && req.url === '/invoke') {
    let rawBody = '';
    req.on('data', chunk => rawBody += chunk);
    req.on('end', async () => {
      try {
        const {
          accessKey,
          secretKey,
          region = 'us-east-1',
          modelId = 'mistral.mistral-7b-instruct-v0:2',
          prompt,
          max_tokens = 800
        } = JSON.parse(rawBody);

        if (!accessKey || !secretKey) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'accessKey and secretKey are required' }));
          return;
        }
        if (!prompt) {
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'prompt is required' }));
          return;
        }

        // Build request body based on model provider
        let bedrockPayload;

        if (modelId.startsWith('anthropic')) {
          // Claude format
          bedrockPayload = {
            anthropic_version: 'bedrock-2023-05-31',
            max_tokens,
            messages: [{ role: 'user', content: prompt }]
          };
        } else if (modelId.startsWith('mistral')) {
          // Mistral instruct format
          bedrockPayload = {
            prompt: `<s>[INST] ${prompt} [/INST]`,
            max_tokens,
            temperature: 0.7
          };
        } else if (modelId.startsWith('amazon.titan')) {
          // Titan Text format
          bedrockPayload = {
            inputText: prompt,
            textGenerationConfig: {
              maxTokenCount: max_tokens,
              temperature: 0.7
            }
          };
        } else if (modelId.startsWith('meta')) {
          // Llama format
          bedrockPayload = {
            prompt,
            max_gen_len: max_tokens,
            temperature: 0.7
          };
        } else {
          // Generic fallback — try Mistral format
          bedrockPayload = {
            prompt: `<s>[INST] ${prompt} [/INST]`,
            max_tokens,
            temperature: 0.7
          };
        }

        const result = await callBedrock({
          accessKey,
          secretKey,
          region,
          modelId,
          body: JSON.stringify(bedrockPayload)
        });

        // Extract text based on model provider response format
        let text = '';
        if (result?.content?.[0]?.text) {
          // Claude
          text = result.content[0].text;
        } else if (result?.outputs?.[0]?.text) {
          // Mistral
          text = result.outputs[0].text;
        } else if (result?.generation) {
          // Mistral alternate / Llama
          text = result.generation;
        } else if (result?.results?.[0]?.outputText) {
          // Titan
          text = result.results[0].outputText;
        } else if (result?.completions?.[0]?.data?.text) {
          // AI21
          text = result.completions[0].data.text;
        } else {
          // Unknown format — return raw
          text = JSON.stringify(result);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          text,
          modelId,
          usage: result.usage || {},
          raw: result
        }));

      } catch (err) {
        const statusCode = err.statusCode || 500;
        console.error('Bedrock error:', JSON.stringify(err));
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: false,
          statusCode,
          error: err.awsError || err.message || 'Unknown error',
          stage: err.statusCode ? 'bedrock_api' : 'proxy_server'
        }));
      }
    });
    return;
  }

  // 404
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ success: false, error: 'Not found. Available: GET /health, POST /invoke' }));
});

server.listen(PORT, () => {
  console.log(`Bedrock proxy server running on port ${PORT}`);
});
