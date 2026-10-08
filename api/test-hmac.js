/**
 * Vercel Serverless Function: HMAC-SHA256 Test & Utility Endpoint
 * Generates valid HMAC-SHA256 headers for testing Supabase Webhooks
 */

const { generateHmacSha256 } = require('./security');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    return res.status(200).end();
  }

  res.setHeader('Access-Control-Allow-Origin', '*');

  const secret = process.env.WEBHOOK_SECRET || 'sec_super_secret_hmac_key_9f82a17cb420';

  if (req.method === 'POST') {
    const rawPayload = typeof req.body === 'string' ? req.body : JSON.stringify(req.body);
    const signature = generateHmacSha256(rawPayload, secret);

    return res.status(200).json({
      success: true,
      raw_payload: rawPayload,
      hmac_sha256: signature,
      headers: {
        'x-supabase-signature': signature,
        'Content-Type': 'application/json'
      },
      curl_example: `curl -X POST https://your-domain.vercel.app/api/webhook \\
  -H "Content-Type: application/json" \\
  -H "x-supabase-signature: ${signature}" \\
  -d '${rawPayload.replace(/'/g, "\\'")}'`
    });
  }

  // GET default response with demo payload signed
  const samplePayload = JSON.stringify({
    type: 'INSERT',
    table: 'users',
    schema: 'public',
    record: { id: 101, username: 'sqli_attacker', query: "SELECT * FROM users WHERE id='1' OR '1'='1'" },
    role: 'anon'
  });

  const sampleSignature = generateHmacSha256(samplePayload, secret);

  return res.status(200).json({
    status: 'HMAC Generator Active',
    secret_configured: Boolean(process.env.WEBHOOK_SECRET),
    sample_payload: JSON.parse(samplePayload),
    sample_signature: sampleSignature,
    format: 'sha256 hex string'
  });
};
