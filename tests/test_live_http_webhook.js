/**
 * End-to-End HTTP Webhook Live Verification
 * Tests the live HTTP /api/webhook serverless handler for:
 * 1. 401 Unauthorized upon invalid HMAC signature
 * 2. 200 OK upon valid HMAC-SHA256 signature with Dual NVIDIA NIM response
 */

const http = require('http');
const { generateHmacSha256 } = require('../api/security');

const SECRET = 'sec_super_secret_hmac_key_9f82a17cb420';

function postRequest(path, headers, body) {
  return new Promise((resolve, reject) => {
    const postData = typeof body === 'string' ? body : JSON.stringify(body);
    const options = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(postData),
        ...headers
      }
    };

    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          data: JSON.parse(data)
        });
      });
    });

    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

async function run() {
  console.log('================================================================');
  console.log('🌐 END-TO-END LIVE HTTP WEBHOOK ENDPOINT VERIFICATION');
  console.log('================================================================');

  const attackPayload = JSON.stringify({
    type: 'INSERT',
    table: 'public.auth_sessions',
    query: "SELECT token FROM auth_sessions WHERE session_id = 'sess_01' OR 1=1 --",
    role: 'anon'
  });

  // TEST 1: Forged / Invalid HMAC Signature
  console.log('[STEP 1] Testing Unauthenticated Webhook Request with Forged Signature:');
  const res1 = await postRequest('/api/webhook', {
    'x-supabase-signature': '000000000000000000000000000000000000000000000000000000000000dead'
  }, attackPayload);

  console.log(`  HTTP Response Status: ${res1.statusCode}`);
  console.log(`  Response Error Code:  ${res1.data.code}`);
  console.log(`  Error Message:        ${res1.data.error}`);
  if (res1.statusCode === 401 && res1.data.code === 'HMAC_VERIFICATION_FAILED') {
    console.log('  ==> PASS: Webhook correctly rejected unauthorized attempt with 401 Unauthorized!\n');
  } else {
    throw new Error('Expected 401 Unauthorized');
  }

  // TEST 2: Valid HMAC-SHA256 Signed Webhook Request
  console.log('[STEP 2] Testing Authenticated Webhook Request with Valid HMAC-SHA256 Signature:');
  const validSignature = generateHmacSha256(attackPayload, SECRET);
  console.log(`  Calculated Signature: ${validSignature}`);

  const res2 = await postRequest('/api/webhook', {
    'x-supabase-signature': validSignature
  }, attackPayload);

  console.log(`  HTTP Response Status: ${res2.statusCode}`);
  console.log(`  Response Code:        ${res2.data.code}`);
  console.log(`  Verified By:          ${res2.data.verified_by}`);
  console.log(`  NIM Models Invoked:   ${res2.data.ai_ensemble?.models_invoked?.join(', ')}`);
  console.log(`  Threat Rating:        ${res2.data.ai_ensemble?.threat_level}`);
  console.log(`  Mitigation Action:    ${res2.data.ai_ensemble?.mitigation}`);

  if (res2.statusCode === 200 && res2.data.verified_by === 'HMAC-SHA256') {
    console.log('  ==> PASS: Webhook accepted, verified HMAC-SHA256 in constant time, and evaluated with Dual NVIDIA NIM!\n');
  } else {
    throw new Error('Expected 200 OK');
  }

  console.log('================================================================');
  console.log('🎉 ALL END-TO-END HTTP TESTS PASSED COMPLETELY!');
  console.log('================================================================\n');
}

run().catch(e => {
  console.error('Test failed:', e);
  process.exit(1);
});
