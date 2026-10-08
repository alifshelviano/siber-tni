/**
 * Test Suite: Supabase Webhook Security Verification & Telegram Alert Flows
 * Skenario Pengujian:
 *  - Test 1: Valid Signature (HMAC benar) -> HTTP 200 OK & Telegram menerima pesan
 *  - Test 2: Tampered Signature (diubah/rusak) -> HTTP 401 Unauthorized
 *  - Test 3: Missing Header (tanpa x-signature) -> HTTP 400 Bad Request
 */

import http from 'http';
import crypto from 'crypto';
import assert from 'assert';
import handler from '../api/webhook.js';

// Konfigurasi Environment Pengujian
const HMAC_SECRET = 'sec_super_secret_supabase_key_778899';
const TEST_BOT_TOKEN = '123456789:ABCdefGHIjklMNOpqrsTUVwxyz';
const TEST_CHAT_ID = '987654321';

process.env.WEBHOOK_SECRET = HMAC_SECRET;
process.env.HMAC_SECRET = HMAC_SECRET;
process.env.telegram_bot_token = TEST_BOT_TOKEN;
process.env.telgram_chat_id = TEST_CHAT_ID;

// Mocking Telegram Bot API call
let capturedTelegramPayload = null;
const originalFetch = globalThis.fetch;

globalThis.fetch = async function mockFetch(url, options) {
  if (typeof url === 'string' && url.includes('api.telegram.org')) {
    capturedTelegramPayload = {
      url,
      method: options?.method,
      headers: options?.headers,
      body: JSON.parse(options?.body || '{}')
    };
    return {
      ok: true,
      status: 200,
      json: async () => ({
        ok: true,
        result: {
          message_id: 42,
          chat: { id: TEST_CHAT_ID },
          text: capturedTelegramPayload.body.text
        }
      })
    };
  }
  return originalFetch(url, options);
};

// Buat HTTP Server Pengujian
function createTestServer() {
  return http.createServer(async (req, res) => {
    // Emulasi method res.status(code).json(payload) khas Vercel Serverless
    res.status = function (code) {
      res.statusCode = code;
      return this;
    };
    res.json = function (data) {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify(data, null, 2));
      return this;
    };

    // Buffer body jika berupa stream
    let raw = '';
    req.on('data', chunk => raw += chunk);
    req.on('end', async () => {
      req.body = raw;
      try {
        await handler(req, res);
      } catch (err) {
        res.statusCode = 500;
        res.end(JSON.stringify({ error: err.message }));
      }
    });
  });
}

function calculateHmac(payloadString, secret) {
  return crypto.createHmac('sha256', secret).update(payloadString).digest('hex');
}

async function runTestSuite() {
  const server = createTestServer();
  await new Promise(resolve => server.listen(0, resolve));
  const port = server.address().port;
  const baseUrl = `http://localhost:${port}/api/webhook`;

  console.log('================================================================');
  console.log('🔒 TEST SUITE: SUPABASE WEBHOOK HMAC-SHA256 & TELEGRAM BOT ALERT');
  console.log('================================================================');
  console.log(`[INFO] Server Uji Lokal berjalan di: ${baseUrl}`);
  console.log(`[INFO] Kunci Rahasia HMAC           : ${HMAC_SECRET}`);
  console.log(`[INFO] Telegram Bot Token          : ${TEST_BOT_TOKEN}`);
  console.log(`[INFO] Telegram Chat ID            : ${TEST_CHAT_ID}\n`);

  try {
    // -------------------------------------------------------------
    // TEST 1: Valid Signature (HMAC Benar)
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('📌 [TEST 1] VALID SIGNATURE: HMAC Valid & Pengiriman Telegram');
    console.log('----------------------------------------------------------------');
    capturedTelegramPayload = null;

    const payloadTest1 = JSON.stringify({
      event: 'DATABASE_MUTATION',
      table: 'public.users',
      type: 'INSERT',
      record: { id: 101, username: 'komandan_siber', role: 'officer' },
      status: 'AMAN',
      threat_level: 'LOW'
    });

    const validSignature = calculateHmac(payloadTest1, HMAC_SECRET);

    const res1 = await originalFetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': validSignature
      },
      body: payloadTest1
    });

    const body1 = await res1.json();
    console.log(`  Payload Dikirim   : ${payloadTest1}`);
    console.log(`  Header x-signature: ${validSignature}`);
    console.log(`  HTTP Response     : ${res1.status} ${res1.statusText}`);
    console.log(`  Respons JSON Body :`, JSON.stringify(body1, null, 2));

    assert.strictEqual(res1.status, 200, 'Test 1 Gagal: Status harus 200 OK');
    assert.strictEqual(body1.status, 'success', 'Test 1 Gagal: Status JSON harus "success"');
    assert.ok(capturedTelegramPayload, 'Test 1 Gagal: Notifikasi Telegram harus terkirim');
    console.log(`  [TELEGRAM VERIFIED] Pesan Telegram Terkirim:`);
    console.log(`    - URL Target : ${capturedTelegramPayload.url}`);
    console.log(`    - Chat ID    : ${capturedTelegramPayload.body.chat_id}`);
    console.log(`    - Isi Pesan  :\n${capturedTelegramPayload.body.text.split('\n').map(l => '      ' + l).join('\n')}`);
    console.log('  ==> PASS: [TEST 1] Diterima 200 OK & Pesan Telegram Berhasil Dikirim!\n');

    // -------------------------------------------------------------
    // TEST 2: Tampered Signature (Signature Diubah / Dirusak)
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('📌 [TEST 2] TAMPERED SIGNATURE: Signature Rusak / Tidak Cocok');
    console.log('----------------------------------------------------------------');
    capturedTelegramPayload = null;

    const payloadTest2 = JSON.stringify({
      event: 'INJECTION_ATTEMPT',
      table: 'public.auth_sessions',
      type: 'UPDATE',
      query: "SELECT token FROM auth_sessions WHERE session_id = '1' OR 1=1 --",
      status: 'BAHAYA',
      threat_level: 'CRITICAL'
    });

    const fakeTamperedSignature = 'badc0de00000000000000000000000000000000000000000000000000000dead';

    const res2 = await originalFetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-signature': fakeTamperedSignature
      },
      body: payloadTest2
    });

    const body2 = await res2.json();
    console.log(`  Payload Dikirim   : ${payloadTest2}`);
    console.log(`  Header x-signature: ${fakeTamperedSignature} (RUSAK / PALSU)`);
    console.log(`  HTTP Response     : ${res2.status} ${res2.statusText}`);
    console.log(`  Respons JSON Body :`, JSON.stringify(body2, null, 2));

    assert.strictEqual(res2.status, 401, 'Test 2 Gagal: Status harus 401 Unauthorized');
    assert.strictEqual(capturedTelegramPayload, null, 'Test 2 Gagal: Telegram TIDAK boleh menerima pesan untuk signature palsu');
    console.log('  ==> PASS: [TEST 2] Ditolak dengan 401 Unauthorized!\n');

    // -------------------------------------------------------------
    // TEST 3: Missing Header (Tanpa Header x-signature)
    // -------------------------------------------------------------
    console.log('----------------------------------------------------------------');
    console.log('📌 [TEST 3] MISSING HEADER: Request Tanpa Header x-signature');
    console.log('----------------------------------------------------------------');
    capturedTelegramPayload = null;

    const payloadTest3 = JSON.stringify({
      table: 'public.audit_logs',
      message: 'Unsigned probe attempt'
    });

    const res3 = await originalFetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
        // Tidak ada header x-signature
      },
      body: payloadTest3
    });

    const body3 = await res3.json();
    console.log(`  Payload Dikirim   : ${payloadTest3}`);
    console.log(`  Header x-signature: (TIDAK DILAMPIRKAN)`);
    console.log(`  HTTP Response     : ${res3.status} ${res3.statusText}`);
    console.log(`  Respons JSON Body :`, JSON.stringify(body3, null, 2));

    assert.strictEqual(res3.status, 400, 'Test 3 Gagal: Status harus 400 Bad Request');
    assert.strictEqual(capturedTelegramPayload, null, 'Test 3 Gagal: Telegram TIDAK boleh menerima pesan tanpa header signature');
    console.log('  ==> PASS: [TEST 3] Ditolak dengan 400 Bad Request!\n');

    console.log('================================================================');
    console.log('✅ SEMUA 3 PENGUJIAN ALUR (TEST 1, TEST 2, TEST 3) BERHASIL 100%!');
    console.log('================================================================');

  } finally {
    server.close();
  }
}

runTestSuite().catch(err => {
  console.error('Test Suite Gagal:', err);
  process.exit(1);
});
