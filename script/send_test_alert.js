import dotenv from 'dotenv';
dotenv.config();

import crypto from 'crypto';
import handler from '../api/webhook.js';

/**
 * Script untuk memicu notifikasi webhook Supabase nyata ke Telegram
 * Mengirimkan payload ancaman (BAHAYA / CRITICAL) dengan HMAC-SHA256 yang sah
 */
async function triggerRealAlert() {
  console.log('='.repeat(65));
  console.log('🚨 MENGIRIM NOTIFIKASI WEBHOOK SUPABASE KE TELEGRAM...');
  console.log('='.repeat(65));

  const secret = process.env.WEBHOOK_SECRET || 'sec_super_secret_hmac_key_9f82a17cb420';

  const mockPayload = {
    event: 'DATABASE_MUTATION_SUSPICIOUS',
    table: 'public.auth_sessions',
    type: 'UPDATE',
    query: "SELECT token FROM auth_sessions WHERE session_id = '1' OR 1=1 --",
    status: 'BAHAYA',
    threat_level: 'CRITICAL',
    source_ip: '198.51.100.42',
    timestamp: new Date().toISOString(),
    ai_defense: {
      action: 'QUARANTINE_IP_AND_REVOKE_SESSION',
      cvss_score: 9.6,
      mitigation: 'Automated containment enforced by Dual NVIDIA NIM'
    }
  };

  const bodyString = JSON.stringify(mockPayload);
  const hmac = crypto.createHmac('sha256', secret).update(bodyString).digest('hex');

  console.log('[*] Target Bot Token :', (process.env.TELEGRAM_BOT_TOKEN || '').slice(0, 10) + '...');
  console.log('[*] Target Chat ID   :', process.env.TELEGRAM_CHAT_ID);
  console.log('[*] HMAC Signature   :', hmac);
  console.log('[*] Status Ancaman   : BAHAYA (CRITICAL)\n');

  const req = {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-signature': hmac
    },
    body: mockPayload
  };

  const res = {
    statusCode: 200,
    headers: {},
    setHeader(k, v) { this.headers[k] = v; },
    status(code) { this.statusCode = code; return this; },
    json(data) {
      console.log('='.repeat(65));
      console.log(`[HTTP ${this.statusCode}] Respons Serverless Webhook:`);
      console.log(JSON.stringify(data, null, 2));
      console.log('='.repeat(65));
      if (data.telegram?.sent) {
        console.log('✅ BERHASIL! Notifikasi BAHAYA telah terkirim ke Telegram Anda!');
      } else {
        console.log('⚠️ Telegram Response:', data.telegram?.response);
      }
      return this;
    }
  };

  await handler(req, res);
}

triggerRealAlert();
