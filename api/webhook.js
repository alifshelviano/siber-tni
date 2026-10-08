import crypto from 'crypto';

/**
 * Vercel Serverless Function: Supabase Database Webhook Receiver
 * - Format: ES Module (import / export default)
 * - HMAC-SHA256 signature verification via 'x-signature' header
 * - Telegram Bot Alert Integration
 */
export default async function handler(req, res) {
  // CORS Preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-signature, x-supabase-signature');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({
      error: 'Method Not Allowed',
      message: 'Supabase webhook requires POST method'
    });
  }

  try {
    // 1. Periksa apakah header x-signature ada, jika tidak ada tolak dengan 400 Bad Request
    const signature = req.headers['x-signature'] || req.headers['x-supabase-signature'];
    if (!signature) {
      return res.status(400).json({
        error: 'Bad Request',
        message: 'Missing x-signature header'
      });
    }

    // 2. Ambil isi body request sebagai string (JSON.stringify jika perlu),
    // buat HMAC-SHA256 menggunakan crypto.createHmac("sha256", hmac_secret).update(body).digest("hex")
    let bodyString = '';
    let payload = req.body;

    if (typeof req.body === 'string') {
      bodyString = req.body;
      try {
        payload = JSON.parse(bodyString);
      } catch (e) {
        payload = { raw: bodyString };
      }
    } else if (req.body && typeof req.body === 'object') {
      bodyString = JSON.stringify(req.body);
    } else {
      // Buffer stream dari raw request (untuk custom server / local runner)
      bodyString = await new Promise((resolve, reject) => {
        let data = '';
        req.on('data', chunk => data += chunk);
        req.on('end', () => resolve(data));
        req.on('error', reject);
      });
      try {
        payload = JSON.parse(bodyString || '{}');
      } catch (e) {
        payload = { raw: bodyString };
      }
    }

    const hmacSecret = process.env.HMAC_SECRET || process.env.WEBHOOK_SECRET || 'secret_key';
    const computedHmac = crypto
      .createHmac('sha256', hmacSecret)
      .update(bodyString)
      .digest('hex');

    // 3. Bandingkan HMAC yang dibuat dengan nilai di header x-signature menggunakan perbandingan string biasa
    const cleanHeaderSignature = signature.replace(/^sha256=/, '').trim();

    if (computedHmac !== cleanHeaderSignature) {
      // Jika tidak cocok tolak dengan 401 Unauthorized
      return res.status(401).json({
        error: 'Unauthorized',
        message: 'Invalid HMAC signature'
      });
    }

    // 4. Jika cocok lanjut ke pengiriman Telegram
    // 5. Integrasi Telegram Bot Alert: URL https://api.telegram.org/bot{TOKEN}/sendMessage
    // 6. Pesan mencantumkan status kejadian (AMAN/BAHAYA), level ancaman, dan detail dari payload Supabase
    // 7. Gunakan environment variables telegram_bot_token dan telgram_chat_id (jangan hard code)
    const botToken = process.env.TELEGRAM_BOT_TOKEN || process.env.telegram_bot_token;
    const chatId = process.env.TELEGRAM_CHAT_ID || process.env.telgram_chat_id || process.env.telegram_chat_id;

    // Evaluasi status kejadian (AMAN / BAHAYA) dan level ancaman dari payload Supabase
    const payloadStr = JSON.stringify(payload).toLowerCase();
    const isThreat = /union\s+select|or\s+1=1|drop\s+table|<script>|admin'|exec\s*\(|benchmark\(|sleep\(/i.test(payloadStr)
      || payload.status === 'BAHAYA'
      || payload.threat_level === 'CRITICAL'
      || payload.threat_level === 'HIGH';

    const statusKejadian = isThreat ? 'BAHAYA' : (payload.status || 'AMAN');
    const levelAncaman = isThreat ? (payload.threat_level || 'CRITICAL') : (payload.threat_level || 'LOW');

    const telegramMessage = `🚨 *SUPABASE SECURITY REPORT ALERT* 🚨\n\n`
      + `📌 *Status Kejadian:* ${statusKejadian}\n`
      + `⚠️ *Level Ancaman:* ${levelAncaman}\n`
      + `🕒 *Waktu:* ${new Date().toISOString()}\n\n`
      + `📋 *Detail Payload Supabase:*\n`
      + `\`\`\`json\n${JSON.stringify(payload, null, 2)}\n\`\`\``;

    let telegramSent = false;
    let telegramResult = null;

    if (botToken && chatId) {
      try {
        const tgRes = await fetch(`https://api.telegram.org/bot${botToken}/sendMessage`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: chatId,
            text: telegramMessage,
            parse_mode: 'Markdown'
          })
        });
        telegramResult = await tgRes.json();
        telegramSent = tgRes.ok;
      } catch (tgErr) {
        console.error('Telegram notification error:', tgErr.message);
        telegramResult = { error: tgErr.message };
      }
    } else {
      telegramResult = { note: 'Telegram credentials not provided in environment' };
    }

    return res.status(200).json({
      success: true,
      status: 'success',
      message: 'Valid signature - Supabase report accepted',
      event_status: statusKejadian,
      threat_level: levelAncaman,
      telegram: {
        sent: telegramSent,
        response: telegramResult
      },
      payload
    });

  } catch (error) {
    console.error('Webhook processing error:', error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: error.message
    });
  }
}
