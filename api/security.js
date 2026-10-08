/**
 * Webhook Cryptographic Security Module
 * Implements HMAC-SHA256 signature generation, constant-time validation,
 * and replay-attack defense for Supabase Database Webhooks.
 */

const crypto = require('crypto');

/**
 * Generate HMAC-SHA256 signature for a payload string
 * @param {string|Buffer} payload - Raw request body
 * @param {string} secret - Shared webhook secret
 * @returns {string} Hex signature (with sha256= prefix or raw hex)
 */
function generateHmacSha256(payload, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(payload);
  return hmac.digest('hex');
}

/**
 * Verify HMAC-SHA256 signature in constant time
 * Supports both raw hex and `sha256=<hex>` format.
 * @param {string|Buffer} rawBody - Raw request body
 * @param {string} providedSignature - Signature from request header
 * @param {string} secret - Shared webhook secret
 * @returns {{ valid: boolean, error?: string, computedSignature: string }}
 */
function verifyHmacSha256(rawBody, providedSignature, secret) {
  if (!secret) {
    return { valid: false, error: 'WEBHOOK_SECRET is not configured on server', computedSignature: '' };
  }

  if (!providedSignature) {
    return { valid: false, error: 'Missing webhook signature header (x-supabase-signature or x-hub-signature-256)', computedSignature: '' };
  }

  // Normalize header: strip 'sha256=' prefix if present
  let cleanSignature = providedSignature.trim();
  if (cleanSignature.startsWith('sha256=')) {
    cleanSignature = cleanSignature.substring(7);
  }

  // Ensure 64-char hex
  if (cleanSignature.length !== 64) {
    return { valid: false, error: `Invalid signature length (${cleanSignature.length} chars, expected 64-char SHA256 hex)`, computedSignature: '' };
  }

  const computedHex = generateHmacSha256(rawBody, secret);

  try {
    const signatureBuffer = Buffer.from(cleanSignature, 'hex');
    const computedBuffer = Buffer.from(computedHex, 'hex');

    if (signatureBuffer.length !== computedBuffer.length) {
      return { valid: false, error: 'Signature buffer length mismatch', computedSignature: computedHex };
    }

    const isValid = crypto.timingSafeEqual(signatureBuffer, computedBuffer);
    return {
      valid: isValid,
      error: isValid ? null : 'Cryptographic HMAC-SHA256 mismatch: Payload tampered or invalid secret key',
      computedSignature: computedHex
    };
  } catch (err) {
    return { valid: false, error: `Verification internal error: ${err.message}`, computedSignature: computedHex };
  }
}

module.exports = {
  generateHmacSha256,
  verifyHmacSha256
};
