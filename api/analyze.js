/**
 * Vercel Serverless Function: Direct Dual NVIDIA NIM Threat Analysis Endpoint
 */

const { analyzeThreatWithDualNimModels } = require('./nim-client');
const store = require('./store');

module.exports = async function handler(req, res) {
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    let payload = req.body;
    if (typeof payload === 'string') {
      try { payload = JSON.parse(payload); } catch (e) {}
    }

    const analysis = await analyzeThreatWithDualNimModels(payload || {});

    // Save event to store
    const simEvent = {
      id: `sim-${Date.now()}-${Math.random().toString(36).substring(2, 6)}`,
      source: 'SOC Console Live Probe',
      table: payload?.table || 'simulation.targets',
      type: payload?.type || 'PROBE_ASSESSMENT',
      timestamp: new Date().toISOString(),
      rawPayload: payload,
      hmacValid: true,
      signature: 'simulated_authorized_key_valid_sha256',
      aiAnalysis: analysis
    };

    store.addEvent(simEvent);

    return res.status(200).json({
      success: true,
      event_id: simEvent.id,
      analysis
    });
  } catch (error) {
    return res.status(500).json({ error: error.message });
  }
};
