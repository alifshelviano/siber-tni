/**
 * Vercel Serverless Function: Real-time Security Events & Metrics Feed
 */

const store = require('./store');

module.exports = async function handler(req, res) {
  // CORS Preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    return res.status(200).end();
  }

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Content-Type', 'application/json');

  const limit = parseInt(req.query?.limit || '50', 10);
  const events = store.getEvents(limit);
  const metrics = store.getMetrics();

  return res.status(200).json({
    status: 'ONLINE',
    system_time: new Date().toISOString(),
    metrics,
    events
  });
};
