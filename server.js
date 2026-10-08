/**
 * Local Development Server & Vercel Emulation Runner
 * Allows testing the frontend, serverless endpoints (/api/*), HMAC verification,
 * and dual NVIDIA NIM analysis locally.
 */

require('dotenv').config();
const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');

const webhookModule = require('./api/webhook');
const webhookHandler = webhookModule.default || webhookModule;
const eventsHandler = require('./api/events');
const analyzeHandler = require('./api/analyze');
const testHmacHandler = require('./api/test-hmac');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

const MIME_TYPES = {
  '.html': 'text/html',
  '.css': 'text/css',
  '.js': 'application/javascript',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

const server = http.createServer(async (req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;

  // Augment req with query params
  req.query = parsedUrl.query;

  // Emulate Vercel Serverless res.status(code).json(body)
  res.status = function (statusCode) {
    res.statusCode = statusCode;
    return this;
  };
  res.json = function (data) {
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify(data, null, 2));
    return this;
  };

  // Route API requests
  if (pathname.startsWith('/api/')) {
    if (pathname === '/api/webhook') {
      return webhookHandler(req, res);
    }
    if (pathname === '/api/events') {
      return eventsHandler(req, res);
    }
    if (pathname === '/api/analyze') {
      // Parse body if JSON
      let raw = '';
      req.on('data', chunk => raw += chunk);
      req.on('end', () => {
        try { req.body = JSON.parse(raw); } catch (e) { req.body = raw; }
        analyzeHandler(req, res);
      });
      return;
    }
    if (pathname === '/api/test-hmac') {
      let raw = '';
      req.on('data', chunk => raw += chunk);
      req.on('end', () => {
        try { req.body = JSON.parse(raw); } catch (e) { req.body = raw; }
        testHmacHandler(req, res);
      });
      return;
    }
    return res.status(404).json({ error: 'Endpoint Not Found' });
  }

  // Serve static files from /public
  let filePath = path.join(PUBLIC_DIR, pathname === '/' ? 'index.html' : pathname);
  
  if (!fs.existsSync(filePath)) {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  }

  const ext = path.extname(filePath);
  const contentType = MIME_TYPES[ext] || 'text/plain';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.statusCode = 500;
      res.end(`Server Error: ${err.message}`);
    } else {
      res.statusCode = 200;
      res.setHeader('Content-Type', contentType);
      res.end(content);
    }
  });
});

if (require.main === module) {
  server.listen(PORT, () => {
    console.log(`[DB Security Monitor] Server listening on http://localhost:${PORT}`);
    console.log(`[Shield Active] Webhook HMAC-SHA256 listener at http://localhost:${PORT}/api/webhook`);
    console.log(`[NVIDIA NIM] Models active: ${process.env.NIM_MODEL_1 || 'meta/llama-3.1-70b-instruct'} & ${process.env.NIM_MODEL_2 || 'meta/llama-3.1-8b-instruct'}`);
  });
}

module.exports = server;
