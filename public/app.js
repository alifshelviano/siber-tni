/**
 * Supabase Sentinel Frontend Engine
 * Real-time event polling, HMAC signature simulation, and Dual NIM telemetry display
 */

const PRESETS = {
  sqli: {
    type: 'INSERT',
    table: 'public.auth_sessions',
    schema_table: 'public.auth_sessions',
    query: "SELECT token FROM auth_sessions WHERE session_id = 'sess_09' OR 1=1 --",
    role: 'anon',
    caller_ip: '185.220.101.45',
    headers: { 'user-agent': 'sqlmap/1.7.2#stable' }
  },
  privesc: {
    type: 'UPDATE',
    table: 'public.user_roles',
    schema_table: 'public.user_roles',
    query: "UPDATE user_roles SET role = 'SUPERUSER_ADMIN' WHERE id = 'usr_ghost'",
    role: 'anon',
    caller_ip: '45.154.255.8',
    headers: { 'user-agent': 'curl/7.88.1' }
  },
  exfil: {
    type: 'SELECT_BULK',
    table: 'public.customer_wallets',
    schema_table: 'public.customer_wallets',
    record_count: 50000,
    query: "SELECT wallet_address, private_seed_encrypted FROM customer_wallets LIMIT 50000",
    role: 'service_role',
    caller_ip: '193.106.191.22'
  },
  benign: {
    type: 'UPDATE',
    table: 'public.user_profiles',
    schema_table: 'public.user_profiles',
    query: "UPDATE user_profiles SET last_seen = NOW() WHERE id = 'usr_valid_33'",
    role: 'authenticated',
    caller_ip: '103.21.244.2'
  }
};

let currentEvents = [];

document.addEventListener('DOMContentLoaded', () => {
  initSimulator();
  fetchEvents();
  // Poll events every 4 seconds
  setInterval(fetchEvents, 4000);

  // Setup modal close
  const modal = document.getElementById('incident-modal');
  const closeBtn = document.getElementById('modal-close-btn');
  closeBtn.addEventListener('click', () => { modal.style.display = 'none'; });
  modal.addEventListener('click', (e) => {
    if (e.target === modal) modal.style.display = 'none';
  });

  document.getElementById('btn-refresh-feed').addEventListener('click', fetchEvents);
});

/**
 * Initialize Webhook Testing Simulator
 */
function initSimulator() {
  const presetSelect = document.getElementById('attack-preset');
  const payloadEditor = document.getElementById('webhook-payload-editor');
  const btnFire = document.getElementById('btn-fire-webhook');
  const btnInspectKey = document.getElementById('btn-recompute-hmac');

  // Load default preset
  payloadEditor.value = JSON.stringify(PRESETS[presetSelect.value], null, 2);

  presetSelect.addEventListener('change', () => {
    const val = presetSelect.value;
    if (PRESETS[val]) {
      payloadEditor.value = JSON.stringify(PRESETS[val], null, 2);
    }
  });

  btnFire.addEventListener('click', async () => {
    await fireWebhookSimulation();
  });

  btnInspectKey.addEventListener('click', async () => {
    await inspectHmacCalculation();
  });
}

/**
 * Send simulated webhook to /api/webhook
 */
async function fireWebhookSimulation() {
  const payloadEditor = document.getElementById('webhook-payload-editor');
  const consoleStatus = document.getElementById('console-http-status');
  const consoleOutput = document.getElementById('console-code-block');
  const integrityRadio = document.querySelector('input[name="hmac-integrity"]:checked');

  const rawPayload = payloadEditor.value;
  consoleStatus.textContent = 'STATUS: COMPUTING HMAC & TRANSMITTING...';
  consoleStatus.style.color = 'var(--color-cyan)';

  try {
    let signatureHeader = '';

    if (integrityRadio.value === 'valid') {
      // Fetch computed HMAC signature from backend helper
      const sigRes = await fetch('/api/test-hmac', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: rawPayload
      });
      const sigData = await sigRes.json();
      signatureHeader = sigData.hmac_sha256;
    } else {
      // Simulate forged or tampered signature
      signatureHeader = 'badc0de00000000000000000000000000000000000000000000000000000dead';
    }

    const t0 = performance.now();
    const response = await fetch('/api/webhook', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-supabase-signature': signatureHeader
      },
      body: rawPayload
    });

    const duration = Math.round(performance.now() - t0);
    const data = await response.json();

    if (response.status === 200) {
      consoleStatus.textContent = `STATUS: 200 OK (${duration}ms) • HMAC VALID • NIM ANALYZED`;
      consoleStatus.style.color = 'var(--color-emerald)';
    } else if (response.status === 401) {
      consoleStatus.textContent = `STATUS: 401 UNAUTHORIZED • HMAC INTEGRITY FAILED`;
      consoleStatus.style.color = 'var(--color-red)';
    } else {
      consoleStatus.textContent = `STATUS: ${response.status} (${duration}ms)`;
      consoleStatus.style.color = 'var(--color-amber)';
    }

    const telemetryReport = {
      http_status: response.status,
      latency_ms: duration,
      transport: 'HTTPS POST /api/webhook',
      cryptography: {
        algorithm: 'HMAC-SHA256',
        submitted_signature: signatureHeader,
        integrity_check: response.status === 200 ? 'PASSED (Constant-Time Match)' : 'REJECTED (Hash Mismatch / Forgery)'
      },
      endpoint_response: data
    };

    consoleOutput.textContent = JSON.stringify(telemetryReport, null, 2);

    // Refresh events feed
    await fetchEvents();

  } catch (err) {
    consoleStatus.textContent = 'STATUS: NETWORK ERROR';
    consoleStatus.style.color = 'var(--color-red)';
    consoleOutput.textContent = `Error executing request: ${err.message}`;
  }
}

/**
 * Inspect HMAC Secret & Math
 */
async function inspectHmacCalculation() {
  const consoleStatus = document.getElementById('console-http-status');
  const consoleOutput = document.getElementById('console-code-block');
  const payloadEditor = document.getElementById('webhook-payload-editor');

  try {
    const res = await fetch('/api/test-hmac', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: payloadEditor.value
    });
    const data = await res.json();
    consoleStatus.textContent = 'STATUS: HMAC INSPECTION GENERATED';
    consoleStatus.style.color = 'var(--color-nvidia)';
    consoleOutput.textContent = JSON.stringify({
      cryptographic_primitive: 'HMAC-SHA256',
      secret_source: 'process.env.WEBHOOK_SECRET',
      generated_signature: data.hmac_sha256,
      curl_test_command: data.curl_example
    }, null, 2);
  } catch (e) {
    consoleOutput.textContent = e.message;
  }
}

/**
 * Fetch and Render Events Feed & KPIs
 */
async function fetchEvents() {
  try {
    const res = await fetch('/api/events?limit=30');
    if (!res.ok) return;
    const data = await res.json();

    currentEvents = data.events || [];
    renderKPIs(data.metrics);
    renderIncidentFeed(currentEvents);
    updateModelSummary(currentEvents[0]);
  } catch (e) {
    console.error('Failed to poll events:', e);
  }
}

function renderKPIs(metrics) {
  if (!metrics) return;
  document.getElementById('kpi-total-val').textContent = (metrics.totalEvents || 0).toLocaleString();
  document.getElementById('kpi-threats-val').textContent = (metrics.threatsBlocked || 0).toLocaleString();
  
  const totalHmac = (metrics.hmacVerifiedCount || 0) + (metrics.hmacFailedCount || 0);
  const hmacRate = totalHmac > 0 ? ((metrics.hmacVerifiedCount / totalHmac) * 100).toFixed(1) + '%' : '100%';
  document.getElementById('kpi-hmac-val').textContent = hmacRate;
  document.getElementById('kpi-hmac-counts').textContent = `${metrics.hmacVerifiedCount || 0} Valid / ${metrics.hmacFailedCount || 0} Tampered`;

  // Defcon level update
  const defconEl = document.getElementById('defcon-level');
  if (metrics.currentThreatLevel === 'DEFCON_1') {
    defconEl.textContent = 'DEFCON 1 • CRITICAL ALERT';
    defconEl.style.background = 'rgba(244, 63, 94, 0.3)';
    defconEl.style.color = 'var(--color-red)';
  } else if (metrics.currentThreatLevel === 'ELEVATED') {
    defconEl.textContent = 'DEFCON 3 • ELEVATED';
    defconEl.style.background = 'rgba(245, 158, 11, 0.2)';
    defconEl.style.color = 'var(--color-amber)';
  } else {
    defconEl.textContent = 'DEFCON 5 • SECURE';
    defconEl.style.background = 'rgba(16, 185, 129, 0.2)';
    defconEl.style.color = 'var(--color-emerald)';
  }
}

function updateModelSummary(latest) {
  if (!latest || !latest.aiAnalysis) return;
  const analysis = latest.aiAnalysis;

  if (analysis.model_1_triage) {
    const v1 = document.getElementById('model1-last-verdict');
    v1.textContent = analysis.model_1_triage.threat_type || 'NORMAL';
    v1.className = `status-pill ${analysis.model_1_triage.severity === 'CRITICAL' ? 'pill-danger' : analysis.model_1_triage.severity === 'HIGH' ? 'pill-warning' : 'pill-success'}`;
  }

  if (analysis.model_2_defense) {
    const v2 = document.getElementById('model2-last-mitigation');
    v2.textContent = analysis.model_2_defense.suggested_mitigation || 'ALLOW';
    v2.className = `status-pill ${analysis.model_2_defense.risk_score_100 >= 70 ? 'pill-danger' : 'pill-warning'}`;
  }

  if (analysis.consensus_score) {
    const bar = document.getElementById('consensus-bar');
    const label = document.getElementById('consensus-percentage');
    bar.style.width = `${analysis.consensus_score}%`;
    label.textContent = `${analysis.consensus_score}% Confidence Consensus`;
  }
}

function renderIncidentFeed(events) {
  const container = document.getElementById('incident-feed-container');
  if (!events || events.length === 0) {
    container.innerHTML = '<div class="incident-empty-state">No security incidents detected.</div>';
    return;
  }

  container.innerHTML = events.map((evt, idx) => {
    const isCritical = evt.aiAnalysis?.overall_threat_level === 'CRITICAL';
    const isHigh = evt.aiAnalysis?.overall_threat_level === 'HIGH';
    const borderClass = isCritical ? 'incident-critical' : (isHigh ? 'incident-item' : 'incident-secure');
    const threatTitle = evt.aiAnalysis?.model_1_triage?.threat_type || evt.type || 'DB_TRANSACTION';
    const severity = evt.aiAnalysis?.overall_threat_level || 'SECURE';
    const hmacTag = evt.hmacValid 
      ? '<span class="hmac-badge hmac-valid">HMAC ✓ SHA256</span>'
      : '<span class="hmac-badge hmac-invalid">HMAC ✗ TAMPERED</span>';
    
    const timeFormatted = new Date(evt.timestamp).toLocaleTimeString();

    return `
      <div class="incident-item ${borderClass}" onclick="openIncidentDetails('${evt.id}')">
        <div class="incident-head">
          <span class="incident-table-tag">${evt.table}</span>
          <span class="incident-time">${timeFormatted}</span>
        </div>
        <div class="incident-details">
          <strong>${threatTitle}</strong>: ${evt.aiAnalysis?.model_1_triage?.classification_rationale || 'Query verified and logged.'}
        </div>
        <div class="incident-foot">
          <span class="status-pill ${isCritical ? 'pill-danger' : isHigh ? 'pill-warning' : 'pill-success'}">${severity}</span>
          ${hmacTag}
        </div>
      </div>
    `;
  }).join('');
}

window.openIncidentDetails = function(eventId) {
  const incident = currentEvents.find(e => e.id === eventId);
  if (!incident) return;

  const modal = document.getElementById('incident-modal');
  const modalContent = document.getElementById('modal-incident-content');

  const ai = incident.aiAnalysis || {};
  const m1 = ai.model_1_triage || {};
  const m2 = ai.model_2_defense || {};

  modalContent.innerHTML = `
    <div style="background: rgba(0,0,0,0.3); padding: 12px; border-radius: 8px;">
      <div style="font-size: 11px; color: var(--text-dim); margin-bottom: 4px;">INCIDENT ID</div>
      <div style="font-family: var(--font-mono); font-size: 13px; color: var(--color-cyan);">${incident.id}</div>
      <div style="font-size: 12px; margin-top: 6px;">Target Table: <strong>${incident.table}</strong> | Source: <strong>${incident.source}</strong></div>
    </div>

    <div>
      <h4 style="color: var(--color-cyan); margin-bottom: 8px;">1. Cryptographic HMAC-SHA256 Verification</h4>
      <div style="background: #050811; padding: 12px; border-radius: 8px; font-family: var(--font-mono); font-size: 11px;">
        <div>Status: <strong style="color: ${incident.hmacValid ? 'var(--color-emerald)' : 'var(--color-red)'};">${incident.hmacValid ? 'CRYPTOGRAPHICALLY VALID' : 'FORGERY / TAMPERED DETECTED'}</strong></div>
        <div style="margin-top: 4px; word-break: break-all;">Signature: ${incident.signature || incident.signatureProvided || 'N/A'}</div>
      </div>
    </div>

    <div>
      <h4 style="color: var(--color-cyan); margin-bottom: 8px;">2. NVIDIA NIM Model 1: meta/llama-3.1-70b-instruct</h4>
      <div style="background: #050811; padding: 12px; border-radius: 8px; font-size: 12px;">
        <div>Threat Classification: <strong style="color: var(--color-red);">${m1.threat_type || 'N/A'}</strong></div>
        <div style="margin-top: 4px;">Confidence: <strong>${((m1.confidence_score || 0) * 100).toFixed(1)}%</strong> | Severity: <strong>${m1.severity || 'LOW'}</strong></div>
        <div style="margin-top: 6px; color: #94a3b8;">${m1.classification_rationale || 'N/A'}</div>
      </div>
    </div>

    <div>
      <h4 style="color: var(--color-nvidia); margin-bottom: 8px;">3. NVIDIA NIM Model 2: meta/llama-3.1-8b-instruct</h4>
      <div style="background: #050811; padding: 12px; border-radius: 8px; font-size: 12px;">
        <div>Risk Score (CVSS): <strong style="color: var(--color-amber);">${m2.cvss_score || '0.0'} / 10.0 (Score: ${m2.risk_score_100 || 0})</strong></div>
        <div style="margin-top: 4px;">Active Mitigation: <strong>${m2.suggested_mitigation || 'N/A'}</strong></div>
        <div style="margin-top: 6px; color: #94a3b8;">${m2.containment_protocol || 'N/A'}</div>
      </div>
    </div>

    <div>
      <h4 style="color: var(--text-muted); margin-bottom: 6px;">Raw Supabase Payload</h4>
      <pre style="background: #03050a; padding: 10px; border-radius: 6px; font-family: var(--font-mono); font-size: 11px; max-height: 140px; overflow-y: auto;">${JSON.stringify(incident.rawPayload, null, 2)}</pre>
    </div>
  `;

  modal.style.display = 'flex';
};
