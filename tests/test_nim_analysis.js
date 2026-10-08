/**
 * Security Unit Test Suite 2: Dual NVIDIA NIM AI Threat Intelligence
 * Verifies multi-model orchestration, consensus rating, and mitigation playbook synthesis.
 */

const assert = require('assert');
const { analyzeThreatWithDualNimModels } = require('../api/nim-client');

console.log('================================================================');
console.log('⚡ TEST SUITE 2: DUAL NVIDIA NIM AI THREAT INTELLIGENCE');
console.log('================================================================');

async function runTests() {
  // Case 1: SQL Injection Attack Payload
  console.log('[TEST 1] Testing SQL Injection Attack Payload:');
  const sqliPayload = {
    table: 'users',
    type: 'INSERT',
    query: "SELECT * FROM users WHERE id = 'admin' OR '1'='1' --",
    role: 'anon'
  };

  const resSqli = await analyzeThreatWithDualNimModels(sqliPayload);
  console.log(`  Model 1 (70B Classifier): ${resSqli.model_1_triage.threat_type} (Severity: ${resSqli.model_1_triage.severity})`);
  console.log(`  Model 2 (8B Defense):     CVSS ${resSqli.model_2_defense.cvss_score} / Mitigation: ${resSqli.model_2_defense.suggested_mitigation}`);
  console.log(`  Overall Threat Level:     ${resSqli.overall_threat_level}`);
  console.log(`  Consensus Agreement:      ${resSqli.consensus_status} (${resSqli.consensus_score}%)`);

  assert.strictEqual(resSqli.overall_threat_level, 'CRITICAL', 'SQLi must be rated CRITICAL');
  assert.strictEqual(resSqli.consensus_status, 'DUAL_MODEL_AGREEMENT', 'Both models should agree');
  console.log('  ==> PASS: SQLi correctly identified as CRITICAL threat.\n');

  // Case 2: Unauthorized Privilege Escalation
  console.log('[TEST 2] Testing Privilege Escalation Payload:');
  const privPayload = {
    table: 'user_roles',
    type: 'UPDATE',
    query: "UPDATE user_roles SET role = 'superadmin' WHERE id = 'usr_anon'",
    role: 'anon'
  };

  const resPriv = await analyzeThreatWithDualNimModels(privPayload);
  console.log(`  Model 1 (70B Classifier): ${resPriv.model_1_triage.threat_type} (Severity: ${resPriv.model_1_triage.severity})`);
  console.log(`  Model 2 (8B Defense):     Risk Score: ${resPriv.model_2_defense.risk_score_100} / 100`);
  console.log(`  Overall Threat Level:     ${resPriv.overall_threat_level}`);

  assert.strictEqual(resPriv.overall_threat_level, 'HIGH', 'Privilege escalation must be rated HIGH');
  console.log('  ==> PASS: Privilege escalation accurately flagged.\n');

  // Case 3: Benign Query Activity
  console.log('[TEST 3] Testing Benign Standard Query:');
  const benignPayload = {
    table: 'user_profiles',
    type: 'UPDATE',
    query: "UPDATE user_profiles SET last_seen = NOW() WHERE id = 'usr_101'",
    role: 'authenticated'
  };

  const resBenign = await analyzeThreatWithDualNimModels(benignPayload);
  console.log(`  Model 1 (70B Classifier): ${resBenign.model_1_triage.threat_type} (Severity: ${resBenign.model_1_triage.severity})`);
  console.log(`  Overall Threat Level:     ${resBenign.overall_threat_level}`);
  console.log(`  Recommended Action:       ${resBenign.recommended_action}`);

  assert.strictEqual(resBenign.overall_threat_level, 'SECURE', 'Standard query must be SECURE');
  console.log('  ==> PASS: Benign query classified as safe.\n');

  console.log('================================================================');
  console.log('✅ ALL DUAL NVIDIA NIM THREAT INTELLIGENCE TESTS PASSED!');
  console.log('================================================================\n');
}

runTests().catch(err => {
  console.error('Test error:', err);
  process.exit(1);
});
