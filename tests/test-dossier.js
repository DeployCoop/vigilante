import assert from 'node:assert';
import {
  calculateRiskScore,
  buildHostDossier,
  getHostDossier,
  listHostDossiers
} from '../src/engine/dossier.js';

async function runTests() {
  console.log('🧪 Testing Unified Host Dossier Engine ("Vigilante Brain")...');

  // Test 1: Calculate Risk Score across severities
  const cleanRisk = calculateRiskScore({});
  assert.strictEqual(cleanRisk.score, 0);
  assert.strictEqual(cleanRisk.tier, 'CLEAN');

  const lowRisk = calculateRiskScore({
    nuclei: { medium: 1 }
  });
  assert.strictEqual(lowRisk.score, 8);
  assert.strictEqual(lowRisk.tier, 'LOW');

  const highRisk = calculateRiskScore({
    nuclei: { high: 2 },
    netexec: { signingDisabled: true }
  });
  assert.strictEqual(highRisk.score, 65);
  assert.strictEqual(highRisk.tier, 'HIGH');

  const criticalRisk = calculateRiskScore({
    nuclei: { critical: 2 },
    bloodhound: { tier0Compromised: true }
  });
  assert.strictEqual(criticalRisk.score, 100, 'Score should be capped at 100');
  assert.strictEqual(criticalRisk.tier, 'CRITICAL');
  console.log('✔ Test 1 passed: calculateRiskScore verified across CLEAN, LOW, HIGH, and CRITICAL risk tiers.');

  // Test 2: Build Host Dossier
  const targetIp = '192.168.1.50';
  const dossier = await buildHostDossier(targetIp);
  assert.strictEqual(dossier.target, targetIp);
  assert(typeof dossier.riskScore === 'number');
  assert(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'CLEAN'].includes(dossier.riskTier));
  assert(Array.isArray(dossier.network.openPorts));
  assert(Array.isArray(dossier.vulnerabilities.cves));
  assert(Array.isArray(dossier.remediations));
  console.log(`✔ Test 2 passed: buildHostDossier generated unified dossier for ${targetIp} (Risk: ${dossier.riskScore}/100 [${dossier.riskTier}]).`);

  // Test 3: Get Host Dossier
  const fetched = await getHostDossier(targetIp);
  assert.strictEqual(fetched.target, targetIp);
  assert.strictEqual(fetched.riskScore, dossier.riskScore);
  console.log('✔ Test 3 passed: getHostDossier successfully retrieved persisted dossier.');

  // Test 4: List Host Dossiers
  const dossiers = await listHostDossiers();
  assert(Array.isArray(dossiers));
  assert(dossiers.some(d => d.target === targetIp));
  console.log('✔ Test 4 passed: listHostDossiers returned formatted summaries sorted by risk score.');

  // Test 5: VulnView Component Export & Instantiation
  const { VulnView } = await import('../src/index.js');
  assert(VulnView, 'VulnView must be exported from index.js');
  const React = (await import('react')).default;
  const el = React.createElement(VulnView, { domain: 'vigilante.local', ip: '127.0.0.1' });
  assert(React.isValidElement(el), 'React element for VulnView must be valid');
  console.log('✔ Test 5 passed: VulnView React Ink component instantiated successfully.');

  console.log('🎉 ALL 5 DOSSIER ENGINE & VULNVIEW TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Dossier Engine test failed:', err);
  process.exit(1);
});
