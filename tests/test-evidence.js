import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  saveEvidenceFile,
  saveTriageBundle,
  listEvidenceVault,
  listHostEvidence,
  readEvidenceContent,
  deleteHostEvidence
} from '../src/engine/evidence.js';
import {
  getVigilanteEvidenceDir,
  getHostEvidenceDir,
  ensureVigilanteConfig
} from '../src/engine/config.js';
import { runFullTriageCapture } from '../src/engine/diagnostics.js';

async function runTests() {
  console.log('🧪 Testing Incident Response Evidence Vault & Data Collection Hierarchy (net/host/data.ext)...');

  const tempXdg = path.join(os.tmpdir(), `vigilante-evidence-test-${Math.random().toString(36).slice(2, 8)}`);
  process.env.XDG_CONFIG_HOME = tempXdg;

  try {
    await ensureVigilanteConfig();

    // Test 1: Path Resolution and Structure
    const evidenceDir = getVigilanteEvidenceDir();
    const hostDir = getHostEvidenceDir('10.0.1.0/24', '10.0.1.5');
    const expectedSuffix = path.join('evidence', '10.0.1.0_24', '10.0.1.5');
    if (!hostDir.endsWith(expectedSuffix)) {
      throw new Error(`Host evidence path incorrect: ${hostDir}, expected ending with ${expectedSuffix}`);
    }
    console.log(`✔ Test 1 passed: Resolved hierarchical evidence path: ${hostDir}`);

    // Test 2: Save individual evidence file (e.g. 10.0.1.0_24/10.0.1.5/mtr.txt)
    const savedPath = await saveEvidenceFile('10.0.1.0/24', '10.0.1.5', 'mtr.txt', '1. router.local 0.5ms\n2. target.local 1.2ms');
    const readBack = await readEvidenceContent(savedPath);
    if (!readBack.includes('router.local')) {
      throw new Error(`Failed to read back saved evidence content: ${readBack}`);
    }
    console.log('✔ Test 2 passed: saveEvidenceFile saved and verified individual artifact in net/host/data.ext.');

    // Test 3: Save complete IR Triage Bundle
    const sampleBundle = {
      ping: { success: true, minRtt: '0.04ms', avgRtt: '0.05ms' },
      mtr: 'Start: 2026-08-16\nHOST: test-gateway Loss% 0.0% Snt: 4',
      dns: { aRecords: ['10.0.1.5'], ptr: 'siem.vigilante.local' },
      tls: '-----BEGIN CERTIFICATE-----\nMIIBk...\n-----END CERTIFICATE-----',
      http: 'HTTP/1.1 200 OK\nServer: nginx/1.24.0\nStrict-Transport-Security: max-age=31536000',
      arp: '10.0.1.5 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE'
    };

    const triageRes = await saveTriageBundle('10.0.1.0/24', '10.0.1.5', sampleBundle);
    if (triageRes.artifacts.length !== 8) {
      throw new Error(`Expected 8 triage artifacts saved, got: ${triageRes.artifacts.length}`);
    }
    console.log(`✔ Test 3 passed: saveTriageBundle generated ${triageRes.artifacts.length} structured artifacts (ping, mtr, dns, tls, http, arp, summary, nist_incident_record).`);

    // Test 4: List Evidence Vault
    const vault = await listEvidenceVault();
    if (vault.length !== 1 || vault[0].networkCidr !== '10.0.1.0/24') {
      throw new Error(`Evidence vault network discovery failed: ${JSON.stringify(vault)}`);
    }
    const net = vault[0];
    if (net.hosts.length !== 1 || net.hosts[0].hostIp !== '10.0.1.5') {
      throw new Error(`Host discovery in network failed: ${JSON.stringify(net)}`);
    }
    console.log(`✔ Test 4 passed: listEvidenceVault structured hierarchy (${vault.length} networks, ${net.hosts.length} hosts, ${net.hosts[0].artifactCount} artifacts).`);

    // Test 5: List host evidence
    const hostArtifacts = await listHostEvidence('10.0.1.0/24', '10.0.1.5');
    if (hostArtifacts.length < 7) {
      throw new Error(`Expected at least 7 artifacts for host, got: ${hostArtifacts.length}`);
    }
    console.log(`✔ Test 5 passed: listHostEvidence retrieved all artifacts for host 10.0.1.5.`);

    // Test 6: Live IR Triage Execution against localhost
    const liveTriage = await runFullTriageCapture('127.0.0.1', { networkCidr: '127.0.0.0/8' });
    if (!liveTriage.success || !liveTriage.saved) {
      throw new Error(`runFullTriageCapture failed: ${JSON.stringify(liveTriage)}`);
    }
    console.log(`✔ Test 6 passed: runFullTriageCapture executed all parallel forensic probes in ${liveTriage.durationMs}ms.`);

    // Test 7: Delete host evidence
    await deleteHostEvidence('10.0.1.0/24', '10.0.1.5');
    const remaining = await listHostEvidence('10.0.1.0/24', '10.0.1.5');
    if (remaining.length !== 0) {
      throw new Error('deleteHostEvidence did not delete artifacts completely');
    }
    console.log('✔ Test 7 passed: deleteHostEvidence cleaned up host directory cleanly.');

    console.log('🎉 All Incident Response Evidence Vault tests passed successfully!');
  } finally {
    try {
      await fs.rm(tempXdg, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  }
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
