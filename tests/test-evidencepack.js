import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { execa } from 'execa';
import {
  generateRfc3161Timestamp,
  generateChainOfCustodyRecord,
  createEvidenceBundle,
  verifyEvidenceBundle,
  OID_SHA256,
  OID_VIGILANTE_TSA_POLICY
} from '../src/engine/evidencepack.js';

async function runTests() {
  console.log('🧪 Testing RFC 3161 Court-Admissible Evidence Bundle Exporter...');

  const tempBase = path.join(os.tmpdir(), `vigilante-bundle-test-${Date.now()}`);
  await fs.mkdir(tempBase, { recursive: true });

  // Test 1: generateRfc3161Timestamp
  const sampleHash = crypto.createHash('sha256').update('evidence payload test').digest('hex');
  const tst = generateRfc3161Timestamp(sampleHash);
  assert.strictEqual(tst.status, 0);
  assert.strictEqual(tst.tstInfo.version, 1);
  assert.strictEqual(tst.tstInfo.policy, OID_VIGILANTE_TSA_POLICY);
  assert.strictEqual(tst.tstInfo.messageImprint.hashAlgorithm, OID_SHA256);
  assert.strictEqual(tst.tstInfo.messageImprint.hashedMessage, sampleHash);
  assert.ok(tst.pemFormatted.includes('BEGIN RFC3161 TIME-STAMP TOKEN'));
  console.log('✔ Test 1 passed: generateRfc3161Timestamp created RFC 3161 TST token and PEM wrapper.');

  // Test 2: generateChainOfCustodyRecord
  const coc = generateChainOfCustodyRecord({
    caseNumber: 'CASE-2026-US-001',
    investigatorName: 'Forensic Agent Carter',
    jurisdiction: 'Federal Cyber Crimes Taskforce'
  });
  assert.strictEqual(coc.standard, 'ISO/IEC 27037:2012');
  assert.strictEqual(coc.caseNumber, 'CASE-2026-US-001');
  assert.strictEqual(coc.investigator.name, 'Forensic Agent Carter');
  console.log('✔ Test 2 passed: generateChainOfCustodyRecord synthesized ISO/IEC 27037 chain-of-custody.');

  // Test 3: createEvidenceBundle
  const mockEvidence = [
    { filename: 'memdump.raw', content: Buffer.from([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00]), type: 'MEMORY_DUMP' },
    { filename: 'traffic.pcap', content: 'PCAP_HEADER_DUMMY_DATA_STREAM', type: 'PACKET_CAPTURE' },
    { filename: 'audit_events.jsonl', content: '{"timestamp": "2026-09-28", "event": "root_shell"}\n', type: 'AUDIT_LOG' }
  ];

  const bundle = await createEvidenceBundle(
    { caseNumber: 'CASE-2026-US-001', title: 'Kubernetes Cluster Zero-Day Exploit' },
    mockEvidence,
    { outputDir: tempBase }
  );

  assert.ok(bundle.bundleDir);
  assert.strictEqual(bundle.itemCount, 3);
  assert.ok(bundle.manifestPath);
  assert.ok(bundle.verifyBashPath);
  assert.ok(bundle.verifyNodePath);
  console.log(`✔ Test 3 passed: createEvidenceBundle packaged 3 items into bundle [${bundle.bundleId}].`);

  // Test 4: verifyEvidenceBundle (Pristine)
  const verification = await verifyEvidenceBundle(bundle.bundleDir);
  assert.strictEqual(verification.valid, true);
  assert.strictEqual(verification.totalItems, 3);
  assert.strictEqual(verification.failures.length, 0);
  console.log('✔ Test 4 passed: verifyEvidenceBundle confirmed pristine cryptographic integrity.');

  // Test 5: Standalone External Verification Script Execution
  // Run `node verify_bundle.js` directly inside the bundle folder (proves court auditor can verify without Vigilante)
  const { stdout, exitCode } = await execa('node', ['verify_bundle.js'], { cwd: bundle.bundleDir });
  assert.strictEqual(exitCode, 0);
  assert.ok(stdout.includes('[✔ SUCCESS] All evidence items verified with 100% cryptographic integrity.'));
  console.log('✔ Test 5 passed: Standalone verify_bundle.js passed external court-admissibility verification.');

  // Test 6: Tamper Detection
  const tamperedFile = path.join(bundle.bundleDir, 'traffic.pcap');
  await fs.appendFile(tamperedFile, 'CORRUPTED_BYTES');
  const tamperedVerification = await verifyEvidenceBundle(bundle.bundleDir);
  assert.strictEqual(tamperedVerification.valid, false);
  assert.ok(tamperedVerification.failures.some(f => f.includes('Hash mismatch on traffic.pcap')));
  console.log('✔ Test 6 passed: verifyEvidenceBundle caught file tampering immediately.');

  // Cleanup
  await fs.rm(tempBase, { recursive: true, force: true });

  console.log('🎉 All RFC 3161 Court-Admissible Evidence Bundle Exporter tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ Evidence Pack tests failed:', err);
  process.exit(1);
});
