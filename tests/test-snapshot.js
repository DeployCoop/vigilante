import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  captureContainerVolatiles,
  captureContainerDiff,
  createForensicsSnapshot,
  verifySnapshotIntegrity,
  listSavedSnapshots
} from '../src/engine/snapshot.js';

async function runTests() {
  console.log('🧪 Testing Live Container Memory & Ephemeral Disk Snapshot Engine...');

  const tempBase = path.join(os.tmpdir(), `vigilante-snap-test-${Date.now()}`);
  const rootfsDir = path.join(tempBase, 'rootfs');
  const outputDir = path.join(tempBase, 'snapshots');
  await fs.mkdir(rootfsDir, { recursive: true });
  await fs.mkdir(outputDir, { recursive: true });

  // Create mock rootfs files
  await fs.mkdir(path.join(rootfsDir, 'tmp'), { recursive: true });
  await fs.writeFile(path.join(rootfsDir, 'tmp', 'malicious.sh'), '#!/bin/sh\nrm -rf /', 'utf8');
  await fs.writeFile(path.join(rootfsDir, 'app.conf'), 'PORT=8080\n', 'utf8');
  await fs.writeFile(path.join(rootfsDir, '.wh.old-config'), '', 'utf8'); // whiteout file

  // Test 1: captureContainerVolatiles
  const volatiles = await captureContainerVolatiles(process.pid);
  assert.ok(volatiles.pid === process.pid);
  assert.ok(Array.isArray(volatiles.openFds));
  console.log(`✔ Test 1 passed: captureContainerVolatiles captured process volatile metadata.`);

  // Test 2: captureContainerDiff
  const diff = await captureContainerDiff(rootfsDir);
  assert.strictEqual(diff.summary.totalFiles, 3);
  assert.strictEqual(diff.summary.suspiciousFiles, 1);
  const maliciousFile = diff.files.find(f => f.path.includes('malicious.sh'));
  assert.ok(maliciousFile);
  assert.strictEqual(maliciousFile.isSuspicious, true);
  assert.strictEqual(maliciousFile.sha256.length, 64);
  const whiteoutFile = diff.files.find(f => f.isWhiteout);
  assert.ok(whiteoutFile, 'Must identify .wh. whiteout file');
  console.log(`✔ Test 2 passed: captureContainerDiff identified ${diff.summary.suspiciousFiles} suspicious file and whiteout artifacts.`);

  // Test 3: createForensicsSnapshot
  const snapshotRes = await createForensicsSnapshot({
    podName: 'payment-processor-prod',
    containerId: 'c1234567890abcdef',
    pid: process.pid,
    rootfsDir
  }, { outputDir });

  assert.ok(snapshotRes.snapshotId.startsWith('snapshot-payment-processor-prod'));
  assert.strictEqual(snapshotRes.sha256Seal.length, 64);
  assert.strictEqual(snapshotRes.manifest.suspiciousFilesCount, 1);
  console.log(`✔ Test 3 passed: createForensicsSnapshot produced sealed archive with seal ${snapshotRes.sha256Seal.substring(0, 16)}...`);

  // Test 4: verifySnapshotIntegrity (Pristine)
  const verifyPristine = await verifySnapshotIntegrity(snapshotRes.snapshotDir);
  assert.strictEqual(verifyPristine.valid, true);
  assert.strictEqual(verifyPristine.expectedSeal, verifyPristine.calculatedSeal);
  console.log('✔ Test 4 passed: verifySnapshotIntegrity verified pristine bundle integrity.');

  // Test 5: verifySnapshotIntegrity (Tampered)
  const diskDiffPath = path.join(snapshotRes.snapshotDir, 'disk_diff.json');
  await fs.writeFile(diskDiffPath, '{"tampered": true}', 'utf8');
  const verifyTampered = await verifySnapshotIntegrity(snapshotRes.snapshotDir);
  assert.strictEqual(verifyTampered.valid, false, 'Tampered snapshot must fail verification');
  console.log('✔ Test 5 passed: verifySnapshotIntegrity caught modified disk diff tampering.');

  // Test 6: listSavedSnapshots
  const list = await listSavedSnapshots({ outputDir });
  assert.strictEqual(list.length, 1);
  assert.strictEqual(list[0].podName, 'payment-processor-prod');
  console.log(`✔ Test 6 passed: listSavedSnapshots retrieved ${list.length} stored container snapshot.`);

  // Cleanup
  await fs.rm(tempBase, { recursive: true, force: true });

  console.log('🎉 All Live Container Memory & Ephemeral Disk Snapshot tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ Snapshot tests failed:', err);
  process.exit(1);
});
