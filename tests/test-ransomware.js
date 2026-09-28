import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {
  calculateFileEntropy,
  generateRansomwareCanaryFiles,
  detectRansomwareEncryption,
  triggerRansomwareContainment
} from '../src/engine/ransomware.js';

console.log('🧪 Testing Anti-Ransomware Canary Traps & Rapid File Entropy Monitor...');

// Setup temporary directory
const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-ransom-'));

try {
  // Test 1: calculateFileEntropy
  const plainText = Buffer.from('Normal customer database plain text record without encryption.', 'utf8');
  const plainEntropy = calculateFileEntropy(plainText);
  assert.ok(plainEntropy >= 3.0 && plainEntropy <= 4.8, `Plaintext entropy should be ~3.5-4.8, got ${plainEntropy}`);

  // Pure random/encrypted bytes (simulating AES-256 cipher output)
  const cipherBytes = crypto.randomBytes(4096);
  const cipherEntropy = calculateFileEntropy(cipherBytes);
  assert.ok(cipherEntropy >= 7.8, `Encrypted bytes should have near-maximal entropy (>7.8), got ${cipherEntropy}`);
  console.log(`✔ Test 1 passed: calculateFileEntropy evaluated plaintext (${plainEntropy}) vs encrypted ciphertext (${cipherEntropy}).`);

  // Test 2: generateRansomwareCanaryFiles
  const canaryDir = path.join(tmpDir, 'canary-trap');
  const canaryResult = await generateRansomwareCanaryFiles(canaryDir);
  assert.strictEqual(canaryResult.totalPlanted, 4);
  assert.ok(canaryResult.canaryFiles.some(f => f.fileName.endsWith('.docx')));
  assert.ok(canaryResult.canaryFiles.some(f => f.fileName.endsWith('.sql')));
  assert.ok(canaryResult.canaryFiles[0].baselineEntropy < 5.0, 'Baseline entropy must be plaintext level');
  console.log(`✔ Test 2 passed: generateRansomwareCanaryFiles successfully planted ${canaryResult.totalPlanted} canary files with baseline entropy.`);

  // Test 3: detectRansomwareEncryption - Detect rapid encryption spike
  const beforeBuffer = Buffer.from('Database record content before attack\n'.repeat(50));
  const beforeEnt = calculateFileEntropy(beforeBuffer);

  // Encrypted simulation: AES ciphertext
  const key = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const encryptedBuffer = Buffer.concat([cipher.update(beforeBuffer), cipher.final()]);

  const detection = detectRansomwareEncryption(beforeEnt, encryptedBuffer);
  assert.strictEqual(detection.isEncrypted, true);
  assert.strictEqual(detection.severity, 'CRITICAL');
  assert.strictEqual(detection.mitreTechnique, 'T1486');
  assert.ok(detection.entropyDelta > 2.0, `Entropy delta should be significant, got +${detection.entropyDelta}`);
  console.log(`✔ Test 3 passed: detectRansomwareEncryption flagged AES-256 block encryption spike (Entropy: ${detection.afterEntropy}, Δ +${detection.entropyDelta}).`);

  // Test 4: triggerRansomwareContainment
  const containment = await triggerRansomwareContainment('payment-db-0', 'tenant-prod', 1042, { apply: false });
  assert.strictEqual(containment.containmentSuccess, true);
  assert.strictEqual(containment.podName, 'payment-db-0');
  assert.strictEqual(containment.mitreTechnique, 'T1486');
  assert.ok(containment.freezeResult);
  assert.ok(containment.isolateResult);
  console.log(`✔ Test 4 passed: triggerRansomwareContainment successfully triggered emergency freeze and network isolation.`);

  console.log('🎉 All Anti-Ransomware Canary Traps & Entropy tests passed successfully!\n');
} finally {
  await fs.rm(tmpDir, { recursive: true, force: true });
}
