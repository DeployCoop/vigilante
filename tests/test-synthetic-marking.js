import assert from 'node:assert';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

console.log('🧪 Testing synthetic-result marking: kubeaudit, nuclei, zap, openvas (D19)...');

const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-synthetic-'));
process.env.XDG_CONFIG_HOME = tmpRoot;

const { runKubeAudit } = await import('../src/engine/kubeaudit.js');
const { runNucleiScan } = await import('../src/engine/nuclei.js');
const { runZapScan } = await import('../src/engine/zap.js');
const { generateVulnerabilityFindings, runHostVulnerabilityScan } = await import('../src/engine/openvas.js');

// Test 1 (D19): kube-bench without a host runner must not fabricate PASSes,
// and the persisted (signed/evidence) record must be marked synthetic
{
  const res = await runKubeAudit('cluster', 'kube-bench');
  assert.strictEqual(res.synthetic, true, 'Non-host kube-bench record must be marked synthetic');
  assert.strictEqual(res.runner, 'none');
  assert.strictEqual(res.totals.pass, 0, 'A fabricated PASS total is the D19 defect');
  assert.strictEqual(res.totals.unknown, 2);
  assert.ok(res.tests.every(t => t.status === 'UNKNOWN'), 'Synthetic checks are UNKNOWN, never PASS');
  const saved = JSON.parse(await fs.readFile(res.filePath, 'utf8'));
  assert.strictEqual(saved.synthetic, true, 'The record on disk carries the marking');
  assert.strictEqual(saved.totals.pass, 0);
}
console.log('✔ Test 1 passed: Kube-bench fallback reports UNKNOWN and the saved record is marked synthetic (D19).');

// Test 2 (D19): the kube-hunter fallback record is marked synthetic too
{
  const res = await runKubeAudit('cluster', 'kube-hunter');
  assert.strictEqual(res.synthetic, true);
  assert.strictEqual(res.runner, 'none');
}
console.log('✔ Test 2 passed: Kube-hunter fallback record is marked synthetic (D19).');

// Test 3 (D19): nuclei emulation fallback is marked on the record
{
  const scan = await runNucleiScan('http://localhost:8080', 'cves');
  assert.strictEqual(scan.synthetic, true, 'Emulation findings must not look like scanner output');
  assert.strictEqual(scan.runner, 'none');
  const saved = JSON.parse(await fs.readFile(scan.filePath, 'utf8'));
  assert.strictEqual(saved.synthetic, true);
}
console.log('✔ Test 3 passed: Nuclei emulation record is marked synthetic with runner none (D19).');

// Test 4 (D19): ZAP emulation alerts are retained but the record is marked
{
  const scan = await runZapScan('http://127.0.0.1:9', 'spider', { zapBaseUrl: 'http://127.0.0.1:1' });
  assert.strictEqual(scan.synthetic, true);
  assert.strictEqual(scan.runner, 'none');
  assert.strictEqual(scan.zapReachable, false);
  assert.ok(scan.alerts.length > 0, 'Fallback alerts remain available, now honestly labeled');
  const saved = JSON.parse(await fs.readFile(scan.filePath, 'utf8'));
  assert.strictEqual(saved.synthetic, true);
}
console.log('✔ Test 4 passed: ZAP emulation record is marked synthetic (D19).');

// Test 5 (D19): OpenVAS heuristic findings are each marked, and the scan
// result declares its findings source
{
  const findings = generateVulnerabilityFindings({ ip: '192.0.2.5', ports: [{ port: 443 }, { port: 22 }] });
  assert.ok(findings.length > 0, 'Port-based evaluator still produces its findings');
  assert.ok(findings.every(f => f.synthetic === true), 'Every generated finding is marked synthetic');

  const result = await runHostVulnerabilityScan({
    host: { ip: '192.0.2.5', ports: [{ port: 443 }, { port: 22 }] },
    profile: 'full-and-fast',
    networkTarget: 'test_network'
  });
  assert.strictEqual(result.synthetic, true);
  assert.strictEqual(result.findingsSource, 'heuristic-port-evaluation');
  assert.ok(result.findings.every(f => f.synthetic === true));
}
console.log('✔ Test 5 passed: OpenVAS results declare heuristic provenance, findings marked (D19).');

console.log('\n🎉 All synthetic-marking tests passed successfully!\n');
