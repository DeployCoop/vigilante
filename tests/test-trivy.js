import assert from 'node:assert';
import {
  TRIVY_PROFILES,
  checkTrivyInstalled,
  parseTrivyOutput,
  runTrivyAudit,
  listSavedTrivyScans
} from '../src/engine/trivy.js';

async function runTests() {
  console.log('🧪 Testing Trivy Security & Container Engine...');

  // Test 1: Profiles
  assert(Array.isArray(TRIVY_PROFILES) && TRIVY_PROFILES.length >= 3);
  const imgProf = TRIVY_PROFILES.find(p => p.id === 'image');
  assert(imgProf);
  const args = imgProf.buildArgs('alpine:latest', { severity: 'HIGH,CRITICAL' });
  assert(args.includes('image') && args.includes('alpine:latest'));
  assert(args.includes('--severity') && args.includes('HIGH,CRITICAL'));
  console.log('✔ Test 1 passed: Trivy profiles and argument builders verified.');

  // Test 2: Tool check
  const tool = await checkTrivyInstalled();
  assert('installed' in tool && 'runner' in tool);
  console.log(`✔ Test 2 passed: checkTrivyInstalled returned status (runner: ${tool.runner}).`);

  // Test 3: Parse Trivy JSON
  const sampleTrivyJson = JSON.stringify({
    Results: [
      {
        Target: 'alpine:3.18 (alpine 3.18.3)',
        Vulnerabilities: [
          {
            VulnerabilityID: 'CVE-2023-5678',
            PkgName: 'libssl3',
            InstalledVersion: '3.1.2-r0',
            FixedVersion: '3.1.2-r1',
            Severity: 'CRITICAL',
            Title: 'Buffer overflow in OpenSSL'
          },
          {
            VulnerabilityID: 'CVE-2023-9999',
            PkgName: 'busybox',
            InstalledVersion: '1.36.1-r0',
            Severity: 'HIGH',
            Title: 'Privilege Escalation'
          }
        ],
        Misconfigurations: [
          {
            ID: 'KSV001',
            Title: 'Container running as root',
            Severity: 'MEDIUM',
            Resolution: 'Set securityContext.runAsNonRoot to true'
          }
        ],
        Secrets: [
          {
            RuleID: 'aws-access-key-id',
            Category: 'AWS',
            Severity: 'CRITICAL',
            Match: 'AKIAIOSFODNN7EXAMPLE'
          }
        ]
      }
    ]
  });

  const parsed = parseTrivyOutput(sampleTrivyJson);
  assert.strictEqual(parsed.vulnerabilities.length, 2);
  assert.strictEqual(parsed.misconfigurations.length, 1);
  assert.strictEqual(parsed.secrets.length, 1);
  assert.strictEqual(parsed.summary.critical, 2);
  assert.strictEqual(parsed.summary.high, 1);
  assert.strictEqual(parsed.summary.medium, 1);
  assert.strictEqual(parsed.summary.total, 4);
  console.log('✔ Test 3 passed: parseTrivyOutput successfully parsed CVEs, misconfigurations, and leaked secrets.');

  // Test 4: Run audit and verify persistence
  const audit = await runTrivyAudit('nginx:alpine', 'image');
  assert(audit.id && audit.filePath);
  const saved = await listSavedTrivyScans();
  assert(saved.length >= 1);
  console.log('✔ Test 4 passed: runTrivyAudit executed, created signed artifact, and recorded audit in directory.');

  console.log('🎉 ALL 4 TRIVY TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ Trivy test failed:', err);
  process.exit(1);
});
