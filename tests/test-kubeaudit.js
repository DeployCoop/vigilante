import assert from 'node:assert';
import {
  KUBEAUDIT_PROFILES,
  checkKubeAuditToolsInstalled,
  parseKubeBenchOutput,
  parseKubeHunterOutput,
  runKubeAudit,
  listSavedKubeAudits
} from '../src/engine/kubeaudit.js';

async function runTests() {
  console.log('🧪 Testing KubeAudit Engine (Kube-Bench & Kube-Hunter)...');

  // Test 1: Profiles
  assert(Array.isArray(KUBEAUDIT_PROFILES) && KUBEAUDIT_PROFILES.length >= 2);
  const kbProfile = KUBEAUDIT_PROFILES.find(p => p.id === 'kube-bench');
  assert(kbProfile && kbProfile.buildArgs().includes('--json'));
  console.log('✔ Test 1 passed: KubeAudit profiles and args builder validated.');

  // Test 2: Tool checks
  const tools = await checkKubeAuditToolsInstalled();
  assert('kubeBench' in tools && 'kubeHunter' in tools);
  console.log(`✔ Test 2 passed: Tools checked (Kube-Bench runner: ${tools.kubeBench.runner}, Kube-Hunter runner: ${tools.kubeHunter.runner}).`);

  // Test 3: Parse Kube-Bench output
  const sampleKubeBenchJson = JSON.stringify({
    Controls: [
      {
        tests: [
          {
            results: [
              {
                test_number: '1.1.1',
                test_desc: 'Ensure that the API server pod specification file permissions are set to 644 or more restrictive',
                status: 'PASS',
                scored: true
              },
              {
                test_number: '1.1.2',
                test_desc: 'Ensure that the API server pod specification file ownership is set to root:root',
                status: 'FAIL',
                remediation: 'chown root:root /etc/kubernetes/manifests/kube-apiserver.yaml',
                scored: true
              }
            ]
          }
        ]
      }
    ]
  });

  const parsedBench = parseKubeBenchOutput(sampleKubeBenchJson);
  assert.strictEqual(parsedBench.tests.length, 2);
  assert.strictEqual(parsedBench.totals.pass, 1);
  assert.strictEqual(parsedBench.totals.fail, 1);
  console.log('✔ Test 3 passed: parseKubeBenchOutput extracted tests, remediations, and pass/fail totals.');

  // Test 4: Parse Kube-Hunter output
  const sampleHunterJson = JSON.stringify({
    vulnerabilities: [
      {
        location: '10.0.0.1:10250',
        category: 'Access Control',
        severity: 'high',
        vulnerability: 'Anonymous Authentication Enabled',
        description: 'The Kubelet allows anonymous requests.'
      }
    ],
    services: [
      {
        service: 'Kubelet API',
        location: '10.0.0.1:10250'
      }
    ]
  });

  const parsedHunter = parseKubeHunterOutput(sampleHunterJson);
  assert.strictEqual(parsedHunter.vulnerabilities.length, 1);
  assert.strictEqual(parsedHunter.vulnerabilities[0].severity, 'high');
  assert.strictEqual(parsedHunter.services.length, 1);
  console.log('✔ Test 4 passed: parseKubeHunterOutput extracted cluster exposure vulnerabilities.');

  // Test 5: Run audit and check saved records
  const audit = await runKubeAudit('cluster', 'kube-bench');
  assert(audit.id && audit.filePath);
  const saved = await listSavedKubeAudits();
  assert(saved.length >= 1);
  console.log('✔ Test 5 passed: runKubeAudit ran audit, generated evidence, and listed saved records.');

  console.log('🎉 ALL 5 KUBEAUDIT TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ KubeAudit test failed:', err);
  process.exit(1);
});
