import assert from 'node:assert';
import {
  evaluatePodSecurityStandards,
  generateKspmScorecard,
  generateKspmReport,
  saveKspmReport
} from '../src/engine/kspm.js';

async function runTests() {
  console.log('🧪 Testing Continuous Kubernetes Security Posture Management (KSPM)...');

  // Test 1: Evaluate Pod Security Standards (PSS)
  const privilegedPod = {
    name: 'privileged-debug-pod',
    namespace: 'kube-system',
    spec: {
      hostPID: true,
      containers: [
        {
          name: 'debug',
          securityContext: {
            privileged: true,
            allowPrivilegeEscalation: true
          }
        }
      ]
    }
  };

  const pssPriv = evaluatePodSecurityStandards(privilegedPod);
  assert(pssPriv.level === 'Privileged', 'Must be classified as Privileged');
  assert(pssPriv.violations.length >= 2, 'Must have multiple violations for privileged container & hostPID');
  console.log(`✔ Test 1a passed: Privileged pod identified with level [${pssPriv.level}] and ${pssPriv.violations.length} violations.`);

  const restrictedPod = {
    name: 'secure-api-pod',
    namespace: 'production',
    spec: {
      containers: [
        {
          name: 'api',
          securityContext: {
            privileged: false,
            runAsNonRoot: true,
            readOnlyRootFilesystem: true,
            allowPrivilegeEscalation: false,
            capabilities: { drop: ['ALL'] }
          },
          resources: {
            limits: { cpu: '500m', memory: '512Mi' },
            requests: { cpu: '100m', memory: '128Mi' }
          }
        }
      ]
    }
  };

  const pssRestricted = evaluatePodSecurityStandards(restrictedPod);
  assert(pssRestricted.level === 'Restricted', 'Must be classified as Restricted');
  assert(pssRestricted.violations.length === 0, 'Restricted pod must have 0 violations');
  console.log(`✔ Test 1b passed: Hardened workload identified as [${pssRestricted.level}] with 0 violations.`);

  // Test 2: Generate KSPM Scorecard
  const scorecard = await generateKspmScorecard();
  assert(scorecard && typeof scorecard.overallScore === 'number');
  assert(scorecard.overallScore >= 0 && scorecard.overallScore <= 100);
  assert(typeof scorecard.grade === 'string');
  assert(Array.isArray(scorecard.findings));
  assert(scorecard.workloadCount > 0);
  assert(scorecard.summary && typeof scorecard.summary.pss === 'object');
  console.log(`✔ Test 2 passed: Scorecard generated: Grade [${scorecard.grade}] (${scorecard.overallScore}/100) across ${scorecard.workloadCount} workloads.`);

  // Test 3: Generate Markdown Compliance Report
  const md = generateKspmReport(scorecard);
  assert(md.includes('# 🛡️ KUBERNETES SECURITY POSTURE MANAGEMENT (KSPM) REPORT'));
  assert(md.includes('## 1. Executive Summary & Posture Grade'));
  assert(md.includes('## 2. Pod Security Standards (PSS) Distribution'));
  assert(md.includes('## 3. CIS Kubernetes Benchmark Violations & Remediation'));
  console.log('✔ Test 3 passed: Executive KSPM Markdown report rendered.');

  // Test 4: Save & Cryptographically Sign Report
  const saved = await saveKspmReport(scorecard);
  assert(saved.reportId.startsWith('kspm-'));
  assert(saved.reportPath.endsWith('.md'));
  assert(saved.scorecard.overallScore === scorecard.overallScore);
  console.log(`✔ Test 4 passed: KSPM report signed and persisted (${saved.reportId}).`);

  console.log('🎉 ALL 4 KSPM POSTURE TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ KSPM test failed:', err);
  process.exit(1);
});
