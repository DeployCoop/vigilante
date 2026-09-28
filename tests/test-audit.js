import assert from 'node:assert';
import { auditFileContent, generateSarifReport, runPipelineAudit } from '../src/engine/audit.js';

async function runTests() {
  console.log('🧪 Testing Shift-Left CI/CD Audit Engine (SARIF & Gate)...');

  // Test 1: Audit Insecure Kubernetes Manifest
  const insecureK8sYaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
  namespace: default
spec:
  replicas: 1
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: app:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
`;

  const k8sFindings = auditFileContent('deployment.yaml', insecureK8sYaml);
  assert(Array.isArray(k8sFindings) && k8sFindings.length >= 4, 'Must identify multiple vulnerabilities');
  const privHit = k8sFindings.find(f => f.ruleId === 'VIGIL-K8S-001');
  assert(privHit && privHit.severity === 'CRITICAL', 'Must flag privileged container as CRITICAL');
  const rootHit = k8sFindings.find(f => f.ruleId === 'VIGIL-K8S-002');
  assert(rootHit && rootHit.severity === 'HIGH', 'Must flag runAsUser 0 as HIGH');
  const limitsHit = k8sFindings.find(f => f.ruleId === 'VIGIL-K8S-005');
  assert(limitsHit && limitsHit.severity === 'LOW', 'Must flag missing limits');
  console.log(`✔ Test 1 passed: Insecure K8s manifest flagged with ${k8sFindings.length} violations.`);

  // Test 2: Audit Insecure Dockerfile
  const insecureDockerfile = `
FROM node:latest
USER root
RUN apt-get update && apt-get install -y sudo curl
ADD http://example.com/binary /usr/local/bin/
RUN chmod 777 /usr/local/bin/binary
CMD ["node", "server.js"]
`;

  const dockerFindings = auditFileContent('Dockerfile', insecureDockerfile);
  assert(Array.isArray(dockerFindings) && dockerFindings.length >= 3, 'Must identify Dockerfile anti-patterns');
  const userHit = dockerFindings.find(f => f.ruleId === 'VIGIL-DOCKER-001');
  assert(userHit && userHit.severity === 'HIGH', 'Must flag USER root');
  const latestHit = dockerFindings.find(f => f.ruleId === 'VIGIL-DOCKER-003');
  assert(latestHit && latestHit.severity === 'MEDIUM', 'Must flag :latest tag');
  const addHit = dockerFindings.find(f => f.ruleId === 'VIGIL-DOCKER-005');
  assert(addHit && addHit.severity === 'MEDIUM', 'Must flag ADD with remote URL');
  console.log(`✔ Test 2 passed: Insecure Dockerfile flagged with ${dockerFindings.length} violations.`);

  // Test 3: Generate SARIF v2.1.0 Report
  const allFindings = [...k8sFindings, ...dockerFindings];
  const sarif = generateSarifReport(allFindings);
  assert(sarif.version === '2.1.0');
  assert(sarif.$schema.includes('sarif-schema-2.1.0.json'));
  assert(Array.isArray(sarif.runs) && sarif.runs.length === 1);
  const run = sarif.runs[0];
  assert(run.tool.driver.name === 'vigilante-audit');
  assert(run.results.length === allFindings.length);
  assert(run.tool.driver.rules.length > 0);
  console.log(`✔ Test 3 passed: SARIF v2.1.0 report produced with ${run.results.length} results across ${run.tool.driver.rules.length} rules.`);

  // Test 4: Run Pipeline Audit with Policy Gate
  const auditResult = await runPipelineAudit('.', { failOn: 'CRITICAL' });
  assert(typeof auditResult.filesScanned === 'number');
  assert(Array.isArray(auditResult.findings));
  assert(typeof auditResult.failed === 'boolean');
  assert(typeof auditResult.summary.CRITICAL === 'number');
  assert(typeof auditResult.summary.HIGH === 'number');
  console.log(`✔ Test 4 passed: runPipelineAudit scanned ${auditResult.filesScanned} files. Gate Failed: ${auditResult.failed}.`);

  console.log('🎉 ALL 4 SHIFT-LEFT AUDIT TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Audit Engine test failed:', err);
  process.exit(1);
});
