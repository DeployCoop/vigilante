import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  generatePatchForFinding,
  generateUnifiedDiff,
  applyPatchToFile,
  generateRemediationPrScript
} from '../src/engine/remediation.js';

async function runTests() {
  console.log('🧪 Testing Self-Healing Auto-Remediator ("Auto-Patch Engine")...');

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-remediation-'));

  // Test 1: Patch Insecure Kubernetes Manifest
  const insecureK8s = `
apiVersion: v1
kind: Pod
metadata:
  name: vulnerable-webapp
spec:
  containers:
  - name: web
    image: nginx:latest
`;

  const finding1 = { ruleId: 'VIGIL-K8S-004', message: 'Container missing resource limits' };
  const res1 = generatePatchForFinding(finding1, insecureK8s, 'k8s');
  if (!res1.modified) throw new Error('Expected Kubernetes manifest to be modified');
  if (!res1.patchedContent.includes('limits:')) throw new Error('Missing injected limits in patched YAML');
  if (!res1.patchedContent.includes('readOnlyRootFilesystem: true')) throw new Error('Missing injected securityContext in patched YAML');
  if (!res1.patchedContent.includes('@sha256:')) throw new Error('Expected latest image to be pinned to SHA256 digest');
  console.log('✔ Test 1 passed: Kubernetes manifest auto-patched (resources, securityContext, image digest).');

  // Test 2: Patch Insecure Dockerfile
  const insecureDocker = `
FROM node:latest
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
`;

  const finding2 = { ruleId: 'VIGIL-DOCKER-003', message: 'Dockerfile runs as root' };
  const res2 = generatePatchForFinding(finding2, insecureDocker, 'dockerfile');
  if (!res2.modified) throw new Error('Expected Dockerfile to be modified');
  if (!res2.patchedContent.includes('USER 10001:10001')) throw new Error('Missing USER instruction in Dockerfile');
  if (!res2.patchedContent.includes('@sha256:')) throw new Error('Expected node:latest base image to be pinned');
  console.log('✔ Test 2 passed: Dockerfile auto-patched (non-root USER, pinned base image).');

  // Test 3: Generate Unified Diff
  const diff = generateUnifiedDiff(insecureDocker, res2.patchedContent, 'Dockerfile');
  if (!diff.includes('--- a/Dockerfile') || !diff.includes('+ USER 10001:10001')) {
    throw new Error('Invalid unified diff generation');
  }
  console.log('✔ Test 3 passed: Unified diff generated successfully.');

  // Test 4: Apply Patch To Disk with Backup
  const targetFile = path.join(tempDir, 'Dockerfile');
  await fs.writeFile(targetFile, insecureDocker, 'utf8');

  const applyRes = await applyPatchToFile(targetFile, res2.patchedContent, { backup: true });
  if (!applyRes.applied) throw new Error('Failed to apply patch to file');
  const diskContent = await fs.readFile(targetFile, 'utf8');
  if (!diskContent.includes('USER 10001:10001')) throw new Error('Patched content was not written to disk');
  const backupContent = await fs.readFile(applyRes.backupPath, 'utf8');
  if (backupContent !== insecureDocker) throw new Error('Backup content did not match original');
  console.log(`✔ Test 4 passed: Patch applied to disk with backup verified (${applyRes.backupPath}).`);

  // Test 5: Generate PR Script
  const prScript = generateRemediationPrScript([targetFile], 'fix-security-holes');
  if (!prScript.includes('BRANCH_NAME="fix-security-holes"') || !prScript.includes('git commit')) {
    throw new Error('Invalid PR shell script');
  }
  console.log('✔ Test 5 passed: Git PR shell script generated.');

  console.log('🎉 ALL 5 AUTO-REMEDIATION TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Auto-remediation test failure:', err);
  process.exit(1);
});
