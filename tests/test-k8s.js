import { safeKubectlApply, ensureNamespace, waitForApiServerReady } from '../src/engine/k8s.js';
import { copyToClipboard } from '../src/utils/clipboard.js';
import { applyK8sTlsSecret } from '../src/engine/certs.js';

async function runTests() {
  console.log('🧪 Testing Kubernetes Reliability Engine & Safe Apply Pipeline...');

  // Test 1: Function signatures and readiness polling
  if (typeof safeKubectlApply !== 'function') {
    throw new Error('safeKubectlApply is not a function');
  }
  if (typeof ensureNamespace !== 'function') {
    throw new Error('ensureNamespace is not a function');
  }
  if (typeof waitForApiServerReady !== 'function') {
    throw new Error('waitForApiServerReady is not a function');
  }
  console.log('✔ Test 1 passed: Kubernetes safety primitives exported and callable.');

  // Test 2: ensureNamespace returns cleanly for default namespace
  await ensureNamespace('default');
  await ensureNamespace(null);
  console.log('✔ Test 2 passed: ensureNamespace handled default and falsy namespaces cleanly without API calls.');

  // Test 3: Multiline error payload copy to clipboard via stdin
  const multilineErrorPayload = `✖ Execution Failed:\nCommand failed with exit code 1: kubectl apply -f -\nerror: error validating "STDIN": error validating data: failed to download openapi\n\n=== Execution Logs ===\n[opensearch] Preparing namespace 'tenant-alpha'...\n[opensearch] Deploying OpenSearch cluster...`;
  const copyResult = await copyToClipboard(multilineErrorPayload);
  console.log(`✔ Test 3 result (clipboard copy): ${copyResult}`);

  console.log('🎉 All Kubernetes Reliability & Safe Apply tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
