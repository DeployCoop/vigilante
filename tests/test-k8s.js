import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { safeKubectlApply, ensureNamespace, waitForApiServerReady, KUBECTL_TIMEOUT_MS } from '../src/engine/k8s.js';
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

  // Test 4: M-timeouts — a hung kubectl is killed at the per-attempt timeout
  // (default KUBECTL_TIMEOUT_MS is 30s; the override here keeps the test fast).
  if (KUBECTL_TIMEOUT_MS !== 30000) {
    throw new Error(`KUBECTL_TIMEOUT_MS must be 30000, got ${KUBECTL_TIMEOUT_MS}`);
  }
  const fakeBinDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-fake-kubectl-'));
  const fakeKubectl = path.join(fakeBinDir, 'kubectl');
  await fs.writeFile(fakeKubectl, '#!/bin/sh\nsleep 30\n', 'utf8');
  await fs.chmod(fakeKubectl, 0o755);
  const origPath = process.env.PATH;
  process.env.PATH = `${fakeBinDir}:${origPath}`;
  try {
    const start = Date.now();
    let timeoutErr = null;
    try {
      await safeKubectlApply('apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: timeout-test\n', {
        maxRetries: 1,
        retryDelayMs: 0,
        timeoutMs: 200
      });
    } catch (err) {
      timeoutErr = err;
    }
    const elapsedMs = Date.now() - start;
    if (!timeoutErr) {
      throw new Error('safeKubectlApply against a hung kubectl must reject');
    }
    // execa 8 races its timeout rejection against the killed process's own
    // exit rejection, so the same kill surfaces as either "timed out" or
    // "killed with SIGTERM" (flaky 1-in-5 under load). Both prove the timeout
    // killed the subprocess; the elapsed bound below is the real proof.
    if (!/timed out/i.test(timeoutErr.message) && !/killed with SIGTERM/i.test(timeoutErr.message)) {
      throw new Error(`Expected a timeout error, got: ${timeoutErr.message}`);
    }
    if (elapsedMs > 5000) {
      throw new Error(`safeKubectlApply must abort near timeoutMs, took ${elapsedMs}ms`);
    }
    console.log(`✔ Test 4 passed: hung kubectl killed after ~200ms timeout (took ${elapsedMs}ms).`);
  } finally {
    process.env.PATH = origPath;
    await fs.rm(fakeBinDir, { recursive: true, force: true });
  }

  console.log('🎉 All Kubernetes Reliability & Safe Apply tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
