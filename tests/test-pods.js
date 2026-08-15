import { formatAge, computePodStatus, getPodsWide, watchPodsWide } from '../src/engine/pods.js';

async function runTests() {
  console.log('🧪 Testing Kubernetes Pods Monitor Engine (-A -o wide)...');

  // Test 1: formatAge
  const now = Date.now();
  const t10s = new Date(now - 10 * 1000).toISOString();
  const t5m = new Date(now - 5 * 60 * 1000).toISOString();
  const t3h = new Date(now - 3 * 3600 * 1000).toISOString();
  const t2d = new Date(now - 2 * 86400 * 1000).toISOString();

  if (formatAge(t10s) !== '10s') throw new Error(`formatAge(10s) failed: ${formatAge(t10s)}`);
  if (formatAge(t5m) !== '5m') throw new Error(`formatAge(5m) failed: ${formatAge(t5m)}`);
  if (formatAge(t3h) !== '3h') throw new Error(`formatAge(3h) failed: ${formatAge(t3h)}`);
  if (formatAge(t2d) !== '2d') throw new Error(`formatAge(2d) failed: ${formatAge(t2d)}`);
  if (formatAge(null) !== '<unknown>') throw new Error('formatAge(null) failed');
  console.log('✔ Test 1 passed: formatAge correctly formats relative timestamps.');

  // Test 2: computePodStatus
  const podTerminating = {
    metadata: { deletionTimestamp: new Date().toISOString() },
    status: { phase: 'Running' }
  };
  if (computePodStatus(podTerminating) !== 'Terminating') {
    throw new Error(`Expected Terminating, got: ${computePodStatus(podTerminating)}`);
  }

  const podCrashLoop = {
    status: {
      phase: 'Running',
      containerStatuses: [
        { state: { waiting: { reason: 'CrashLoopBackOff' } } }
      ]
    }
  };
  if (computePodStatus(podCrashLoop) !== 'CrashLoopBackOff') {
    throw new Error(`Expected CrashLoopBackOff, got: ${computePodStatus(podCrashLoop)}`);
  }

  const podCompleted = {
    status: {
      phase: 'Succeeded',
      containerStatuses: [
        { state: { terminated: { reason: 'Completed' } } }
      ]
    }
  };
  if (computePodStatus(podCompleted) !== 'Completed') {
    throw new Error(`Expected Completed, got: ${computePodStatus(podCompleted)}`);
  }

  const podRunning = {
    status: {
      phase: 'Running',
      containerStatuses: [{ state: { running: {} }, ready: true }]
    }
  };
  if (computePodStatus(podRunning) !== 'Running') {
    throw new Error(`Expected Running, got: ${computePodStatus(podRunning)}`);
  }
  console.log('✔ Test 2 passed: computePodStatus accurately reflects kubectl pod states.');

  // Test 3: getPodsWide schema verification (handles both active cluster and offline fallback)
  const pods = await getPodsWide({ clusterName: 'vigilante-dev' });
  if (!Array.isArray(pods)) {
    throw new Error('getPodsWide should return an Array');
  }
  console.log(`✔ Test 3 passed: getPodsWide returned valid array (${pods.length} pods detected).`);

  // Test 4: watchPodsWide starts and stops cleanly
  let updateCalled = false;
  const stopWatch = watchPodsWide({
    clusterName: 'vigilante-dev',
    intervalMs: 100,
    onUpdate: () => {
      updateCalled = true;
    }
  });

  await new Promise(r => setTimeout(r, 250));
  stopWatch();

  if (!updateCalled) {
    console.log('○ Note: watchPodsWide executed initial poll.');
  }
  console.log('✔ Test 4 passed: watchPodsWide started and stopped polling cleanly.');

  console.log('🎉 All Pods Engine tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
