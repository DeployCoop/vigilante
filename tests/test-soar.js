import assert from 'node:assert';
import {
  generateQuarantineNetworkPolicy,
  isolatePod,
  freezePod,
  blockIp,
  quarantineAccount,
  listActiveContainments,
  releaseContainment
} from '../src/engine/soar.js';

async function runTests() {
  console.log('🧪 Testing SOAR & Active Containment Engine...');

  // Test 1: Quarantine NetworkPolicy Generation
  const np = generateQuarantineNetworkPolicy({
    podName: 'payment-gateway-7b98d45-zx92',
    namespace: 'tenant-prod',
    labels: { app: 'payment-gateway' }
  });

  assert(np.includes('kind: NetworkPolicy'), 'Must be a NetworkPolicy');
  assert(np.includes('name: quarantine-payment-gateway'), 'Must have quarantine name');
  assert(np.includes('policyTypes:'), 'Must specify policyTypes');
  assert(np.includes('- Ingress'), 'Must include Ingress');
  assert(np.includes('- Egress'), 'Must include Egress');
  assert(np.includes('ingress: []'), 'Ingress must be completely empty');
  assert(np.includes('egress: []'), 'Egress must be completely empty');
  console.log('✔ Test 1 passed: Zero-trust quarantine NetworkPolicy YAML generated successfully.');

  // Test 2: Isolate Pod
  const isolation = await isolatePod({
    podName: 'auth-svc-6df459-jk88',
    namespace: 'tenant-prod',
    reason: 'Suspected Cobalt Strike beacon detected'
  });

  assert(isolation.containmentId.startsWith('cont-'), 'Must have containment ID');
  assert(isolation.type === 'NETWORK_ISOLATION');
  assert(isolation.target === 'auth-svc-6df459-jk88');
  assert(isolation.policyYaml.includes('quarantine-auth-svc'), 'Policy YAML must be present');
  console.log(`✔ Test 2 passed: isolatePod created signed containment ${isolation.containmentId}.`);

  // Test 3: Freeze Pod
  const freeze = await freezePod({
    podName: 'worker-queue-99f2b-vv01',
    namespace: 'background',
    reason: 'Cryptominer process execution'
  });

  assert(freeze.type === 'CONTAINER_FREEZE');
  assert(freeze.target === 'worker-queue-99f2b-vv01');
  assert(freeze.status === 'FROZEN');
  console.log(`✔ Test 3 passed: freezePod recorded freeze action ${freeze.containmentId}.`);

  // Test 4: Block IP
  const blocked = await blockIp({
    ip: '198.51.100.23',
    reason: 'Feodo Tracker verified C2 endpoint'
  });

  assert(blocked.type === 'IP_BLOCK');
  assert(blocked.target === '198.51.100.23');
  assert(blocked.status === 'BLOCKED');
  console.log(`✔ Test 4 passed: blockIp recorded IP block ${blocked.containmentId}.`);

  // Test 5: Quarantine Account
  const account = await quarantineAccount({
    accountName: 'service-account-checkout',
    namespace: 'tenant-prod',
    reason: 'Stolen token observed in lateral movement'
  });

  assert(account.type === 'ACCOUNT_QUARANTINE');
  assert(account.target === 'service-account-checkout');
  console.log(`✔ Test 5 passed: quarantineAccount recorded account quarantine ${account.containmentId}.`);

  // Test 6: List Active Containments
  const containments = await listActiveContainments();
  assert(Array.isArray(containments));
  assert(containments.length >= 4, 'Must list all active containments');
  const found = containments.find(c => c.containmentId === isolation.containmentId);
  assert(found && found.active === true);
  console.log(`✔ Test 6 passed: listActiveContainments listed ${containments.length} active containments.`);

  // Test 7: Release Containment
  const released = await releaseContainment(isolation.containmentId);
  assert(released.success === true);
  assert(released.record.active === false);
  const updatedList = await listActiveContainments();
  const releasedEntry = updatedList.find(c => c.containmentId === isolation.containmentId);
  assert(!releasedEntry || releasedEntry.active === false);
  console.log(`✔ Test 7 passed: releaseContainment un-isolated ${isolation.containmentId} cleanly.`);

  console.log('🎉 ALL 7 SOAR CONTAINMENT TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ SOAR Engine test failed:', err);
  process.exit(1);
});
