import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  generateCanaryServiceAccount,
  generateCanarySecret,
  generateDecoyDeploymentYaml,
  detectCanaryTripped,
  triggerCanaryAlarm,
  listActiveCanaries,
  registerCanaryAsset
} from '../src/engine/deception.js';

async function runTests() {
  console.log('🧪 Testing Autonomous Deception Mesh ("Canary Kube")...');

  // Setup isolated XDG config home
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-canary-'));
  process.env.XDG_CONFIG_HOME = tempDir;

  // Test 1: Generate Canary ServiceAccount
  const saCanary = generateCanaryServiceAccount('cluster-admin-decoy', 'kube-system');
  if (!saCanary.yaml.includes('cluster-admin-decoy')) throw new Error('Canary SA manifest missing name');
  if (!saCanary.canary.tokenSignature) throw new Error('Missing tokenSignature in Canary SA');
  await registerCanaryAsset(saCanary.canary);
  console.log(`✔ Test 1 passed: Canary ServiceAccount created & registered (${saCanary.canary.id}).`);

  // Test 2: Generate Canary Secrets
  const secCanary = generateCanarySecret('aws-staging-creds', 'default', 'aws_key');
  if (!secCanary.yaml.includes('AWS_ACCESS_KEY_ID')) throw new Error('Canary Secret manifest missing AWS_ACCESS_KEY_ID');
  await registerCanaryAsset(secCanary.canary);
  console.log(`✔ Test 2 passed: Canary Secret created & registered (${secCanary.canary.id}).`);

  // Test 3: Generate Decoy Honeypot Deployment
  const decoySmb = generateDecoyDeploymentYaml('smb', { namespace: 'default' });
  if (!decoySmb.yaml.includes('decoy-smb')) throw new Error('Decoy deployment missing name');
  await registerCanaryAsset(decoySmb.canary);
  console.log(`✔ Test 3 passed: Decoy honeypot manifest generated (${decoySmb.canary.id}).`);

  // Test 4: List active canaries
  const registered = await listActiveCanaries();
  if (registered.length < 3) throw new Error(`Expected at least 3 canaries, got: ${registered.length}`);
  console.log(`✔ Test 4 passed: listActiveCanaries enumerated ${registered.length} registered assets.`);

  // Test 5: Detect Canary Tripped
  const mockAuditLogs = [
    {
      user: 'attacker-pod',
      pod: 'compromised-pod-x7',
      sourceIp: '10.42.0.77',
      requestURI: `/api/v1/namespaces/kube-system/serviceaccounts/cluster-admin-decoy`,
      verb: 'get'
    },
    {
      user: 'innocent-pod',
      pod: 'frontend-pod-1',
      sourceIp: '10.42.0.12',
      requestURI: '/api/v1/namespaces/default/pods',
      verb: 'list'
    },
    {
      user: 'exfil-script',
      pod: 'compromised-pod-x7',
      sourceIp: '10.42.0.77',
      rawPayload: `Found credential with signature: ${secCanary.canary.tokenSignature}`
    }
  ];

  const trips = detectCanaryTripped(mockAuditLogs, registered);
  if (trips.length !== 2) throw new Error(`Expected 2 tripped canaries, got: ${trips.length}`);
  console.log(`✔ Test 5 passed: detectCanaryTripped accurately flagged ${trips.length} unauthorized interactions.`);

  // Test 6: Trigger Canary Alarm and SOAR Containment
  const alarmResult = await triggerCanaryAlarm(trips[0], { autoIsolate: true });
  if (!alarmResult.alarmId) throw new Error('Missing alarmId in alarmResult');
  if (alarmResult.verdict !== 'HIGH_FIDELITY_INTRUSION_DETECTED') throw new Error('Unexpected verdict');
  if (!alarmResult.soarAction || alarmResult.soarAction.status !== 'CONTAINED') {
    throw new Error('Expected SOAR active containment to isolate offending pod');
  }
  console.log(`✔ Test 6 passed: triggerCanaryAlarm executed SOAR containment (${alarmResult.soarAction.containmentId}).`);

  console.log('🎉 ALL 6 DECEPTION MESH TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Deception test failure:', err);
  process.exit(1);
});
