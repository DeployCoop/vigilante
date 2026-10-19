import assert from 'node:assert';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';
import {
  detectK3sAvailability,
  resolveKubeContext,
  getClusterContext,
  getClusterContextArgs,
  createCluster,
  deleteCluster,
  listClusters
} from '../packages/vigilante_lib/src/engine/cluster.js';
import { checkPrereqs } from '../packages/vigilante_lib/src/engine/prereqs.js';
import {
  saveInstanceMetadata,
  loadInstanceMetadata,
  listInstances,
  deleteInstance
} from '../packages/vigilante_lib/src/engine/instances.js';

async function run() {
  console.log('🧪 Testing K3S / K3D Cluster Provider Engine...');

  // Test 1: detectK3sAvailability schema
  const detection = await detectK3sAvailability();
  assert(typeof detection === 'object', 'detectK3sAvailability should return an object');
  assert(typeof detection.available === 'boolean', 'available must be boolean');
  assert(typeof detection.hasK3sBinary === 'boolean', 'hasK3sBinary must be boolean');
  assert(typeof detection.hasK3sKubeconfig === 'boolean', 'hasK3sKubeconfig must be boolean');
  assert(typeof detection.serviceActive === 'boolean', 'serviceActive must be boolean');
  assert(typeof detection.kubectlK3sConnected === 'boolean', 'kubectlK3sConnected must be boolean');
  console.log(`✔ Test 1 passed: detectK3sAvailability returned valid detection state (available: ${detection.available}).`);

  // Test 2: getClusterContext string resolver
  assert.strictEqual(getClusterContext('prod-soc', 'k3s'), 'k3s-prod-soc');
  assert.strictEqual(getClusterContext('prod-soc', 'k3d'), 'k3d-prod-soc');
  assert.strictEqual(getClusterContext('prod-soc'), 'k3d-prod-soc');
  console.log('✔ Test 2 passed: getClusterContext correctly formats context names per provider.');

  // Test 3: resolveKubeContext
  const k3dCtx = await resolveKubeContext('vigilante-dev', 'k3d');
  assert.strictEqual(k3dCtx, 'k3d-vigilante-dev');
  const k3sCtx = await resolveKubeContext('vigilante-dev', 'k3s');
  assert(typeof k3sCtx === 'string' || k3sCtx === null, 'resolveKubeContext for k3s returned string or null');
  console.log(`✔ Test 3 passed: resolveKubeContext resolved contexts (k3d: ${k3dCtx}, k3s: ${k3sCtx}).`);

  // Test 4: getClusterContextArgs
  const k3dArgs = await getClusterContextArgs('vigilante-dev', 'k3d');
  assert(Array.isArray(k3dArgs), 'getClusterContextArgs must return array');
  const k3sArgs = await getClusterContextArgs('vigilante-dev', 'k3s');
  assert(Array.isArray(k3sArgs), 'getClusterContextArgs for k3s must return array');
  console.log('✔ Test 4 passed: getClusterContextArgs returns valid argv arrays.');

  // Test 5: checkPrereqs ignores docker and k3d when provider === 'k3s'
  const k3sPrereqs = await checkPrereqs({ provider: 'k3s' });
  const hasDockerInK3s = k3sPrereqs.tools.some(t => t.id === 'docker');
  const hasK3dInK3s = k3sPrereqs.tools.some(t => t.id === 'k3d');
  const hasK3sInK3s = k3sPrereqs.tools.some(t => t.id === 'k3s');
  assert(!hasDockerInK3s, 'Docker should not be a prerequisite for k3s provider');
  assert(!hasK3dInK3s, 'k3d should not be a prerequisite for k3s provider');
  assert(hasK3sInK3s, 'k3s tool should be checked when provider is k3s');
  console.log('✔ Test 5 passed: checkPrereqs({ provider: "k3s" }) filters out Docker and k3d requirements.');

  // Test 6: Instance metadata with provider: 'k3s'
  const testDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-k3s-test-'));
  const originalConfigHome = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = testDir;

  try {
    await saveInstanceMetadata('k3s-edge', {
      clusterName: 'edge-cluster',
      provider: 'k3s',
      domain: 'edge.local',
      ip: '10.0.0.15'
    });

    const meta = await loadInstanceMetadata('k3s-edge');
    assert.strictEqual(meta.provider, 'k3s', 'Instance metadata must preserve provider');
    assert.strictEqual(meta.clusterName, 'edge-cluster');

    const instances = await listInstances();
    const found = instances.find(i => i.instanceName === 'k3s-edge');
    assert(found, 'listInstances must find saved k3s instance');
    assert.strictEqual(found.provider, 'k3s', 'listInstances entry must have provider: k3s');

    await deleteInstance('k3s-edge', { deleteCluster: false });
    const afterDelete = await listInstances();
    assert(!afterDelete.some(i => i.instanceName === 'k3s-edge'), 'Instance deleted cleanly');
    console.log('✔ Test 6 passed: Instance engine correctly persists, lists, and manages provider: "k3s".');
  } finally {
    process.env.XDG_CONFIG_HOME = originalConfigHome;
    await fs.rm(testDir, { recursive: true, force: true });
  }

  // Test 7: deleteCluster for non-existent k3s cluster
  const delRes = await deleteCluster('non-existent-cluster', { provider: 'k3s' });
  assert.strictEqual(delRes.provider, 'k3s');
  assert.strictEqual(delRes.status, 'deleted');
  console.log('✔ Test 7 passed: deleteCluster with provider: "k3s" handles clean deletion.');

  console.log('🎉 All K3S / K3D Cluster Provider tests passed successfully!');
}

run().catch((err) => {
  console.error('❌ Test failed:', err);
  process.exit(1);
});
