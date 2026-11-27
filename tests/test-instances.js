import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  ensureInstanceDirs,
  saveInstanceMetadata,
  loadInstanceMetadata,
  listInstances,
  deleteInstance,
  getInstanceWriteChainCount
} from '../src/engine/instances.js';
import {
  getVigilanteInstancesDir,
  getInstanceDir,
  getInstanceCertsDir,
  getInstanceValuesDir,
  getInstanceLogsDir,
  ensureVigilanteConfig
} from '../src/engine/config.js';
import { setupCertificates, checkCertificates } from '../src/engine/certs.js';

async function runTests() {
  console.log('🧪 Testing Multi-Instance k3d Orchestration & Instance Isolation Engine...');

  const tempXdg = path.join(os.tmpdir(), `vigilante-instances-test-${Math.random().toString(36).slice(2, 8)}`);
  process.env.XDG_CONFIG_HOME = tempXdg;

  try {
    await ensureVigilanteConfig();

    // Test 1: Verify instance directory structure in XDG_CONFIG_HOME
    const instancesDir = getVigilanteInstancesDir();
    const inst1Dir = getInstanceDir('soc-prod');
    const certsDir = getInstanceCertsDir('soc-prod');
    const valuesDir = getInstanceValuesDir('soc-prod');
    const logsDir = getInstanceLogsDir('soc-prod');

    if (!certsDir.includes(path.join('instances', 'soc-prod', 'certs'))) {
      throw new Error(`Instance certs dir resolved incorrectly: ${certsDir}`);
    }
    console.log(`✔ Test 1 passed: Resolved instance directories in XDG: ${inst1Dir}`);

    // Test 2: Ensure directories created for multiple instances
    await ensureInstanceDirs('soc-prod');
    await ensureInstanceDirs('soc-dev');
    await ensureInstanceDirs('custom-cluster-1');

    const created1 = await fs.access(certsDir).then(() => true).catch(() => false);
    const created2 = await fs.access(getInstanceCertsDir('soc-dev')).then(() => true).catch(() => false);
    if (!created1 || !created2) {
      throw new Error('Failed to create instance directories on disk');
    }
    console.log('✔ Test 2 passed: Successfully created isolated instance directories for multiple clusters.');

    // Test 3: Metadata persistence per instance
    await saveInstanceMetadata('soc-prod', {
      clusterName: 'soc-prod',
      domain: 'soc-prod.vigilante.local',
      ip: '127.0.0.1',
      httpPort: 8080,
      httpsPort: 8443,
      modules: ['opensearch', 'vigil-soc']
    });

    const meta = await loadInstanceMetadata('soc-prod');
    if (!meta || meta.domain !== 'soc-prod.vigilante.local' || meta.httpPort !== 8080) {
      throw new Error(`Instance metadata mismatch: ${JSON.stringify(meta)}`);
    }
    console.log('✔ Test 3 passed: saveInstanceMetadata & loadInstanceMetadata persisted instance configuration.');

    // Test 4: Verify certificate creation inside instance directory (and not /.certs or cwd/.certs)
    // Check certificate existence in instance
    const check1 = await checkCertificates('soc-prod.vigilante.local', { instanceName: 'soc-prod' });
    if (check1.exists) {
      throw new Error('Certificates should not exist before creation');
    }
    if (!check1.certDir.includes('soc-prod')) {
      throw new Error(`checkCertificates certDir should point to instance dir: ${check1.certDir}`);
    }
    console.log(`✔ Test 4 passed: checkCertificates resolved target to instance directory: ${check1.certDir}`);

    // Test 5: List all instances
    const allInstances = await listInstances();
    if (allInstances.length < 3) {
      throw new Error(`Expected at least 3 instances, got: ${allInstances.length}`);
    }
    const foundProd = allInstances.find(i => i.instanceName === 'soc-prod');
    if (!foundProd || foundProd.httpPort !== 8080) {
      throw new Error(`Instance list did not find soc-prod: ${JSON.stringify(allInstances)}`);
    }
    console.log(`✔ Test 5 passed: listInstances discovered ${allInstances.length} configured cluster instances.`);

    // Test 6: Delete instance cleanly
    await deleteInstance('custom-cluster-1', { deleteCluster: false });
    const remainingInstances = await listInstances();
    if (remainingInstances.some(i => i.instanceName === 'custom-cluster-1')) {
      throw new Error('deleteInstance failed to remove custom-cluster-1 directory');
    }
    console.log('✔ Test 6 passed: deleteInstance removed instance directory cleanly.');

    // Test 7: M-instances — instance.json writes are atomic and the write
    // chain drains (no torn file, no leftover tmp, no leaked chain keys).
    // The two soc-prod saves run concurrently: the second must merge onto
    // the first's result (notes preserved), not onto the pre-save state.
    await Promise.all([
      saveInstanceMetadata('soc-prod', { httpPort: 8081, notes: 'x'.repeat(100000) }),
      saveInstanceMetadata('soc-prod', { httpPort: 8082 }),
      saveInstanceMetadata('soc-dev', { httpPort: 9090 })
    ]);
    const saved = await loadInstanceMetadata('soc-prod');
    if (!saved || saved.httpPort !== 8082 || saved.notes !== 'x'.repeat(100000)) {
      throw new Error(`Concurrent saves lost data or tore the file: ${JSON.stringify(saved)?.slice(0, 120)}`);
    }
    const dirEntries = await fs.readdir(getInstanceDir('soc-prod'));
    if (dirEntries.some((e) => e.startsWith('instance.json.tmp-'))) {
      throw new Error(`Atomic write left a tmp file behind: ${dirEntries.join(', ')}`);
    }
    if (getInstanceWriteChainCount() !== 0) {
      throw new Error(`Write chains must drain to 0 after writers settle, got ${getInstanceWriteChainCount()}`);
    }
    console.log('✔ Test 7 passed: instance.json writes atomic, no tmp leftovers, write chains drained.');

    // Test 8: M-instances — deleteInstance serializes with writers: a save
    // that starts before the delete cannot resurrect the instance dir (or
    // throw ENOENT when the delete removes the dir mid-write). The 5MB
    // payload makes the save slow enough that the race is deterministic
    // without the lock.
    const slowSave = saveInstanceMetadata('soc-dev', { httpPort: 9091, notes: 'y'.repeat(5000000) });
    const del = deleteInstance('soc-dev', { deleteCluster: false });
    await Promise.all([slowSave, del]);
    const afterDelete = await listInstances();
    if (afterDelete.some((i) => i.instanceName === 'soc-dev')) {
      throw new Error('deleteInstance raced a concurrent save and the instance was resurrected');
    }
    console.log('✔ Test 8 passed: deleteInstance serialized with writers; no resurrection.');

    console.log('🎉 All Multi-Instance & Instance Isolation tests passed successfully!');
  } finally {
    try {
      await fs.rm(tempXdg, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  }
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
