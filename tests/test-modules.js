import path from 'node:path';
import fs from 'node:fs/promises';
import { ModuleRegistry, globalModuleRegistry } from '../src/modules/registry.js';
import { getDomainHosts } from '../src/engine/hosts.js';

async function runTests() {
  console.log('🧪 Testing Modules System & Dependency Resolver...');

  // Test 1: Global registry default modules
  const allModules = globalModuleRegistry.getAll();
  const ids = allModules.map(m => m.id);

  if (!ids.includes('opensearch') || !ids.includes('vigil-soc') || !ids.includes('kctf') || !ids.includes('openvas') || !ids.includes('wazuh') || !ids.includes('flamingo') || !ids.includes('falco') || !ids.includes('suricata') || !ids.includes('zeek') || !ids.includes('zap') || !ids.includes('bloodhound')) {
    throw new Error(`Expected default modules, got: ${JSON.stringify(ids)}`);
  }
  console.log('✔ Test 1 passed: Default modules registered in globalModuleRegistry.');

  // Test 2: Dependency resolution
  const resolved = globalModuleRegistry.resolveModules(['vigil-soc']);
  const resolvedIds = resolved.map(m => m.id);

  if (resolvedIds[0] !== 'opensearch' || resolvedIds[1] !== 'vigil-soc') {
    throw new Error(`Expected ['opensearch', 'vigil-soc'] in dependency order, got: ${JSON.stringify(resolvedIds)}`);
  }
  console.log('✔ Test 2 passed: Dependency resolution ordered opensearch before vigil-soc.');

  const wazuhOnly = globalModuleRegistry.resolveModules(['wazuh']).map(m => m.id);
  if (wazuhOnly.length !== 1 || wazuhOnly[0] !== 'wazuh') {
    throw new Error(`Expected wazuh to resolve with no dependencies, got: ${JSON.stringify(wazuhOnly)}`);
  }
  const withWazuh = globalModuleRegistry.resolveModules(['wazuh', 'vigil-soc']).map(m => m.id);
  if (withWazuh.indexOf('opensearch') > withWazuh.indexOf('vigil-soc') || !withWazuh.includes('wazuh')) {
    throw new Error(`Expected wazuh plus opensearch before vigil-soc, got: ${JSON.stringify(withWazuh)}`);
  }

  const flamingoOnly = globalModuleRegistry.resolveModules(['flamingo']).map(m => m.id);
  if (flamingoOnly.length !== 1 || flamingoOnly[0] !== 'flamingo') {
    throw new Error(`Expected flamingo to resolve with no dependencies, got: ${JSON.stringify(flamingoOnly)}`);
  }

  for (const mId of ['falco', 'suricata', 'zeek', 'zap', 'bloodhound']) {
    const resMod = globalModuleRegistry.resolveModules([mId]).map(m => m.id);
    if (resMod.length !== 1 || resMod[0] !== mId) {
      throw new Error(`Expected ${mId} to resolve standalone, got: ${JSON.stringify(resMod)}`);
    }
  }

  // Test 3: Circular dependency detection
  const testRegistry = new ModuleRegistry();
  testRegistry.modules.clear();
  testRegistry.register({ id: 'mod-a', dependencies: ['mod-b'] });
  testRegistry.register({ id: 'mod-b', dependencies: ['mod-a'] });

  let threwCircular = false;
  try {
    testRegistry.resolveModules(['mod-a']);
  } catch (err) {
    if (err.message.includes('Circular dependency')) {
      threwCircular = true;
    }
  }

  if (!threwCircular) {
    throw new Error('Expected circular dependency error but none was thrown');
  }
  console.log('✔ Test 3 passed: Circular dependency correctly detected and rejected.');

  // Test 4: Domain hosts include subdomains
  const hosts = getDomainHosts({ domain: 'vigilante.local' });
  if (!hosts.includes('siem.vigilante.local') || !hosts.includes('vigil.vigilante.local') || !hosts.includes('wazuh.vigilante.local') || !hosts.includes('flamingo.vigilante.local')) {
    throw new Error(`Expected siem, vigil, wazuh, and flamingo hostnames, got: ${JSON.stringify(hosts)}`);
  }
  console.log('✔ Test 4 passed: getDomainHosts maps siem, vigil, wazuh, and flamingo subdomains.');

  // Test 5: simulateThreats exists on opensearch and vigil-soc
  const opensearch = globalModuleRegistry.get('opensearch');
  const vigilSoc = globalModuleRegistry.get('vigil-soc');

  if (typeof opensearch.simulateThreats !== 'function') {
    throw new Error('OpenSearch module must have simulateThreats function');
  }
  if (typeof vigilSoc.simulateThreats !== 'function') {
    throw new Error('Vigil SOC module must have simulateThreats function');
  }
  console.log('✔ Test 5 passed: simulateThreats function supported across modules.');

  // Test 6: uninstallModule method and mock invocation
  if (typeof globalModuleRegistry.uninstallModule !== 'function') {
    throw new Error('globalModuleRegistry must have uninstallModule method');
  }
  let mockUninstalled = false;
  let mockDeleteNamespace = null;
  const mockRegistry = new ModuleRegistry();
  mockRegistry.modules.clear();
  mockRegistry.register({
    id: 'mock-mod',
    name: 'Mock Module',
    async uninstall({ deleteNamespace }) {
      mockUninstalled = true;
      mockDeleteNamespace = deleteNamespace;
    },
    async install() {}
  });

  await mockRegistry.uninstallModule({ moduleId: 'mock-mod', deleteNamespace: false });
  if (!mockUninstalled || mockDeleteNamespace !== false) {
    throw new Error('uninstallModule failed to invoke module uninstall with deleteNamespace: false');
  }
  console.log('✔ Test 6 passed: uninstallModule executes successfully preserving namespace.');

  // Test 7: resetModule method and mock invocation
  if (typeof globalModuleRegistry.resetModule !== 'function') {
    throw new Error('globalModuleRegistry must have resetModule method');
  }
  let resetPhases = [];
  mockRegistry.register({
    id: 'mock-reset-mod',
    name: 'Mock Reset Module',
    async uninstall({ deleteNamespace }) {
      resetPhases.push(`uninstall(deleteNamespace=${deleteNamespace})`);
    },
    async install({ domain }) {
      resetPhases.push(`install(domain=${domain})`);
    }
  });

  await mockRegistry.resetModule({ moduleId: 'mock-reset-mod', domain: 'test.local' });
  if (resetPhases.length !== 2 || resetPhases[0] !== 'uninstall(deleteNamespace=false)' || resetPhases[1] !== 'install(domain=test.local)') {
    throw new Error(`resetModule unexpected phase sequence: ${JSON.stringify(resetPhases)}`);
  }
  console.log('✔ Test 7 passed: resetModule executes two-phase teardown and reinstall cleanly.');

  // Test 8: vigil-soc chart version and 0.6.0 image rendering
  const vigilChartYamlPath = path.resolve('src/modules/vigil-soc/charts/vigil/Chart.yaml');
  const vigilChartYaml = await fs.readFile(vigilChartYamlPath, 'utf8');
  if (!vigilChartYaml.includes('version: 0.6.0') || !vigilChartYaml.includes('appVersion: 0.6.0')) {
    throw new Error('vigil-soc Chart.yaml must specify version 0.6.0 and appVersion 0.6.0');
  }

  // Verify daemon-statefulset template includes state volume mount and VIGIL_DIR fix for issue #1152
  const daemonStatefulsetPath = path.resolve('src/modules/vigil-soc/charts/vigil/templates/daemon-statefulset.yaml');
  const daemonTemplate = await fs.readFile(daemonStatefulsetPath, 'utf8');
  if (!daemonTemplate.includes('vigil.stateVolumeMount') || !daemonTemplate.includes('vigil.stateEnv')) {
    throw new Error('daemon-statefulset.yaml must include vigil.stateVolumeMount and vigil.stateEnv');
  }
  console.log('✔ Test 8 passed: vigil-soc chart upgraded to 0.6.0 with VIGIL_DIR state volume mount.');

  // Test 9: getModuleStatuses collects every module's status and isolates failures
  // (the web /api/status route calls this method; it must exist and must not
  // let one module's failed probe fail the whole collection)
  const statusRegistry = new ModuleRegistry();
  statusRegistry.modules.clear();
  let seenContext = null;
  statusRegistry.register({
    id: 'healthy',
    name: 'Healthy Module',
    status: async (ctx) => {
      seenContext = ctx;
      return { id: 'healthy', name: 'Healthy Module', installed: true, status: 'running' };
    }
  });
  statusRegistry.register({
    id: 'broken',
    name: 'Broken Module',
    status: async () => {
      throw new Error('kubectl unreachable');
    }
  });
  const statuses = await statusRegistry.getModuleStatuses('cluster-x', 'example.local');
  if (statuses.length !== 2) {
    throw new Error(`Expected 2 module statuses, got ${statuses.length}`);
  }
  if (statuses[0].id !== 'healthy' || statuses[0].status !== 'running' || statuses[0].installed !== true) {
    throw new Error(`Healthy module status not passed through: ${JSON.stringify(statuses[0])}`);
  }
  if (statuses[1].id !== 'broken' || statuses[1].status !== 'error' || statuses[1].installed !== false || !String(statuses[1].details).includes('kubectl unreachable')) {
    throw new Error(`Broken module must degrade to an error entry, got: ${JSON.stringify(statuses[1])}`);
  }
  if (!seenContext || seenContext.clusterName !== 'cluster-x' || seenContext.domain !== 'example.local') {
    throw new Error(`status() must receive { clusterName, domain }, got: ${JSON.stringify(seenContext)}`);
  }
  if (typeof globalModuleRegistry.getModuleStatuses !== 'function') {
    throw new Error('globalModuleRegistry must expose getModuleStatuses for the /api/status route');
  }
  console.log('✔ Test 9 passed: getModuleStatuses collects statuses, forwards cluster/domain, and isolates per-module failures.');

  console.log('🎉 All Modules tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
