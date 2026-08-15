import { ModuleRegistry, globalModuleRegistry } from '../src/modules/registry.js';
import { getDomainHosts } from '../src/engine/hosts.js';

async function runTests() {
  console.log('🧪 Testing Modules System & Dependency Resolver...');

  // Test 1: Global registry default modules
  const allModules = globalModuleRegistry.getAll();
  const ids = allModules.map(m => m.id);

  if (!ids.includes('opensearch') || !ids.includes('vigil-soc')) {
    throw new Error(`Expected default modules 'opensearch' and 'vigil-soc', got: ${JSON.stringify(ids)}`);
  }
  console.log('✔ Test 1 passed: Default modules registered in globalModuleRegistry.');

  // Test 2: Dependency resolution
  const resolved = globalModuleRegistry.resolveModules(['vigil-soc']);
  const resolvedIds = resolved.map(m => m.id);

  if (resolvedIds[0] !== 'opensearch' || resolvedIds[1] !== 'vigil-soc') {
    throw new Error(`Expected ['opensearch', 'vigil-soc'] in dependency order, got: ${JSON.stringify(resolvedIds)}`);
  }
  console.log('✔ Test 2 passed: Dependency resolution ordered opensearch before vigil-soc.');

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

  // Test 4: Domain hosts include both subdomains
  const hosts = getDomainHosts({ domain: 'vigilante.local' });
  if (!hosts.includes('siem.vigilante.local') || !hosts.includes('vigil.vigilante.local')) {
    throw new Error(`Expected siem and vigil hostnames, got: ${JSON.stringify(hosts)}`);
  }
  console.log('✔ Test 4 passed: getDomainHosts maps both siem and vigil subdomains.');

  console.log('🎉 All Modules tests passed successfully!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
