import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { VigilLocalModule, DEFAULT_VIGIL_LOCAL_CHART_PATH } from '../src/modules/vigil-local/index.js';
import { globalModuleRegistry } from '../src/modules/registry.js';
import { getDomainHosts } from '../src/engine/hosts.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';
import {
  getVigilLocalChartPath,
  setVigilLocalChartPath,
  validateVigilLocalChartPath,
  validateVigilLocalChartPathSync,
  resolvePathWithHome
} from '../src/engine/config.js';

console.log('🧪 Testing Vigil AI SOC Local Checkout Module (vigil-local)...');

// Test 1: Module instantiation & properties
const moduleInstance = new VigilLocalModule();
assert.strictEqual(moduleInstance.id, 'vigil-local');
assert.strictEqual(moduleInstance.name, 'Vigil AI SOC (Local Source / Dev)');
assert.strictEqual(moduleInstance.category, 'soc');
assert.deepStrictEqual(moduleInstance.dependencies, ['opensearch']);
assert.strictEqual(moduleInstance.defaultEnabled, false);
console.log('✔ Test 1 passed: VigilLocalModule initialized with correct metadata and opensearch dependency.');

// Test 2: Registry integration & dependency resolution
const registered = globalModuleRegistry.get('vigil-local');
assert.ok(registered, 'vigil-local must be registered in globalModuleRegistry');
const resolved = globalModuleRegistry.resolveModules(['vigil-local']);
assert.strictEqual(resolved.length, 2);
assert.strictEqual(resolved[0].id, 'opensearch');
assert.strictEqual(resolved[1].id, 'vigil-local');
console.log('✔ Test 2 passed: Dependency resolution orders opensearch before vigil-local.');

// Test 3: Path helpers, getting, setting & validation
const initialPath = getVigilLocalChartPath();
assert.ok(typeof initialPath === 'string' && initialPath.length > 0, 'getVigilLocalChartPath must return a path string');

// Test with known valid chart path in workspace
const validWorkspaceChart = path.resolve('src/modules/vigil-soc/charts/vigil');
const syncValValid = validateVigilLocalChartPathSync(validWorkspaceChart);
assert.strictEqual(syncValValid.valid, true, 'validateVigilLocalChartPathSync must return valid: true for chart directory with Chart.yaml');
assert.strictEqual(syncValValid.chartYamlExists, true);
assert.strictEqual(syncValValid.dirExists, true);

const asyncValValid = await validateVigilLocalChartPath(validWorkspaceChart);
assert.strictEqual(asyncValValid.valid, true);

// Test with non-existent path
const fakePath = '/tmp/nonexistent-vigil-chart-path-test-xyz';
const syncValFake = validateVigilLocalChartPathSync(fakePath);
assert.strictEqual(syncValFake.valid, false, 'Nonexistent path must return valid: false');
assert.strictEqual(syncValFake.dirExists, false);

// Test setting custom chart path
const savedPath = await setVigilLocalChartPath(validWorkspaceChart);
assert.strictEqual(savedPath, validWorkspaceChart);
assert.strictEqual(getVigilLocalChartPath(), validWorkspaceChart);
assert.strictEqual(moduleInstance.getChartPath(), validWorkspaceChart);

const resolvedPath = await moduleInstance.resolveLocalChartPath();
assert.strictEqual(resolvedPath, validWorkspaceChart);
console.log(`✔ Test 3 passed: Configured, validated, and resolved local chart path at '${resolvedPath}'.`);

// Test 4: Domain hosts mapping
const domainHosts = getDomainHosts({ domain: 'vigilante.local' });
assert.ok(domainHosts.includes('vigil-local.vigilante.local'), 'getDomainHosts must include vigil-local.vigilante.local');
console.log('✔ Test 4 passed: Local domain resolution includes vigil-local.vigilante.local.');

// Test 5: Endpoints mapping
const endpoints = await moduleInstance.getEndpoints({ domain: 'vigilante.local', namespace: 'tenant-test' });
assert.strictEqual(endpoints.length, 2);
assert.strictEqual(endpoints[0].url, 'https://tenant-test-vigil-local.vigilante.local');
assert.strictEqual(endpoints[1].url, 'http://vigil-backend.tenant-test.svc.cluster.local:6987');
console.log('✔ Test 5 passed: Endpoints correctly reflect parameterized namespace and domain.');

// Test 6: Helm values resolution
const defaultValuesPath = path.resolve('src/modules/vigil-local/values/vigil.yaml');
const valuesArgs = await resolveChartValuesArgs({
  moduleId: 'vigil-local',
  chartName: 'vigil',
  defaultValuesPath,
  domain: 'vigilante.local',
  tlsSecretName: 'vigil-local-tls',
  namespace: 'vigil-local'
});
assert.ok(valuesArgs.length >= 2, 'resolveChartValuesArgs must produce Helm -f flags');
assert.strictEqual(valuesArgs[0], '-f');
console.log('✔ Test 6 passed: resolveChartValuesArgs successfully templated vigil-local values.');

// Test 7: Status method structure & chart metadata
const statusResult = await moduleInstance.status({ domain: 'vigilante.local', clusterName: 'vigilante-dev' });
assert.strictEqual(statusResult.id, 'vigil-local');
assert.strictEqual(statusResult.name, 'Vigil AI SOC (Local Source / Dev)');
assert.ok(typeof statusResult.installed === 'boolean');
assert.ok(Array.isArray(statusResult.endpoints));
assert.strictEqual(statusResult.chartPath, validWorkspaceChart);
assert.strictEqual(statusResult.chartValid, true);
console.log('✔ Test 7 passed: status() returned standard module health structure with chart metadata.');

// Test 8: SelectModules & ModulesView export and UI integration
const { SelectModules } = await import('../src/ui/SelectModules.js');
const { ModulesView } = await import('../src/ui/ModulesView.js');
assert.strictEqual(typeof SelectModules, 'function', 'SelectModules must be an exported component');
assert.strictEqual(typeof ModulesView, 'object', 'ModulesView must be a memoized component');
console.log('✔ Test 8 passed: SelectModules and ModulesView UI components loaded and integrated.');

console.log('\n🎉 All Vigil Local Checkout Module (vigil-local) tests passed successfully!\n');

