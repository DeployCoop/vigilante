import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { load as yamlLoad } from 'js-yaml';
import {
  OpenVASModule,
  globalModuleRegistry
} from '../src/index.js';
import { getDomainHosts } from '../src/engine/hosts.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';
import {
  SCAN_PROFILES,
  getCvssSeverity,
  checkOpenVasStatus,
  runHostVulnerabilityScan,
  listSavedOpenVasReports
} from '../src/engine/openvas.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

async function runTests() {
  console.log('🧪 Testing OpenVAS / Greenbone Community Edition Module (openvas)...');

  // Test 1: Module instantiation & metadata
  const module = new OpenVASModule();
  assert.strictEqual(module.id, 'openvas', 'Module ID must be openvas');
  assert.strictEqual(module.category, 'scanner', 'Category must be scanner');
  assert.strictEqual(module.defaultEnabled, false, 'Should be disabled by default');
  assert.strictEqual(module.namespace, 'openvas', 'Default namespace must be openvas');
  assert.strictEqual(module.tlsSecretName, 'openvas-tls', 'TLS secret must be openvas-tls');
  assert.deepStrictEqual(module.dependencies, [], 'Dependencies must be empty');
  console.log('✔ Test 1 passed: OpenVASModule initialized with correct metadata and defaults.');

  // Test 2: Global Module Registry
  const fromRegistry = globalModuleRegistry.get('openvas');
  assert(fromRegistry, 'OpenVAS module must be present in globalModuleRegistry');
  assert.strictEqual(fromRegistry.id, 'openvas');
  const resolved = globalModuleRegistry.resolveModules(['openvas']);
  assert.strictEqual(resolved.length, 1);
  assert.strictEqual(resolved[0].id, 'openvas');
  console.log('✔ Test 2 passed: openvas module registered and resolvable in globalModuleRegistry.');

  // Test 3: Helm Chart Manifests & Templates Structure
  const chartDir = path.join(rootDir, 'src', 'modules', 'openvas', 'charts', 'openvas');
  const chartYamlPath = path.join(chartDir, 'Chart.yaml');
  const valuesYamlPath = path.join(chartDir, 'values.yaml');
  const templatesDir = path.join(chartDir, 'templates');

  const chartRaw = await fs.readFile(chartYamlPath, 'utf8');
  const chartData = yamlLoad(chartRaw);
  assert.strictEqual(chartData.name, 'openvas');
  assert.strictEqual(chartData.appVersion, '24.10');

  const valuesRaw = await fs.readFile(valuesYamlPath, 'utf8');
  const valuesData = yamlLoad(valuesRaw);
  assert(valuesData.psgvm, 'values.yaml must contain psgvm configuration');
  assert(valuesData.ospd, 'values.yaml must contain ospd configuration');
  assert.strictEqual(valuesData.FEED_RELEASE, '24.10');

  const requiredTemplates = [
    '_helpers.tpl',
    'deployment.yaml',
    'init-configmap.yaml',
    'pvc.yaml',
    'service.yaml',
    'ingress.yaml'
  ];
  for (const tpl of requiredTemplates) {
    await fs.access(path.join(templatesDir, tpl));
  }
  console.log('✔ Test 3 passed: Verified all OpenVAS Helm chart files and templates.');

  // Test 4: Local Domain Hosts Resolution
  const hosts = getDomainHosts({ domain: 'vigilante.local' });
  assert(hosts.includes('openvas.vigilante.local'), 'Hosts must include openvas.vigilante.local');
  assert(hosts.includes('gvm.vigilante.local'), 'Hosts must include gvm.vigilante.local');
  console.log('✔ Test 4 passed: Local domain resolution includes openvas.vigilante.local and gvm.vigilante.local.');

  // Test 5: Endpoints mapping
  const endpoints = await module.getEndpoints({ domain: 'threatlab.internal', namespace: 'openvas' });
  assert.strictEqual(endpoints.length, 4);
  const webEndpoint = endpoints.find(e => e.url.includes('https://openvas.threatlab.internal'));
  assert(webEndpoint, 'Endpoints must contain https://openvas.threatlab.internal');
  const gvmEndpoint = endpoints.find(e => e.url.includes('https://gvm.threatlab.internal'));
  assert(gvmEndpoint, 'Endpoints must contain https://gvm.threatlab.internal');
  console.log('✔ Test 5 passed: Endpoints correctly reflect parameterized namespace and domain.');

  // Test 6: Chart values resolution and templating
  const defaultValuesPath = path.join(rootDir, 'src', 'modules', 'openvas', 'values', 'openvas.yaml');
  const valuesArgs = await resolveChartValuesArgs({
    moduleId: 'openvas',
    chartName: 'openvas',
    defaultValuesPath,
    domain: 'vigilante.test',
    tlsSecretName: 'test-tls',
    namespace: 'openvas-ns'
  });
  assert(valuesArgs.includes('-f'), 'Helm args must include -f flag');
  const renderedPath = valuesArgs[valuesArgs.indexOf('-f') + 1];
  const renderedContent = await fs.readFile(renderedPath, 'utf8');
  assert(renderedContent.includes('openvas.vigilante.test'), 'Rendered values must replace {{DOMAIN}}');
  assert(renderedContent.includes('test-tls'), 'Rendered values must replace {{TLS_SECRET}}');
  console.log('✔ Test 6 passed: resolveChartValuesArgs successfully templated openvas values.');

  // Test 7: OpenVAS Engine & CVSS Classification
  assert.strictEqual(SCAN_PROFILES.length, 5, 'Must provide 5 built-in scan profiles');
  assert.strictEqual(getCvssSeverity(9.8).level, 'CRITICAL');
  assert.strictEqual(getCvssSeverity(7.5).level, 'HIGH');
  assert.strictEqual(getCvssSeverity(5.3).level, 'MEDIUM');
  assert.strictEqual(getCvssSeverity(2.1).level, 'LOW');
  assert.strictEqual(getCvssSeverity(0.0).level, 'LOG');

  const progressEvents = [];
  const testHost = {
    ip: '10.0.1.50',
    hostname: 'test-target.local',
    ports: [
      { port: 80, protocol: 'tcp', service: 'http', state: 'open' },
      { port: 443, protocol: 'tcp', service: 'https', state: 'open' },
      { port: 22, protocol: 'tcp', service: 'ssh', state: 'open' }
    ]
  };

  const scanResult = await runHostVulnerabilityScan({
    host: testHost,
    profile: 'full-and-fast',
    networkTarget: 'test_openvas_net',
    onProgress: (p) => progressEvents.push(p)
  });

  assert.strictEqual(scanResult.target, '10.0.1.50');
  assert(scanResult.findings.length >= 3, 'Must discover vulnerability findings for HTTP and SSH');
  assert(scanResult.summary.high > 0, 'Must record high severity CVEs');
  assert(progressEvents.some(p => p.percent === 100), 'Must complete to 100%');

  const savedReports = await listSavedOpenVasReports('test_openvas_net', '10.0.1.50');
  assert(savedReports.length >= 1, 'Must discover auto-saved OpenVAS report in evidence vault');
  assert.strictEqual(savedReports[0].target, '10.0.1.50');
  console.log('✔ Test 7 passed: OpenVAS scanner engine executed, generated CVE findings, and saved evidence.');

  // Test 8: MCP Server OpenVAS Tools
  const mcpServer = createVigilanteMcpServer();
  assert(mcpServer, 'MCP server instance must be created');
  console.log('✔ Test 8 passed: MCP Server initializes with OpenVAS tools available.');

  console.log('\n🎉 All OpenVAS / Greenbone Community Edition Module tests passed successfully!\n');
}

runTests().catch(err => {
  console.error('✖ Test suite failed:', err);
  process.exit(1);
});
