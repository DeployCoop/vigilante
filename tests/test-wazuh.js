import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { load as yamlLoad } from 'js-yaml';
import { WazuhModule, globalModuleRegistry } from '../src/index.js';
import { getDomainHosts } from '../src/engine/hosts.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';
import { loadConfig } from '../src/engine/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

async function runTests() {
  console.log('🧪 Testing Wazuh XDR/SIEM Module (wazuh)...');

  const module = new WazuhModule();
  assert.strictEqual(module.id, 'wazuh');
  assert.strictEqual(module.name, 'Wazuh XDR/SIEM');
  assert.strictEqual(module.category, 'siem');
  assert.strictEqual(module.version, '4.14.7');
  assert.strictEqual(module.defaultEnabled, false);
  assert.strictEqual(module.namespace, 'wazuh');
  assert.strictEqual(module.tlsSecretName, 'wazuh-tls');
  assert.deepStrictEqual(module.dependencies, []);
  assert.strictEqual(typeof module.install, 'function');
  assert.strictEqual(typeof module.uninstall, 'function');
  assert.strictEqual(typeof module.status, 'function');
  assert.strictEqual(typeof module.getEndpoints, 'function');
  console.log('✔ Test 1 passed: WazuhModule initialized with correct metadata and defaults.');

  const fromRegistry = globalModuleRegistry.get('wazuh');
  assert.ok(fromRegistry, 'Wazuh module must be present in globalModuleRegistry');
  assert.strictEqual(fromRegistry.id, 'wazuh');
  const resolved = globalModuleRegistry.resolveModules(['wazuh']);
  assert.strictEqual(resolved.length, 1);
  assert.strictEqual(resolved[0].id, 'wazuh');
  const withSoc = globalModuleRegistry.resolveModules(['vigil-soc', 'wazuh']).map(m => m.id);
  assert.ok(withSoc.indexOf('opensearch') < withSoc.indexOf('vigil-soc'));
  assert.ok(withSoc.includes('wazuh'));
  console.log('✔ Test 2 passed: wazuh is registered and dependency resolution still orders opensearch before vigil-soc.');

  const chartDir = path.join(rootDir, 'src', 'modules', 'wazuh', 'charts', 'wazuh');
  const chartData = yamlLoad(await fs.readFile(path.join(chartDir, 'Chart.yaml'), 'utf8'));
  assert.strictEqual(chartData.name, 'wazuh');
  assert.strictEqual(chartData.appVersion, '4.14.7');

  const valuesData = yamlLoad(await fs.readFile(path.join(chartDir, 'values.yaml'), 'utf8'));
  assert.strictEqual(valuesData.images.indexer, 'wazuh/wazuh-indexer:4.14.7');
  assert.strictEqual(valuesData.images.manager, 'wazuh/wazuh-manager:4.14.7');
  assert.strictEqual(valuesData.images.dashboard, 'wazuh/wazuh-dashboard:4.14.7');
  assert.strictEqual(valuesData.credentials.indexerUsername, 'admin');
  assert.strictEqual(valuesData.credentials.indexerPassword, 'SecretPassword');
  assert.strictEqual(valuesData.credentials.dashboardPassword, 'kibanaserver');
  assert.strictEqual(valuesData.credentials.apiUsername, 'wazuh-wui');
  assert.strictEqual(valuesData.indexer.javaOpts, '-Xms512m -Xmx512m');
  assert.strictEqual(valuesData.ingress.hosts[0].host, 'wazuh.vigilante.local');

  const requiredTemplates = [
    '_helpers.tpl',
    'configmap.yaml',
    'pvc.yaml',
    'services.yaml',
    'ingress.yaml',
    'indexer-statefulset.yaml',
    'manager-statefulset.yaml',
    'dashboard-deployment.yaml'
  ];
  for (const tpl of requiredTemplates) {
    await fs.access(path.join(chartDir, 'templates', tpl));
  }
  const indexerTpl = await fs.readFile(path.join(chartDir, 'templates', 'indexer-statefulset.yaml'), 'utf8');
  assert.ok(indexerTpl.includes('node.store.allow_mmap') === false);
  const opensearchYml = await fs.readFile(path.join(chartDir, 'files', 'opensearch.yml'), 'utf8');
  assert.ok(opensearchYml.includes('node.store.allow_mmap: false'));
  assert.ok(opensearchYml.includes('CN=wazuh-indexer,OU=Wazuh,O=Wazuh,L=California,C=US'));
  const usersYml = await fs.readFile(path.join(chartDir, 'files', 'internal_users.yml'), 'utf8');
  assert.ok(usersYml.includes('admin:'));
  assert.ok(usersYml.includes('kibanaserver:'));
  console.log('✔ Test 3 passed: Verified Wazuh Helm chart files, single-node defaults, and lab credentials.');

  const hosts = getDomainHosts({ domain: 'vigilante.local' });
  assert.ok(hosts.includes('wazuh.vigilante.local'));
  assert.ok(hosts.includes('siem.vigilante.local'));
  assert.ok(hosts.includes('openvas.vigilante.local'));
  console.log('✔ Test 4 passed: Local domain resolution includes wazuh.vigilante.local.');

  const endpoints = await module.getEndpoints({ domain: 'threatlab.internal', namespace: 'wazuh' });
  assert.strictEqual(endpoints.length, 5);
  const web = endpoints.find(e => e.url === 'https://wazuh.threatlab.internal');
  assert.ok(web, 'Dashboard endpoint must be https://wazuh.threatlab.internal');
  const indexer = endpoints.find(e => e.url.includes('wazuh-indexer.wazuh.svc.cluster.local:9200'));
  assert.ok(indexer);
  const api = endpoints.find(e => e.url.includes('wazuh-manager.wazuh.svc.cluster.local:55000'));
  assert.ok(api);
  const events = endpoints.find(e => e.url.endsWith(':1514'));
  const enroll = endpoints.find(e => e.url.endsWith(':1515'));
  assert.ok(events && enroll);

  const tenantEndpoints = await module.getEndpoints({ domain: 'threatlab.internal', namespace: 'tenant-lab' });
  assert.strictEqual(tenantEndpoints[0].url, 'https://tenant-lab-wazuh.threatlab.internal');
  assert.ok(tenantEndpoints[1].url.includes('wazuh-indexer.tenant-lab.svc.cluster.local'));
  console.log('✔ Test 5 passed: Endpoints reflect the dashboard host and in-cluster indexer, API, and agent ports.');

  const defaultValuesPath = path.join(rootDir, 'src', 'modules', 'wazuh', 'values', 'wazuh.yaml');
  const valuesArgs = await resolveChartValuesArgs({
    moduleId: 'wazuh',
    chartName: 'wazuh',
    defaultValuesPath,
    domain: 'vigilante.test',
    tlsSecretName: 'test-tls',
    namespace: 'wazuh'
  });
  assert.ok(valuesArgs.includes('-f'));
  const renderedPath = valuesArgs[valuesArgs.indexOf('-f') + 1];
  const renderedContent = await fs.readFile(renderedPath, 'utf8');
  assert.ok(renderedContent.includes('wazuh.vigilante.test'));
  assert.ok(renderedContent.includes('test-tls'));
  assert.ok(renderedContent.includes('SecretPassword'));
  console.log('✔ Test 6 passed: resolveChartValuesArgs templated wazuh ingress host and TLS secret.');

  const offline = await module.status({ domain: 'vigilante.local', clusterName: 'missing-cluster', namespace: 'wazuh' });
  assert.strictEqual(offline.id, 'wazuh');
  assert.strictEqual(offline.installed, false);
  assert.strictEqual(offline.status, 'Not Installed');
  console.log('✔ Test 7 passed: status() reports Not Installed when the cluster API is unreachable.');

  const cfg = loadConfig();
  assert.strictEqual(cfg.modules?.wazuh?.enabled, false);
  assert.strictEqual(cfg.modules?.wazuh?.version, '4.14.7');
  console.log('✔ Test 8 passed: default config keeps the Wazuh module disabled.');

  console.log('\n🎉 All Wazuh XDR/SIEM Module tests passed successfully!\n');
}

runTests().catch(err => {
  console.error('✖ Test suite failed:', err);
  process.exit(1);
});
