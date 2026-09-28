import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { load as yamlLoad } from 'js-yaml';
import { FlamingoModule, globalModuleRegistry } from '../src/index.js';
import { getDomainHosts } from '../src/engine/hosts.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';
import { loadConfig } from '../src/engine/config.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

async function runTests() {
  console.log('🧪 Testing Flamingo Credential Harvester Module (flamingo)...');

  // Test 1: FlamingoModule metadata and properties
  const module = new FlamingoModule();
  assert.strictEqual(module.id, 'flamingo');
  assert.strictEqual(module.name, 'Flamingo Credential Harvester');
  assert.strictEqual(module.category, 'recon');
  assert.strictEqual(module.version, '0.1.0');
  assert.strictEqual(module.defaultEnabled, false);
  assert.strictEqual(module.namespace, 'flamingo');
  assert.strictEqual(module.tlsSecretName, 'flamingo-tls');
  assert.deepStrictEqual(module.dependencies, []);
  assert.strictEqual(typeof module.install, 'function');
  assert.strictEqual(typeof module.uninstall, 'function');
  assert.strictEqual(typeof module.status, 'function');
  assert.strictEqual(typeof module.getEndpoints, 'function');
  console.log('✔ Test 1 passed: FlamingoModule initialized with correct metadata and defaults.');

  // Test 2: Global registry & dependency resolution
  const fromRegistry = globalModuleRegistry.get('flamingo');
  assert.ok(fromRegistry, 'Flamingo module must be registered in globalModuleRegistry');
  assert.strictEqual(fromRegistry.id, 'flamingo');
  const resolved = globalModuleRegistry.resolveModules(['flamingo']);
  assert.strictEqual(resolved.length, 1);
  assert.strictEqual(resolved[0].id, 'flamingo');

  const withSoc = globalModuleRegistry.resolveModules(['vigil-soc', 'flamingo']).map(m => m.id);
  assert.ok(withSoc.indexOf('opensearch') < withSoc.indexOf('vigil-soc'));
  assert.ok(withSoc.includes('flamingo'));
  console.log('✔ Test 2 passed: flamingo is registered and resolves without unexpected dependencies.');

  // Test 3: Chart structure and templates verification
  const chartDir = path.join(rootDir, 'src', 'modules', 'flamingo', 'charts', 'flamingo');
  const chartData = yamlLoad(await fs.readFile(path.join(chartDir, 'Chart.yaml'), 'utf8'));
  assert.strictEqual(chartData.name, 'flamingo');
  assert.strictEqual(chartData.version, '0.1.0');

  const valuesData = yamlLoad(await fs.readFile(path.join(chartDir, 'values.yaml'), 'utf8'));
  assert.strictEqual(valuesData.image.repository, 'ghcr.io/joshuacox/flamingo');
  assert.strictEqual(valuesData.image.tag, 'latest');
  assert.strictEqual(valuesData.securityContext.capabilities.add[0], 'NET_BIND_SERVICE');
  assert.strictEqual(valuesData.config.protocols, 'ssh,snmp,ldap,http,dns,ftp');
  assert.strictEqual(valuesData.ingress.hosts[0].host, 'flamingo.vigilante.local');

  const requiredTemplates = [
    '_helpers.tpl',
    'deployment.yaml',
    'service.yaml',
    'ingress.yaml',
    'pvc.yaml',
    'serviceaccount.yaml'
  ];
  for (const tpl of requiredTemplates) {
    await fs.access(path.join(chartDir, 'templates', tpl));
  }
  const deploymentTpl = await fs.readFile(path.join(chartDir, 'templates', 'deployment.yaml'), 'utf8');
  assert.ok(deploymentTpl.includes('NET_BIND_SERVICE') === false); // in values, referenced in template
  assert.ok(deploymentTpl.includes('--protocols='));
  assert.ok(deploymentTpl.includes('--tls-cert=/etc/flamingo/tls/tls.crt'));

  const serviceTpl = await fs.readFile(path.join(chartDir, 'templates', 'service.yaml'), 'utf8');
  assert.ok(serviceTpl.includes('name: ssh'));
  assert.ok(serviceTpl.includes('name: ftp'));
  assert.ok(serviceTpl.includes('name: dns-udp'));
  assert.ok(serviceTpl.includes('name: http'));
  console.log('✔ Test 3 passed: Verified Flamingo Helm chart files, multi-protocol listeners, and templates.');

  // Test 4: Local domain resolution
  const hosts = getDomainHosts({ domain: 'vigilante.local' });
  assert.ok(hosts.includes('flamingo.vigilante.local'));
  console.log('✔ Test 4 passed: Local domain resolution includes flamingo.vigilante.local.');

  // Test 5: Endpoints mapping
  const endpoints = await module.getEndpoints({ domain: 'ctf.local', namespace: 'flamingo' });
  assert.strictEqual(endpoints.length, 6);
  const web = endpoints.find(e => e.url === 'https://flamingo.ctf.local');
  assert.ok(web, 'Web ingress endpoint must be https://flamingo.ctf.local');
  const ssh = endpoints.find(e => e.url === 'flamingo.flamingo.svc.cluster.local:22');
  assert.ok(ssh, 'SSH listener endpoint must match');
  const dns = endpoints.find(e => e.url === 'flamingo.flamingo.svc.cluster.local:53');
  assert.ok(dns, 'DNS listener endpoint must match');
  console.log('✔ Test 5 passed: Endpoints reflect the web ingress and internal protocol listeners.');

  // Test 6: Chart values resolution and templating
  const defaultValsPath = path.join(rootDir, 'src', 'modules', 'flamingo', 'values', 'flamingo.yaml');
  const resolvedArgs = await resolveChartValuesArgs({
    moduleId: 'flamingo',
    chartName: 'flamingo',
    defaultValuesPath: defaultValsPath,
    domain: 'lab.internal',
    tlsSecretName: 'custom-flamingo-tls',
    namespace: 'flamingo'
  });
  assert.ok(resolvedArgs.length >= 2);
  assert.strictEqual(resolvedArgs[0], '-f');
  const renderedContent = await fs.readFile(resolvedArgs[1], 'utf8');
  assert.ok(renderedContent.includes('flamingo.lab.internal'));
  assert.ok(renderedContent.includes('custom-flamingo-tls'));
  console.log('✔ Test 6 passed: resolveChartValuesArgs templated flamingo ingress host and TLS secret.');

  // Test 7: Status reporting when cluster API is unreachable
  const st = await module.status({ domain: 'vigilante.local', clusterName: 'nonexistent-cluster-xyz' });
  assert.strictEqual(st.installed, false);
  assert.strictEqual(st.status, 'Not Installed');
  assert.deepStrictEqual(st.pods, []);
  console.log('✔ Test 7 passed: status() reports Not Installed when cluster is unreachable.');

  // Test 8: Default configuration
  const config = await loadConfig();
  assert.strictEqual(config.modules?.flamingo?.enabled, false);
  console.log('✔ Test 8 passed: default config keeps the Flamingo module disabled.');

  console.log('🎉 ALL 8 FLAMINGO TESTS PASSED SUCCESSFULLY!');
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
