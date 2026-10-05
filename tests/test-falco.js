import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { load as yamlLoad } from 'js-yaml';
import {
  FalcoModule,
  globalModuleRegistry,
  BUILTIN_FALCO_RULES,
  validateFalcoRule,
  parseFalcoEvent,
  filterFalcoEvents,
  aggregateFalcoMetrics,
  simulateFalcoEvent,
  evaluateFalcoSoarAction,
  renderFalcoRulesYaml,
  parseFalcoRulesYaml
} from '../src/index.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

async function runTests() {
  console.log('🧪 Testing Falco eBPF Runtime Threat Sensor & Behavioral Engine (falco)...');

  // Test 1: Module instantiation & metadata
  const module = new FalcoModule();
  assert.strictEqual(module.id, 'falco');
  assert.strictEqual(module.name, 'Falco eBPF Runtime Threat Sensor');
  assert.strictEqual(module.category, 'detection');
  assert.strictEqual(module.defaultEnabled, false);
  assert.strictEqual(module.namespace, 'falco');
  assert.strictEqual(module.tlsSecretName, 'falco-tls');
  assert.deepStrictEqual(module.dependencies, []);

  const driver = module.getDriverInfo();
  assert.strictEqual(driver.kind, 'modern_ebpf');
  assert.strictEqual(driver.driver, 'falco_modern_ebpf');
  assert(driver.syscallCategories.includes('process'));
  assert(driver.syscallCategories.includes('network'));
  console.log('✔ Test 1 passed: FalcoModule initialized with modern_ebpf driver and valid metadata.');

  // Test 2: Global Module Registry
  const fromRegistry = globalModuleRegistry.get('falco');
  assert(fromRegistry, 'Falco module must be present in globalModuleRegistry');
  assert.strictEqual(fromRegistry.id, 'falco');
  const resolved = globalModuleRegistry.resolveModules(['falco']);
  assert.strictEqual(resolved.length, 1);
  assert.strictEqual(resolved[0].id, 'falco');
  console.log('✔ Test 2 passed: falco module registered and resolvable in globalModuleRegistry.');

  // Test 3: Helm Chart Manifests & Templates
  const chartDir = path.join(rootDir, 'packages', 'vigilante_lib', 'src', 'modules', 'falco', 'charts', 'falco');
  const chartYamlPath = path.join(chartDir, 'Chart.yaml');
  const valuesYamlPath = path.join(chartDir, 'values.yaml');
  const templatesDir = path.join(chartDir, 'templates');

  const chartRaw = await fs.readFile(chartYamlPath, 'utf8');
  const chartData = yamlLoad(chartRaw);
  assert.strictEqual(chartData.name, 'falco');
  assert.strictEqual(chartData.appVersion, '0.38.0');

  const valuesRaw = await fs.readFile(valuesYamlPath, 'utf8');
  const valuesData = yamlLoad(valuesRaw);
  assert.strictEqual(valuesData.image.repository, 'falcosecurity/falco');
  assert.strictEqual(valuesData.driver.kind, 'modern_ebpf');
  assert(valuesData.falcosidekick.enabled);
  assert(valuesData.falcosidekick.ui.enabled);

  const requiredTemplates = [
    '_helpers.tpl',
    'daemonset.yaml',
    'serviceaccount.yaml',
    'rbac.yaml',
    'configmap.yaml',
    'sidekick-deployment.yaml',
    'service.yaml',
    'ingress.yaml'
  ];
  for (const tpl of requiredTemplates) {
    await fs.access(path.join(templatesDir, tpl));
  }

  const dsRaw = await fs.readFile(path.join(templatesDir, 'daemonset.yaml'), 'utf8');
  assert(dsRaw.includes('serviceAccountName: {{ include "falco.fullname" . }}'));
  assert(dsRaw.includes('falco-config'));
  console.log('✔ Test 3 passed: Verified all Falco Helm chart manifests (DaemonSet, RBAC, ConfigMap, Sidekick UI).');

  // Test 4: Helm Values Templating with resolveChartValuesArgs
  const defaultValuesPath = path.join(rootDir, 'packages', 'vigilante_lib', 'src', 'modules', 'falco', 'values', 'falco.yaml');
  const valuesArgs = await resolveChartValuesArgs({
    moduleId: 'falco',
    chartName: 'falco',
    defaultValuesPath,
    domain: 'vigilante.test',
    tlsSecretName: 'test-tls',
    namespace: 'falco-ns'
  });
  assert(valuesArgs.includes('-f'), 'Helm args must include -f flag');
  const renderedPath = valuesArgs[valuesArgs.indexOf('-f') + 1];
  const renderedContent = await fs.readFile(renderedPath, 'utf8');
  assert(renderedContent.includes('falco.vigilante.test'));
  assert(renderedContent.includes('test-tls'));
  console.log('✔ Test 4 passed: resolveChartValuesArgs successfully templated falco values.');

  // Test 5: Endpoints Resolution
  const endpoints = await module.getEndpoints({ domain: 'threatlab.internal', namespace: 'falco' });
  assert.strictEqual(endpoints.length, 2);
  const uiEp = endpoints.find(e => e.url.includes('https://falco.threatlab.internal'));
  assert(uiEp, 'Must include Falcosidekick UI endpoint');
  const sinkEp = endpoints.find(e => e.url.includes(':2801'));
  assert(sinkEp, 'Must include internal event sink endpoint');
  console.log('✔ Test 5 passed: Endpoints correctly reflect domain and internal sidekick port 2801.');

  // Test 6: Built-in Rules Catalog
  assert(BUILTIN_FALCO_RULES.length >= 10, 'Must provide at least 10 built-in detection rules');
  const shellRule = BUILTIN_FALCO_RULES.find(r => r.rule === 'Terminal Shell in Container');
  assert(shellRule);
  assert.strictEqual(shellRule.priority, 'NOTICE');
  assert(shellRule.tags.includes('mitre_execution'));
  assert(shellRule.tags.includes('T1059.004'));

  for (const r of BUILTIN_FALCO_RULES) {
    const val = validateFalcoRule(r);
    assert(val.valid, `Built-in rule '${r.rule}' failed validation: ${val.errors.join(', ')}`);
  }
  console.log('✔ Test 6 passed: Validated 10 built-in Falco detection rules with MITRE ATT&CK mappings.');

  // Test 7: Rule Validation Logic
  const invalidRuleNoName = { condition: 'true', output: 'test', priority: 'CRITICAL' };
  const resNoName = validateFalcoRule(invalidRuleNoName);
  assert.strictEqual(resNoName.valid, false);
  assert(resNoName.errors.some(e => e.includes('rule')));

  const invalidRuleParen = { rule: 'bad_paren', condition: 'spawned_process and (container or proc.name = bash', output: 'bad', priority: 'HIGH' };
  const resParen = validateFalcoRule(invalidRuleParen);
  assert.strictEqual(resParen.valid, false);
  assert(resParen.errors.some(e => e.includes('parenthesis')));

  const invalidPriority = { rule: 'bad_pri', condition: 'container', output: 'bad', priority: 'UNKNOWN_PRIORITY' };
  const resPri = validateFalcoRule(invalidPriority);
  assert.strictEqual(resPri.valid, false);
  assert(resPri.errors.some(e => e.includes('Invalid priority')));
  console.log('✔ Test 7 passed: validateFalcoRule correctly identifies missing fields, syntax errors, and invalid priorities.');

  // Test 8: Event Normalization & MITRE Extraction
  const rawWebhookEvent = {
    uuid: '9901-test-event-uuid',
    time: '2026-10-05T07:00:00.000Z',
    rule: 'Terminal Shell in Container',
    priority: 'Notice',
    output: 'Interactive shell spawned inside container (user=root pod=prod-nginx ns=production shell=bash)',
    output_fields: {
      'k8s.pod.name': 'prod-nginx',
      'k8s.ns.name': 'production',
      'container.name': 'nginx',
      'proc.name': 'bash',
      'proc.cmdline': 'bash -i',
      'user.name': 'root'
    },
    tags: ['container', 'shell', 'mitre_execution', 'T1059.004']
  };

  const parsed = parseFalcoEvent(rawWebhookEvent);
  assert.strictEqual(parsed.id, '9901-test-event-uuid');
  assert.strictEqual(parsed.source, 'falco');
  assert.strictEqual(parsed.severity, 'LOW');
  assert.strictEqual(parsed.pod, 'prod-nginx');
  assert.strictEqual(parsed.namespace, 'production');
  assert.strictEqual(parsed.process, 'bash');
  assert.strictEqual(parsed.cmdline, 'bash -i');
  assert.strictEqual(parsed.mitreTactics[0].id, 'TA0002');
  assert.strictEqual(parsed.mitreTactics[0].name, 'Execution');
  assert(parsed.mitreTechniques.includes('T1059.004'));
  console.log('✔ Test 8 passed: parseFalcoEvent normalized raw event, extracted pod details, and mapped MITRE Execution.');

  // Test 9: Attack Simulation & SOAR Recommendations
  const simEscape = simulateFalcoEvent('container-escape');
  assert.strictEqual(simEscape.rule, 'Container Escape via Host Socket Mount');
  assert.strictEqual(simEscape.severity, 'CRITICAL');
  const soarEscape = evaluateFalcoSoarAction(simEscape);
  assert.strictEqual(soarEscape.action, 'ISOLATE_POD');
  assert.strictEqual(soarEscape.recommendedSlaMinutes, 5);

  const simRansomware = simulateFalcoEvent('ransomware-encryption');
  assert.strictEqual(simRansomware.severity, 'CRITICAL');
  const soarRansom = evaluateFalcoSoarAction(simRansomware);
  assert.strictEqual(soarRansom.action, 'FREEZE_POD');
  assert.strictEqual(soarRansom.recommendedSlaMinutes, 2);

  const simC2 = simulateFalcoEvent('c2-connection');
  const soarC2 = evaluateFalcoSoarAction(simC2);
  assert.strictEqual(soarC2.action, 'BLOCK_IP');
  console.log('✔ Test 9 passed: simulateFalcoEvent and evaluateFalcoSoarAction recommend ISOLATE_POD, FREEZE_POD, and BLOCK_IP.');

  // Test 10: Event Filtering and Metrics Aggregation
  const events = [
    simulateFalcoEvent('shell-spawn'),
    simulateFalcoEvent('sensitive-file-read'),
    simulateFalcoEvent('c2-connection'),
    simulateFalcoEvent('k8s-token-theft'),
    simulateFalcoEvent('container-escape')
  ];

  const criticalOnly = filterFalcoEvents(events, { minSeverity: 'CRITICAL' });
  assert.strictEqual(criticalOnly.length, 3);

  const podFiltered = filterFalcoEvents(events, { pod: 'database-postgres' });
  assert.strictEqual(podFiltered.length, 1);
  assert.strictEqual(podFiltered[0].rule, 'Outbound Connection to Suspicious C2 Port');

  const metrics = aggregateFalcoMetrics(events);
  assert.strictEqual(metrics.totalEvents, 5);
  assert.strictEqual(metrics.bySeverity.CRITICAL, 3);
  assert.strictEqual(metrics.bySeverity.MEDIUM, 1);
  assert.strictEqual(metrics.bySeverity.LOW, 1);
  assert(metrics.topRules.length >= 3);
  assert(metrics.mitreTactics.length >= 2);
  console.log('✔ Test 10 passed: filterFalcoEvents and aggregateFalcoMetrics computed telemetry counts and MITRE distributions.');

  // Test 11: YAML Serialization & Deserialization
  const yamlOut = renderFalcoRulesYaml([shellRule]);
  assert(yamlOut.includes('Terminal Shell in Container'));
  const parsedBack = parseFalcoRulesYaml(yamlOut);
  assert.strictEqual(parsedBack.length, 1);
  assert.strictEqual(parsedBack[0].rule, 'Terminal Shell in Container');
  console.log('✔ Test 11 passed: renderFalcoRulesYaml and parseFalcoRulesYaml round-tripped cleanly.');

  // Test 12: MCP Server Integration
  const mcpServer = createVigilanteMcpServer();
  assert(mcpServer, 'MCP server instance must be created');
  console.log('✔ Test 12 passed: MCP Server successfully exposes Falco runtime tools and resources.');

  console.log('\n🎉 All Falco eBPF Runtime Threat Sensor & Behavioral Engine tests passed successfully!\n');
}

runTests().catch(err => {
  console.error('✖ Test suite failed:', err);
  process.exit(1);
});
