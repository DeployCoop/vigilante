import assert from 'node:assert';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { load as yamlLoad } from 'js-yaml';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';

import {
  RedAiRangeModule,
  globalModuleRegistry,
  AI_CTF_CATEGORY,
  REDAIRANGE_SCENARIOS,
  assertSafeScenarioId,
  resolveSafeStackPath,
  getRedAiRangeScenario,
  listRedAiRangeScenarios,
  validateStackComposeYaml,
  generateScenarioComposeYaml,
  deriveAiCtfFlag,
  verifyAiCtfFlag,
  redactAiCtfRecord,
  buildAiCtfChallengeCatalog,
  provisionAiCtfChallenge,
  listBridgedAiChallenges,
  teardownBridgedAiChallenge,
  evaluateAiAttackTelemetry
} from '../src/index.js';
import { getDomainHosts } from '../src/engine/hosts.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, '..');

async function runTests() {
  console.log('🧪 Testing RedAiRange AI Red Teaming Module, Isolated DinD Chart, AI-CTF Bridge & MCP Tools...');

  const tmpXdg = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-redairange-test-'));
  process.env.XDG_CONFIG_HOME = tmpXdg;
  const origSecret = process.env.VIGILANTE_CTF_SECRET;
  delete process.env.VIGILANTE_CTF_SECRET;

  try {
    // Test 1: Module metadata & isolated DinD runtime info
    const mod = new RedAiRangeModule();
    assert.strictEqual(mod.id, 'redairange');
    assert.strictEqual(mod.category, 'ai-redteam');
    assert.strictEqual(mod.defaultEnabled, false);
    assert.strictEqual(mod.namespace, 'redairange');
    assert.strictEqual(mod.tlsSecretName, 'redairange-tls');
    assert.deepStrictEqual(mod.dependencies, []);

    const rt = mod.getRuntimeInfo();
    assert.strictEqual(rt.mode, 'k8s-isolated-dind');
    assert.strictEqual(rt.hostDockerSocketMounted, false, 'Must NEVER mount host docker.sock');
    assert.strictEqual(rt.uiPort, 5002);
    assert.ok(rt.supportedProviders.includes('k3d') && rt.supportedProviders.includes('k3s'));
    console.log('✔ Test 1 passed: RedAiRangeModule initialized with isolated DinD runtime & safe defaults.');

    // Test 2: Registry & domain host mapping
    const fromRegistry = globalModuleRegistry.get('redairange');
    assert.ok(fromRegistry, 'redairange must be registered in globalModuleRegistry');
    const resolved = globalModuleRegistry.resolveModules(['redairange']);
    assert.strictEqual(resolved.length, 1);
    assert.strictEqual(resolved[0].id, 'redairange');

    const hosts = getDomainHosts({ domain: 'vigilante.local' });
    assert.ok(hosts.includes('redairange.vigilante.local'), 'getDomainHosts must include redairange.vigilante.local');

    const defaultEps = await mod.getEndpoints({ domain: 'vigilante.local', namespace: 'redairange' });
    assert.strictEqual(defaultEps[0].url, 'https://redairange.vigilante.local');
    const tenantEps = await mod.getEndpoints({ domain: 'vigilante.local', namespace: 'ai-lab' });
    assert.strictEqual(tenantEps[0].url, 'https://ai-lab-redairange.vigilante.local');
    console.log('✔ Test 2 passed: Registry, getDomainHosts, and parameterized endpoints verified.');

    // Test 3: Helm chart manifests & Option A isolation invariant
    const chartDir = path.join(rootDir, 'packages', 'vigilante_lib', 'src', 'modules', 'redairange', 'charts', 'redairange');
    const chartData = yamlLoad(await fs.readFile(path.join(chartDir, 'Chart.yaml'), 'utf8'));
    assert.strictEqual(chartData.name, 'redairange');
    assert.strictEqual(chartData.appVersion, '1');

    const valuesData = yamlLoad(await fs.readFile(path.join(chartDir, 'values.yaml'), 'utf8'));
    assert.strictEqual(valuesData.image.repository, 'erdemozgen/redairange');
    assert.strictEqual(valuesData.dind.enabled, true);
    assert.strictEqual(valuesData.service.port, 5002);
    assert.strictEqual(valuesData.networkPolicy.enabled, true);

    const templatesDir = path.join(chartDir, 'templates');
    for (const tpl of ['_helpers.tpl', 'deployment.yaml', 'service.yaml', 'ingress.yaml', 'pvc.yaml', 'configmap-stacks.yaml', 'networkpolicy.yaml']) {
      await fs.access(path.join(templatesDir, tpl));
    }

    const deployTpl = await fs.readFile(path.join(templatesDir, 'deployment.yaml'), 'utf8');
    assert.ok(deployTpl.includes('unix:///var/run/dind/docker.sock'), 'Deployment must use pod-private DinD Unix socket');
    assert.ok(!deployTpl.includes('hostPath'), 'Deployment must NOT use hostPath (no host docker.sock mount)');
    assert.ok(!deployTpl.includes('/var/run/docker.sock'), 'Deployment must NOT mount host /var/run/docker.sock');
    assert.ok(deployTpl.includes('automountServiceAccountToken: false'), 'Pod must disable K8s service account token automount');
    console.log('✔ Test 3 passed: Verified Option A Helm chart manifests & zero host docker.sock isolation.');

    // Test 4: Helm values templating
    const defaultValuesPath = path.join(rootDir, 'packages', 'vigilante_lib', 'src', 'modules', 'redairange', 'values', 'redairange.yaml');
    const valuesArgs = await resolveChartValuesArgs({
      moduleId: 'redairange',
      chartName: 'redairange',
      defaultValuesPath,
      domain: 'cyberrange.test',
      tlsSecretName: 'rar-tls',
      namespace: 'redairange'
    });
    assert.ok(valuesArgs.includes('-f'));
    const renderedValues = await fs.readFile(valuesArgs[valuesArgs.indexOf('-f') + 1], 'utf8');
    assert.ok(renderedValues.includes('redairange.cyberrange.test'));
    assert.ok(renderedValues.includes('rar-tls'));
    console.log('✔ Test 4 passed: resolveChartValuesArgs templated redairange values cleanly.');

    // Test 5: Scenarios catalog, path containment (Rule 3) & compose security linter
    assert.ok(REDAIRANGE_SCENARIOS.length >= 7);
    assert.strictEqual(AI_CTF_CATEGORY.id, 'ai-redteam');
    assert.ok(getRedAiRangeScenario('gen-ai-target'));
    assert.ok(getRedAiRangeScenario('gen_ai_target'));
    assert.strictEqual(listRedAiRangeScenarios({ kind: 'arsenal' }).length, 1);

    assert.throws(() => assertSafeScenarioId('../etc/passwd'), /Invalid RedAiRange scenario ID/);
    assert.throws(() => resolveSafeStackPath('/opt/stacks', '../escape'), /Invalid RedAiRange scenario ID/);
    assert.strictEqual(resolveSafeStackPath('/opt/stacks', 'gen_ai_target'), path.resolve('/opt/stacks', 'gen_ai_target'));

    const validCompose = generateScenarioComposeYaml('gen-ai-target');
    const okVal = validateStackComposeYaml(validCompose);
    assert.strictEqual(okVal.valid, true, `Generated compose must pass validation: ${okVal.errors.join(', ')}`);

    const hostSockCompose = `services:\n  bad:\n    image: alpine:3.20\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n`;
    const badSockVal = validateStackComposeYaml(hostSockCompose);
    assert.strictEqual(badSockVal.valid, false, 'Must reject host docker.sock mounts in scenario stacks');
    assert.ok(badSockVal.errors.some((e) => e.includes('forbidden host path')));

    const privCompose = `services:\n  bad:\n    image: alpine:3.20\n    privileged: true\n    network_mode: host\n`;
    const badPrivVal = validateStackComposeYaml(privCompose);
    assert.strictEqual(badPrivVal.valid, false);
    assert.ok(badPrivVal.errors.length >= 2);
    console.log('✔ Test 5 passed: Path containment and compose security linter blocked unsafe mounts & privileged stacks.');

    // Test 6: Fail-closed AI-CTF flag derivation & verification (Rule 2)
    assert.throws(
      () => deriveAiCtfFlag({ teamId: 'team_alpha', scenarioId: 'gen-ai-target' }),
      /CTF flag secret is not configured/
    );
    await assert.rejects(
      () => provisionAiCtfChallenge({ scenarioId: 'gen-ai-target', teamId: 'team_alpha', mock: true }),
      /CTF flag secret is not configured/
    );

    const SECRET = 'redairange-unit-test-secret';
    process.env.VIGILANTE_CTF_SECRET = SECRET;

    const flag = deriveAiCtfFlag({ teamId: 'team_alpha', scenarioId: 'gen-ai-target' });
    assert.ok(flag.startsWith('VIGILANTE{ai-gen-ai-target_team_alpha_'));
    const verOk = verifyAiCtfFlag({ teamId: 'team_alpha', scenarioId: 'gen-ai-target', submittedFlag: flag });
    assert.strictEqual(verOk.valid, true);
    const verBad = verifyAiCtfFlag({ teamId: 'team_alpha', scenarioId: 'gen-ai-target', submittedFlag: 'VIGILANTE{forged}' });
    assert.strictEqual(verBad.valid, false);
    console.log('✔ Test 6 passed: Fail-closed AI-CTF HMAC flag derivation and constant-time verification verified.');

    // Test 7: AI-CTF Bridge provisioning, synthetic marking (Rule 4), redaction & teardown
    const catalog = buildAiCtfChallengeCatalog({ domain: 'vigilante.local' });
    assert.ok(catalog.length >= 6, 'Catalog must bridge all RedAiRange target scenarios');
    assert.ok(catalog.every((c) => c.category === 'ai-redteam' && c.isDynamicFlag === true));

    const record = await provisionAiCtfChallenge({
      scenarioId: 'model-tampering',
      teamId: 'team_alpha',
      mock: true
    });
    assert.strictEqual(record.synthetic, true, 'Mock mode must set synthetic: true (D19 invariant)');
    assert.strictEqual(record.runner, 'none', 'Mock mode must set runner: none (D19 invariant)');
    assert.ok(record.flag && record.composeYaml.includes(record.flag));

    const redacted = redactAiCtfRecord(record);
    assert.ok(!('flag' in redacted) && !('composeYaml' in redacted));

    const listed = await listBridgedAiChallenges({ teamId: 'team_alpha' });
    assert.strictEqual(listed.length, 1);
    assert.ok(!('flag' in listed[0]) && !('composeYaml' in listed[0]), 'Default list must redact flag & composeYaml');

    const teardown = await teardownBridgedAiChallenge({ bridgeId: record.id, mock: true });
    assert.strictEqual(teardown.success, true);
    assert.strictEqual((await listBridgedAiChallenges({ teamId: 'team_alpha' })).length, 0);
    console.log('✔ Test 7 passed: AI-CTF bridge persistence, D19 synthetic marking, secret redaction & teardown verified.');

    // Test 8: Purple-Team / Falco telemetry mapping
    const tel = evaluateAiAttackTelemetry('model-tampering');
    assert.strictEqual(tel.recommendedSoar, 'ISOLATE_POD');
    assert.ok(tel.mitreAtlas.includes('AML.T0018'));
    console.log('✔ Test 8 passed: Purple-Team / Falco / MITRE ATLAS telemetry mapping verified.');

    // Test 9: MCP Server Resources & Tools Integration
    const server = createVigilanteMcpServer();
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const client = new Client({ name: 'redairange-test-client', version: '0.1.0' }, { capabilities: {} });
    await server.connect(serverTransport);
    await client.connect(clientTransport);

    const resources = (await client.listResources()).resources || [];
    assert.ok(resources.some((r) => r.uri === 'vigilante://redairange/status'));
    assert.ok(resources.some((r) => r.uri === 'vigilante://redairange/scenarios'));

    const scRes = await client.readResource({ uri: 'vigilante://redairange/scenarios' });
    const parsedSc = JSON.parse(scRes.contents[0].text);
    assert.ok(parsedSc.count >= 7);

    const tools = (await client.listTools()).tools || [];
    for (const expectedTool of [
      'get_redairange_status',
      'list_redairange_scenarios',
      'generate_redairange_compose',
      'bridge_redairange_to_ctf',
      'evaluate_ai_redteam_telemetry'
    ]) {
      assert.ok(tools.some((t) => t.name === expectedTool), `Missing MCP tool: ${expectedTool}`);
    }

    const stTool = JSON.parse((await client.callTool({ name: 'get_redairange_status', arguments: {} })).content[0].text);
    assert.strictEqual(stTool.runtime.hostDockerSocketMounted, false);

    const listTool = JSON.parse((await client.callTool({ name: 'list_redairange_scenarios', arguments: { kind: 'target' } })).content[0].text);
    assert.ok(listTool.count >= 6);

    const composeTool = JSON.parse((await client.callTool({ name: 'generate_redairange_compose', arguments: { scenarioId: 'privacy-attacks' } })).content[0].text);
    assert.strictEqual(composeTool.validation.valid, true);

    const bridgeTool = JSON.parse((await client.callTool({
      name: 'bridge_redairange_to_ctf',
      arguments: { scenarioId: 'gen-ai-target', teamId: 'mcp-team', mock: true }
    })).content[0].text);
    assert.strictEqual(bridgeTool.challengeId, 'ai-gen-ai-target');
    assert.strictEqual(bridgeTool.synthetic, true);
    assert.strictEqual(bridgeTool.runner, 'none');
    assert.ok(!('flag' in bridgeTool) && !('composeYaml' in bridgeTool), 'MCP bridge tool must never leak flag or composeYaml');

    const telTool = JSON.parse((await client.callTool({
      name: 'evaluate_ai_redteam_telemetry',
      arguments: { scenarioId: 'privacy-attacks' }
    })).content[0].text);
    assert.strictEqual(telTool.recommendedSoar, 'ISOLATE_POD');

    await client.close();
    console.log('✔ Test 9 passed: MCP resources and all 5 RedAiRange tools verified without secret leakage.');

    console.log('\n🎉 All RedAiRange AI Red Teaming & AI-CTF Bridge tests passed successfully!\n');
  } finally {
    if (origSecret === undefined) delete process.env.VIGILANTE_CTF_SECRET;
    else process.env.VIGILANTE_CTF_SECRET = origSecret;
    await fs.rm(tmpXdg, { recursive: true, force: true }).catch(() => {});
  }
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
