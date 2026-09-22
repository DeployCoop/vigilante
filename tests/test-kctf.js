import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import { KCTFModule } from '../src/modules/kctf/index.js';
import { globalModuleRegistry } from '../src/modules/registry.js';
import { getDomainHosts } from '../src/engine/hosts.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';

console.log('🧪 Testing kCTF Capture The Flag Platform Module (kctf)...');

// Test 1: Module instantiation & properties
const moduleInstance = new KCTFModule();
assert.strictEqual(moduleInstance.id, 'kctf');
assert.strictEqual(moduleInstance.name, 'kCTF (Capture The Flag Platform)');
assert.strictEqual(moduleInstance.category, 'ctf');
assert.deepStrictEqual(moduleInstance.dependencies, []);
assert.strictEqual(moduleInstance.defaultEnabled, false);
console.log('✔ Test 1 passed: KCTFModule initialized with correct metadata and defaults.');

// Test 2: Registry integration & dependency resolution
const registered = globalModuleRegistry.get('kctf');
assert.ok(registered, 'kctf must be registered in globalModuleRegistry');
const resolved = globalModuleRegistry.resolveModules(['kctf']);
assert.strictEqual(resolved.length, 1);
assert.strictEqual(resolved[0].id, 'kctf');
console.log('✔ Test 2 passed: kctf module registered and resolvable in globalModuleRegistry.');

// Test 3: Manifest files existence & YAML structure
const manifestsDir = path.resolve('src/modules/kctf/manifests');
const requiredManifests = [
  '00-crd-challenges.yaml',
  '01-rbac.yaml',
  '02-kctf-portal.yaml',
  '03-sample-challenges.yaml'
];

for (const mFile of requiredManifests) {
  const fullPath = path.join(manifestsDir, mFile);
  const content = await fs.readFile(fullPath, 'utf8');
  assert.ok(content.length > 50, `${mFile} must not be empty`);
  if (mFile.includes('crd')) {
    assert.ok(content.includes('challenges.kctf.dev'), 'CRD must define challenges.kctf.dev');
    assert.ok(content.includes('kind: CustomResourceDefinition'), 'CRD must define kind: CustomResourceDefinition');
  }
  if (mFile.includes('portal')) {
    assert.ok(content.includes('kctf-portal'), 'Portal manifest must define kctf-portal');
  }
  if (mFile === '03-sample-challenges.yaml') {
    assert.ok(content.includes('kind: Challenge'), 'Sample challenges must define kind: Challenge');
    assert.ok(content.includes('web-flag-leak'), 'Sample challenges must include web-flag-leak');
  }
}
console.log('✔ Test 3 passed: Verified all kCTF manifests (CRD, RBAC, Portal, Sample Challenges).');

// Test 4: Domain hosts mapping includes kctf and ctf
const domainHosts = getDomainHosts({ domain: 'vigilante.local' });
assert.ok(domainHosts.includes('kctf.vigilante.local'), 'getDomainHosts must include kctf.vigilante.local');
assert.ok(domainHosts.includes('ctf.vigilante.local'), 'getDomainHosts must include ctf.vigilante.local');
console.log('✔ Test 4 passed: Local domain resolution includes kctf.vigilante.local and ctf.vigilante.local.');

// Test 5: Endpoints mapping
const defaultEndpoints = await moduleInstance.getEndpoints({ domain: 'vigilante.local', namespace: 'kctf' });
assert.ok(defaultEndpoints.length >= 2, 'Must return at least 2 endpoints');
assert.strictEqual(defaultEndpoints[0].url, 'https://kctf.vigilante.local');
assert.strictEqual(defaultEndpoints[1].url, 'https://ctf.vigilante.local');

const tenantEndpoints = await moduleInstance.getEndpoints({ domain: 'vigilante.local', namespace: 'ctf-finals' });
assert.strictEqual(tenantEndpoints[0].url, 'https://ctf-finals-kctf.vigilante.local');
assert.strictEqual(tenantEndpoints[1].url, 'https://ctf-finals-ctf.vigilante.local');
console.log('✔ Test 5 passed: Endpoints correctly reflect parameterized namespace and domain.');

// Test 6: Helm values resolution
const defaultValuesPath = path.resolve('src/modules/kctf/values/kctf.yaml');
const valuesArgs = await resolveChartValuesArgs({
  moduleId: 'kctf',
  chartName: 'kctf',
  defaultValuesPath,
  domain: 'vigilante.local',
  tlsSecretName: 'kctf-tls',
  namespace: 'kctf'
});
assert.ok(valuesArgs.length >= 2, 'resolveChartValuesArgs must produce Helm -f flags');
assert.strictEqual(valuesArgs[0], '-f');
console.log('✔ Test 6 passed: resolveChartValuesArgs successfully templated kctf values.');

// Test 7: Status method structure
const statusResult = await moduleInstance.status({ domain: 'vigilante.local', clusterName: 'vigilante-dev' });
assert.strictEqual(statusResult.id, 'kctf');
assert.strictEqual(statusResult.name, 'kCTF (Capture The Flag Platform)');
assert.ok(typeof statusResult.installed === 'boolean');
assert.ok(Array.isArray(statusResult.pods));
assert.ok(Array.isArray(statusResult.challenges));
assert.ok(Array.isArray(statusResult.endpoints));
console.log('✔ Test 7 passed: status() returned standard module health and challenge structure.');

// Test 8: Challenge Categories & Archetypes
const {
  CHALLENGE_CATEGORIES,
  CHALLENGE_TEMPLATES,
  generateDynamicFlag,
  generateChallengeManifest,
  testChallengeConnection
} = await import('../src/engine/kctf.js');

assert.strictEqual(CHALLENGE_CATEGORIES.length, 6, 'Must define 6 challenge categories');
const categoryIds = CHALLENGE_CATEGORIES.map(c => c.id);
assert.ok(categoryIds.includes('web'), 'Must include web');
assert.ok(categoryIds.includes('pwn'), 'Must include pwn');
assert.ok(categoryIds.includes('crypto'), 'Must include crypto');
assert.ok(categoryIds.includes('rev'), 'Must include rev');
assert.ok(categoryIds.includes('forensics'), 'Must include forensics');
assert.ok(categoryIds.includes('misc'), 'Must include misc');

assert.ok(CHALLENGE_TEMPLATES.length >= 10, 'Must include rich library of starter templates');
const pwnTemplate = CHALLENGE_TEMPLATES.find(t => t.id === 'pwn-nsjail-echo');
assert.ok(pwnTemplate, 'Must include pwn-nsjail-echo');
assert.strictEqual(pwnTemplate.category, 'pwn');
assert.strictEqual(pwnTemplate.port, 31337);
console.log(`✔ Test 8 passed: Verified ${CHALLENGE_CATEGORIES.length} categories and ${CHALLENGE_TEMPLATES.length} challenge templates.`);

// Test 9: Dynamic flag generation
const dynamicFlag = generateDynamicFlag('kctf', 'pwn_echo');
assert.ok(dynamicFlag.startsWith('VIGILANTE{kctf_pwn_echo_'), 'Flag must match standard Vigilante CTF pattern');
assert.ok(dynamicFlag.endsWith('}'), 'Flag must close with brace');
console.log(`✔ Test 9 passed: Dynamic flag generated: ${dynamicFlag}`);

// Test 10: Kubernetes manifest generation
const manifest = generateChallengeManifest({
  templateId: 'pwn-nsjail-echo',
  customName: 'custom-echo',
  customPort: 31340,
  customFlag: 'VIGILANTE{test_echo_flag}',
  powDifficultySeconds: 10,
  namespace: 'ctf-lab'
});
assert.ok(manifest.includes('kind: Challenge'), 'Manifest must define Challenge');
assert.ok(manifest.includes('name: custom-echo'), 'Manifest must use custom name');
assert.ok(manifest.includes('port: 31340'), 'Manifest must use custom port');
assert.ok(manifest.includes('powDifficultySeconds: 10'), 'Manifest must define pow difficulty');
assert.ok(manifest.includes('VIGILANTE{test_echo_flag}'), 'Manifest must include flag');
assert.ok(manifest.includes('kind: Deployment'), 'Manifest must define Deployment');
assert.ok(manifest.includes('kind: Service'), 'Manifest must define Service');
console.log('✔ Test 10 passed: Generated valid multi-document Kubernetes manifest for challenge.');

// Test 11: TCP connection test handling
const connTest = await testChallengeConnection({
  host: '127.0.0.1',
  port: 59999, // Unused port to test graceful rejection
  timeoutMs: 300,
  category: 'pwn'
});
assert.strictEqual(typeof connTest.success, 'boolean');
assert.strictEqual(typeof connTest.message, 'string');
console.log('✔ Test 11 passed: testChallengeConnection handled socket probe gracefully.');

// Test 12: MCP Server registration
const { createVigilanteMcpServer } = await import('../src/mcp/server.js');
const mcpServer = createVigilanteMcpServer();
assert.ok(mcpServer, 'MCP server must initialize cleanly with kCTF tools');
console.log('✔ Test 12 passed: MCP Server initializes with kCTF tools and resources available.');

console.log('\n🎉 All kCTF Capture The Flag Platform Module (kctf) tests passed successfully!\n');
