import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import fsPromises from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

console.log('🧪 Testing CLI state leftovers: hosts marker safety (B9), down cleanup (B10), chart path default (B11), deleteInstance honesty (B12), scenarios XDG (B13)...');

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmpRoot = await fsPromises.mkdtemp(path.join(os.tmpdir(), 'vigilante-state-leftovers-'));
process.env.XDG_CONFIG_HOME = tmpRoot;
process.env.HOME = path.join(tmpRoot, 'fake-home');

const { syncHosts, removeHosts, BLOCK_START, BLOCK_END } = await import('../src/engine/hosts.js');
const { deleteInstance } = await import('../src/engine/instances.js');
const { loadConfig, ensureVigilanteConfig, getVigilanteScenariosDir, getVigilanteConfigDir } = await import('../src/engine/config.js');
const { ScenarioEngine } = await import('../src/engine/scenarios.js');
const { VigilLocalModule, DEFAULT_VIGIL_LOCAL_CHART_PATH } = await import('../src/modules/vigil-local/index.js');

const count = (haystack, needle) => haystack.split(needle).length - 1;

// Test 1 (B9): syncHosts repairs an orphan BEGIN marker without duplicating
// the block or swallowing the user entry that followed it
{
  const hostsPath = path.join(tmpRoot, 'hosts-orphan');
  await fsPromises.writeFile(hostsPath, [
    '127.0.0.1 myhost.local',
    BLOCK_START,
    '10.0.0.5 user-important.local',
    ''
  ].join('\n'));

  await syncHosts({ hostsPath, hostnames: ['vigilante.local'], ip: '127.0.0.1' });
  const content = await fsPromises.readFile(hostsPath, 'utf8');
  assert.strictEqual(count(content, BLOCK_START), 1, 'Exactly one BEGIN marker after repair');
  assert.strictEqual(count(content, BLOCK_END), 1, 'Exactly one END marker after repair');
  assert.ok(content.includes('10.0.0.5 user-important.local'), 'User entry preserved');
  const block = content.slice(content.indexOf(BLOCK_START), content.indexOf(BLOCK_END));
  assert.ok(!block.includes('user-important.local'), 'User entry must not be absorbed into the managed block');
  assert.ok(block.includes('127.0.0.1 vigilante.local'), 'Managed entry present in the block');

  // Idempotent: a second sync changes nothing
  const again = await syncHosts({ hostsPath, hostnames: ['vigilante.local'], ip: '127.0.0.1' });
  assert.strictEqual(again.alreadySynced, true);
}
console.log('✔ Test 1 passed: Orphan BEGIN marker repaired without data loss or duplication (B9).');

// Test 2 (B9): removeHosts on a legacy corrupted file (orphan marker plus a
// complete block) removes the managed entries but preserves the user line
{
  const hostsPath = path.join(tmpRoot, 'hosts-corrupt');
  await fsPromises.writeFile(hostsPath, [
    '127.0.0.1 myhost.local',
    BLOCK_START,
    '10.0.0.5 user-important.local',
    BLOCK_START,
    '127.0.0.1 vigilante.local',
    BLOCK_END,
    '192.168.1.10 nas.local',
    ''
  ].join('\n'));

  const res = await removeHosts({ hostsPath });
  assert.strictEqual(res.removed, true);
  assert.strictEqual(res.removedBlocks, 1);
  const content = await fsPromises.readFile(hostsPath, 'utf8');
  assert.ok(!content.includes(BLOCK_START) && !content.includes(BLOCK_END), 'All markers removed');
  assert.ok(!content.includes('vigilante.local'), 'Managed entries removed');
  assert.ok(content.includes('10.0.0.5 user-important.local'), 'User entry after orphan marker preserved');
  assert.ok(content.includes('127.0.0.1 myhost.local') && content.includes('192.168.1.10 nas.local'), 'Surrounding entries preserved');
}
console.log('✔ Test 2 passed: removeHosts never deletes user entries around malformed markers (B9).');

// Test 3 (B12): deleteInstance reports what actually happened
{
  // No k3d cluster exists for this name (and no k3d binary in the test
  // environment): the old code still reported deletedCluster: true.
  const ghost = await deleteInstance('ghost-instance', { deleteCluster: true });
  assert.strictEqual(ghost.deletedCluster, false, 'A not-found cluster is not a deleted cluster');
  assert.strictEqual(ghost.clusterStatus, 'not_found');
  assert.strictEqual(ghost.success, true, 'Removing local state for a ghost still succeeds');
  assert.strictEqual(ghost.removedInstanceDir, true);

  // Directory-removal failure must surface in success, not be swallowed:
  // make `instances` a regular file so removing a child path fails.
  const brokenXdg = path.join(tmpRoot, 'broken-xdg');
  await fsPromises.mkdir(path.join(brokenXdg, 'vigilante'), { recursive: true });
  await fsPromises.writeFile(path.join(brokenXdg, 'vigilante', 'instances'), 'not a directory');
  const prevXdg = process.env.XDG_CONFIG_HOME;
  process.env.XDG_CONFIG_HOME = brokenXdg;
  try {
    const broken = await deleteInstance('some-instance', { deleteCluster: false });
    assert.strictEqual(broken.success, false, 'Directory removal failure must flip success to false');
    assert.strictEqual(broken.removedInstanceDir, false);
    assert.ok(broken.error && broken.error.includes('instance directory removal failed'));
  } finally {
    process.env.XDG_CONFIG_HOME = prevXdg;
  }
}
console.log('✔ Test 3 passed: deleteInstance distinguishes not-found from deleted and surfaces removal failures (B12).');

// Test 4 (B11): no personal home directory in defaults, generated config, or
// the vigil-local fallback chain
{
  const cfg = loadConfig();
  assert.strictEqual(cfg.modules.vigilLocal.chartPath, '', 'Default chartPath is empty so module fallbacks apply');
  const ensured = await ensureVigilanteConfig();
  const rawConfig = await fsPromises.readFile(ensured.configFile, 'utf8');
  assert.ok(!rawConfig.includes('djehauti'), 'Generated config.yaml contains no personal path');
  const mod = new VigilLocalModule();
  assert.strictEqual(mod.getChartPath(), DEFAULT_VIGIL_LOCAL_CHART_PATH, 'Module fallback is reachable again');
}
console.log('✔ Test 4 passed: vigil-local chart path defaults are machine-independent (B11).');

// Test 5 (B13): ScenarioEngine follows XDG_CONFIG_HOME like every other engine
{
  const engine = new ScenarioEngine();
  assert.strictEqual(engine.userScenarioDir, getVigilanteScenariosDir());
  assert.strictEqual(engine.userScenarioDir, path.join(getVigilanteConfigDir(), 'scenarios'));
  assert.ok(!engine.userScenarioDir.startsWith(process.env.HOME), 'Must not be derived from $HOME/.config');
  const ensured = await ensureVigilanteConfig();
  assert.strictEqual(ensured.scenariosDir, engine.userScenarioDir);
  assert.ok(fs.existsSync(ensured.scenariosDir), 'ensureVigilanteConfig creates the scenarios directory');
}
console.log('✔ Test 5 passed: User scenarios live under the XDG config tree (B13).');

// Test 6 (B10): `vigilante down` removes instance state, including the TLS
// private key — exercised through the real bin in an isolated XDG home
{
  const downXdg = path.join(tmpRoot, 'down-xdg');
  const instanceDir = path.join(downXdg, 'vigilante', 'instances', 'vigilante-dev');
  await fsPromises.mkdir(path.join(instanceDir, 'certs'), { recursive: true });
  await fsPromises.writeFile(path.join(downXdg, 'vigilante', 'config.yaml'), [
    'hostr:',
    '  enabled: true',
    '  autoCleanOnDown: false',
    ''
  ].join('\n'));
  await fsPromises.writeFile(path.join(instanceDir, 'instance.json'), '{"instanceName":"vigilante-dev"}');
  await fsPromises.writeFile(path.join(instanceDir, 'certs', 'vigilante.local.pem'), 'CERT');
  await fsPromises.writeFile(path.join(instanceDir, 'certs', 'vigilante.local-key.pem'), 'PRIVATE KEY');

  const res = spawnSync(process.execPath, [path.join(repoRoot, 'bin', 'vigilante.js'), 'down', '--non-interactive'], {
    cwd: repoRoot,
    env: { ...process.env, XDG_CONFIG_HOME: downXdg },
    input: '',
    encoding: 'utf8',
    timeout: 60000
  });
  assert(!res.error, `down failed to run: ${res.error?.message}`);
  assert.strictEqual(res.status, 0, `down should exit 0, output: ${(res.stdout || '').slice(-500)}`);
  assert.ok(!fs.existsSync(instanceDir), 'down must remove the instance directory (metadata, certs, private key)');
}
console.log('✔ Test 6 passed: `down` removes instance state and the TLS private key (B10).');

console.log('\n🎉 All CLI state-leftover tests passed successfully!\n');
