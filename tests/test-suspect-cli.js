import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Isolated config home BEFORE any engine state is touched.
const tmpXdg = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-suspect-cli-xdg-'));
process.env.XDG_CONFIG_HOME = tmpXdg;

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const engine = (name) => path.join(repoRoot, 'packages/vigilante_lib/src/engine', name);

const { syncHosts, removeHosts } = await import(engine('hosts.js'));
const { setupCertificates } = await import(engine('certs.js'));
const { listK3dClusters, createK3dCluster } = await import(engine('cluster.js'));
const { ensureNamespace } = await import(engine('k8s.js'));
const { getVigilanteConfigDir, loadConfig, DEFAULT_CONFIG } = await import(engine('config.js'));
const { listChartValues } = await import(engine('helm.js'));
const execModule = await import(path.join(repoRoot, 'packages/vigilante_lib/src/utils/exec.js'));
const { commandExists } = execModule;

function makeStubDir(stubs) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-stubs-'));
  for (const [name, body] of Object.entries(stubs)) {
    fs.writeFileSync(path.join(dir, name), body, { mode: 0o755 });
  }
  return dir;
}

async function withPath(dir, fn) {
  const old = process.env.PATH;
  process.env.PATH = dir + ':' + old;
  try {
    return await fn();
  } finally {
    process.env.PATH = old;
  }
}

// ---------------------------------------------------------------------------
// 1. hosts (S2): the shared managed block merges per-domain slices.
// ---------------------------------------------------------------------------
{
  const hostsPath = path.join(tmpXdg, 'hosts');
  await fsp.writeFile(hostsPath, '127.0.0.1 localhost\n::1 localhost\n');
  await syncHosts({ domain: 'alpha.local', hostsPath });
  await syncHosts({ domain: 'beta.local', hostsPath });
  let content = await fsp.readFile(hostsPath, 'utf8');
  assert.ok(content.includes('alpha.local'), 'alpha entries must survive the beta sync');
  assert.ok(content.includes('beta.local'), 'beta entries must be present');
  assert.ok(content.includes('127.0.0.1 localhost'), 'user lines preserved');

  const scoped = await removeHosts({ domain: 'beta.local', hostsPath });
  assert.strictEqual(scoped.removed, true);
  assert.ok(scoped.remainingEntries > 0);
  content = await fsp.readFile(hostsPath, 'utf8');
  assert.ok(!content.includes('beta.local'), 'beta entries removed');
  assert.ok(content.includes('alpha.local'), 'alpha entries survive the scoped removal');

  const all = await removeHosts({ hostsPath });
  assert.strictEqual(all.removed, true);
  content = await fsp.readFile(hostsPath, 'utf8');
  assert.ok(!content.includes('alpha.local'), 'unscoped removal clears the block');
}
console.log('✔ Group 1 passed: hosts sync merges domains; removal can be domain-scoped.');

// ---------------------------------------------------------------------------
// 2. certs (S7): existing certificates are reused, not regenerated.
// ---------------------------------------------------------------------------
{
  const log = path.join(tmpXdg, 'mkcert.log');
  const stubDir = makeStubDir({
    mkcert: `#!/bin/sh
echo "$@" >> ${log}
if [ "$1" = "-CAROOT" ]; then echo /tmp/fake-caroot; exit 0; fi
cert=""; key=""
while [ $# -gt 0 ]; do
  case "$1" in
    -cert-file) cert="$2"; shift 2;;
    -key-file) key="$2"; shift 2;;
    *) shift;;
  esac
done
[ -n "$cert" ] && echo CERT > "$cert"
[ -n "$key" ] && echo KEY > "$key"
exit 0
`
  });
  await withPath(stubDir, async () => {
    const first = await setupCertificates('reuse.local', { certDir: path.join(tmpXdg, 'certs') });
    assert.strictEqual(first.regenerated, true);
    const callsAfterFirst = fs.readFileSync(log, 'utf8').trim().split('\n').length;
    assert.ok(callsAfterFirst >= 2, 'first setup installs the CA and generates');

    const second = await setupCertificates('reuse.local', { certDir: path.join(tmpXdg, 'certs') });
    assert.strictEqual(second.regenerated, false);
    assert.strictEqual(second.certPath, first.certPath);
    assert.strictEqual(fs.readFileSync(log, 'utf8').trim().split('\n').length, callsAfterFirst,
      'second setup must not invoke mkcert at all');

    const forced = await setupCertificates('reuse.local', { certDir: path.join(tmpXdg, 'certs'), force: true });
    assert.strictEqual(forced.regenerated, true);
    assert.ok(fs.readFileSync(log, 'utf8').trim().split('\n').length > callsAfterFirst,
      'force: true regenerates');
  });
}
console.log('✔ Group 2 passed: certificates are reused across runs; regeneration is opt-in via force.');

// ---------------------------------------------------------------------------
// 3. cluster (S6 + S1 engine side): list failures are logged, reuse warns,
//    explicit ports reach the create argv, invalid ports are rejected.
// ---------------------------------------------------------------------------
{
  const failDir = makeStubDir({ k3d: '#!/bin/sh\necho "daemon exploded" >&2\nexit 1\n' });
  await withPath(failDir, async () => {
    assert.deepStrictEqual(await listK3dClusters(), [], 'contract preserved: [] on failure');
  });

  const argvLog = path.join(tmpXdg, 'k3d-argv.log');
  const okDir = makeStubDir({
    k3d: `#!/bin/sh
echo "$@" >> ${argvLog}
if [ "$1 $2" = "cluster list" ]; then echo '[]'; exit 0; fi
exit 0
`,
    kubectl: `#!/bin/sh
case "$*" in
  *"/readyz"*) echo ok;;
  *) echo '{}';;
esac
exit 0
`
  });
  await withPath(okDir, async () => {
    const created = await createK3dCluster('ports-inst', { httpPort: 8080, httpsPort: 8443, onLog: () => {} });
    assert.strictEqual(created.status, 'created');
    const argv = fs.readFileSync(argvLog, 'utf8');
    assert.ok(argv.includes('8080:80@loadbalancer'), argv);
    assert.ok(argv.includes('8443:443@loadbalancer'), argv);
    await assert.rejects(() => createK3dCluster('bad-port', { httpPort: 70000 }), /Invalid httpPort/);
  });

  const existsDir = makeStubDir({
    k3d: `#!/bin/sh
if [ "$1 $2" = "cluster list" ]; then echo '[{"name":"ports-inst","serversCount":1,"serversRunning":1,"agentsCount":1,"agentsRunning":1}]'; exit 0; fi
exit 0
`,
    kubectl: '#!/bin/sh\nexit 0\n'
  });
  await withPath(existsDir, async () => {
    const logs = [];
    const reused = await createK3dCluster('ports-inst', { httpPort: 9999, onLog: (m) => logs.push(m) });
    assert.strictEqual(reused.status, 'exists');
    assert.ok(logs.some(m => m.includes('NOT re-applied')), 'reuse with explicit ports must warn they are not re-applied');
  });
}
console.log('✔ Group 3 passed: cluster listing/reuse/ports behave honestly.');

// ---------------------------------------------------------------------------
// 4. instances ports surface (S1): config defaults exist and metadata
//    round-trips through listInstances (the App up-flow now feeds both).
// ---------------------------------------------------------------------------
{
  assert.strictEqual(DEFAULT_CONFIG.defaults.httpPort, 80);
  assert.strictEqual(DEFAULT_CONFIG.defaults.httpsPort, 443);
  const { saveInstanceMetadata, listInstances } = await import(engine('instances.js'));
  await saveInstanceMetadata('ports-display', { httpPort: 8080, httpsPort: 8443 });
  const listed = await listInstances();
  const inst = listed.find(i => i.name === 'ports-display' || i.instanceName === 'ports-display');
  assert.ok(inst, 'instance listed');
  assert.strictEqual(inst.httpPort, 8080);
  assert.strictEqual(inst.httpsPort, 8443);
}
console.log('✔ Group 4 passed: instance port defaults exist and persisted ports are displayed.');

// ---------------------------------------------------------------------------
// 5. prereqs (S8): commandExists works without a `which` binary.
// ---------------------------------------------------------------------------
{
  const stubDir = makeStubDir({
    docker: '#!/bin/sh\nexit 0\n',
    k3d: '#!/bin/sh\nexit 0\n'
  });
  const oldPath = process.env.PATH;
  process.env.PATH = stubDir; // deliberately no `which` anywhere
  try {
    assert.strictEqual(await commandExists('docker'), true);
    assert.strictEqual(await commandExists('definitely-not-a-real-tool-xyz'), false);
  } finally {
    process.env.PATH = oldPath;
  }
}
console.log('✔ Group 5 passed: commandExists falls back to a PATH scan when `which` is absent.');

// ---------------------------------------------------------------------------
// 6. config (S5): the config-bearing dir wins when both trees exist, and a
//    partial theme colors map merges over the defaults.
// ---------------------------------------------------------------------------
{
  const plain = path.join(tmpXdg, 'vigilante');
  const dot = path.join(tmpXdg, '.vigilante');
  await fsp.mkdir(plain, { recursive: true });
  await fsp.writeFile(path.join(plain, 'config.yaml'),
    'defaults:\n  domain: "custom.example"\ntheme:\n  name: dracula\n  colors:\n    primary: hotpink\n');
  assert.strictEqual(getVigilanteConfigDir(), plain);
  await fsp.mkdir(dot, { recursive: true }); // the stray empty dir appears
  assert.strictEqual(getVigilanteConfigDir(), plain, 'an empty .vigilante must not orphan the live tree');
  const cfg = loadConfig();
  assert.strictEqual(cfg.defaults.domain, 'custom.example');
  // Theme overrides stay sparse in loadConfig BY DESIGN: resolveTheme
  // (the only consumer) merges them over the NAMED theme's palette.
  // Pin that end-to-end behavior instead of a loadConfig-side merge,
  // which would poison the per-theme fallback with default colors.
  assert.strictEqual(cfg.theme.colors.primary, 'hotpink');
  const { resolveTheme, THEMES } = await import(path.join(repoRoot, 'apps/ink/src/ui/theme.js'));
  const resolved = resolveTheme(cfg);
  assert.strictEqual(resolved.primary, 'hotpink');
  assert.strictEqual(resolved.border, THEMES.dracula.border, 'named-theme fallback intact');
  assert.strictEqual(Object.keys(resolved).length >= Object.keys(DEFAULT_CONFIG.theme.colors).length, true);
}
console.log('✔ Group 6 passed: config dir resolution is stable and theme colors merge over defaults.');

// ---------------------------------------------------------------------------
// 7. namespaces (S9): invalid names are rejected before kubectl; the UI
//    sanitizer's contract is enforced at the engine boundary.
// ---------------------------------------------------------------------------
{
  await assert.rejects(() => ensureNamespace('-prod-ns-'), /Invalid namespace/);
  await assert.rejects(() => ensureNamespace('---'), /Invalid namespace/);
  await assert.rejects(() => ensureNamespace('a'.repeat(80)), /Invalid namespace/);
  const stubDir = makeStubDir({
    kubectl: '#!/bin/sh\nif [ "$1" = "get" ]; then exit 1; fi\nexit 0\n'
  });
  await withPath(stubDir, async () => {
    await ensureNamespace('valid-ns-1'); // must not throw
  });
}
console.log('✔ Group 7 passed: ensureNamespace validates DNS labels; valid names proceed.');

// ---------------------------------------------------------------------------
// 8. helm (S4): the modules dir resolves through fileURLToPath, so the
//    engine works from a path containing spaces.
// ---------------------------------------------------------------------------
{
  const spacedRoot = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-space-')), 'My Projects');
  const libDest = path.join(spacedRoot, 'libsrc');
  fs.cpSync(path.join(repoRoot, 'packages/vigilante_lib/src'), libDest, { recursive: true, dereference: true });
  fs.symlinkSync(path.join(repoRoot, 'packages/vigilante_lib/node_modules'), path.join(spacedRoot, 'node_modules'), 'dir');
  const childCode = `const m = await import(${JSON.stringify(pathToFileURL(path.join(libDest, 'engine/helm.js')).href)});
const values = await m.listChartValues();
console.log('CHART_VALUES=' + values.length);`;
  const out = execFileSync(process.execPath, ['--input-type=module', '-e', childCode], {
    encoding: 'utf8',
    env: { ...process.env, XDG_CONFIG_HOME: tmpXdg }
  });
  const count = Number(out.match(/CHART_VALUES=(\d+)/)[1]);
  assert.ok(count > 0, `listChartValues from a spaced path must find charts (got ${count})`);
  const normal = await listChartValues();
  assert.strictEqual(count, normal.length);
}
console.log('✔ Group 8 passed: helm chart discovery works from paths with spaces.');

// ---------------------------------------------------------------------------
// 9. hygiene (D S-2): engines floor everywhere; CI and Pages pin the same
//    Node major.
// ---------------------------------------------------------------------------
{
  for (const rel of ['package.json', 'packages/vigilante_lib/package.json', 'apps/ink/package.json', 'apps/web/package.json', 'apps/githubio/package.json']) {
    const pkg = JSON.parse(await fsp.readFile(path.join(repoRoot, rel), 'utf8'));
    assert.strictEqual(pkg.engines?.node, '>=22.5', `${rel} must declare the Node floor`);
  }
  const deployPages = await fsp.readFile(path.join(repoRoot, '.github/workflows/deploy-pages.yml'), 'utf8');
  assert.ok(deployPages.includes('node-version: "24"'), 'deploy-pages must pin Node 24 like CI');
}
console.log('✔ Group 9 passed: Node engine floor declared in all five packages; workflow pins aligned.');

console.log('\n🎉 All suspect-CLI regression tests passed successfully!\n');
