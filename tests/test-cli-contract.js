import assert from 'node:assert';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// CLI contract regression tests. These exercise the real bin as a
// subprocess — the contract under test (flags, exit codes, non-interactive
// behaviour without a TTY) only exists at the process boundary. Every run
// gets an isolated XDG_CONFIG_HOME and stdin at EOF (the CI condition).
// Assumes the test environment has no live vigilante cluster tooling
// (no k3d/mkcert/kubectl), matching CI runners.

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const binPath = path.join(repoRoot, 'bin', 'vigilante.js');
const xdg = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-cli-test-'));

const stripAnsi = (s) => s.replace(/\x1b\[[0-9;]*[A-Za-z]/g, '').replace(/\x1b\[[0-9]*[GK]/g, '');

function runCli(args, { cwd = repoRoot, extraEnv = {}, timeout = 30000 } = {}) {
  const res = spawnSync(process.execPath, [binPath, ...args], {
    cwd,
    env: { ...process.env, XDG_CONFIG_HOME: xdg, ...extraEnv },
    input: '',
    encoding: 'utf8',
    timeout
  });
  assert(!res.error, `vigilante ${args.join(' ')} failed to run: ${res.error?.message}`);
  return { status: res.status, out: stripAnsi(`${res.stdout || ''}\n${res.stderr || ''}`) };
}

async function runTests() {
  console.log('🧪 Testing CLI contract (flags, exit codes, non-interactive)...');

  // Test 1: -h prints help and exits 0 (previously launched the `up` UI)
  {
    const { status, out } = runCli(['-h']);
    assert.strictEqual(status, 0);
    assert(out.includes('Usage'), '-h should print usage');
    assert(!out.includes('SELECT SECURITY PACKAGES'), '-h must not launch the up module picker');
    console.log('✔ Test 1 passed: -h prints help, exit 0.');
  }

  // Test 2: -v prints the version and exits 0 (previously launched `up`)
  {
    const { status, out } = runCli(['-v']);
    assert.strictEqual(status, 0);
    assert(/^\d+\.\d+\.\d+\s*$/.test(out.trim()), `-v should print a bare version, got: ${out.trim()}`);
    console.log('✔ Test 2 passed: -v prints version, exit 0.');
  }

  // Test 3: long forms keep working
  {
    const help = runCli(['--help']);
    assert.strictEqual(help.status, 0);
    assert(help.out.includes('Usage'));
    const ver = runCli(['--version']);
    assert.strictEqual(ver.status, 0);
    assert(/^\d+\.\d+\.\d+\s*$/.test(ver.out.trim()));
    console.log('✔ Test 3 passed: --help / --version unchanged.');
  }

  // Test 4: unknown command in non-interactive mode exits 1 without a TTY
  // (previously: Ink raw-mode crash, or a rendered failure with exit 0)
  {
    const { status, out } = runCli(['boguscmd', '--non-interactive']);
    assert.strictEqual(status, 1, `unknown command must exit 1, got ${status}`);
    assert(out.includes('Unknown command: boguscmd'));
    assert(!out.includes('Raw mode is not supported'), 'must not crash on non-TTY stdin');
    console.log('✔ Test 4 passed: unknown command exits 1, no raw-mode crash.');
  }

  // Test 5: status runs headless without a TTY and exits 0
  {
    const { status, out } = runCli(['status', '--non-interactive']);
    assert.strictEqual(status, 0);
    assert(!out.includes('Raw mode is not supported'));
    console.log('✔ Test 5 passed: status --non-interactive runs without a TTY, exit 0.');
  }

  // Test 6: documented view commands are not branded "Unknown command"
  for (const cmd of ['ai', 'openvas', 'battle']) {
    const { status, out } = runCli([cmd, '--non-interactive']);
    assert.strictEqual(status, 0, `${cmd} should exit 0, got ${status}`);
    assert(!out.includes(`Unknown command: ${cmd}`), `${cmd} must not be reported unknown`);
    assert(!out.includes('Raw mode is not supported'));
    console.log(`✔ Test 6 passed: ${cmd} --non-interactive exits 0, not "Unknown command".`);
  }

  // Test 7: `config path` output actually renders in non-interactive mode
  // (previously lost to the batched-log vs auto-exit race)
  {
    const { status, out } = runCli(['config', 'path', '--non-interactive']);
    assert.strictEqual(status, 0);
    assert(out.includes('config.yaml'), 'config path must print the config file path');
    console.log('✔ Test 7 passed: config path prints the config.yaml path.');
  }

  // Test 8: a workflow failure exits 1 (prereqs cannot pass in the test env)
  {
    const { status, out } = runCli(['up', '--non-interactive']);
    assert.strictEqual(status, 1, `failed up must exit 1, got ${status}`);
    assert(out.includes('Execution Failed'));
    console.log('✔ Test 8 passed: failed workflow exits 1.');
  }

  // Test 9: threat-sim --scenario runs the named scenario instead of
  // dropping the flag and hanging on the interactive picker
  {
    const bogus = runCli(['threat-sim', '--scenario', 'no-such-scenario-xyz', '--non-interactive']);
    assert.strictEqual(bogus.status, 1);
    assert(bogus.out.includes('Scenario not found: no-such-scenario-xyz'));

    const real = runCli(['threat-sim', '--scenario', 'credential-bruteforce', '--non-interactive'], { timeout: 60000 });
    assert(real.status === 0 || real.status === 1, `scenario run must terminate, got ${real.status}`);
    assert(
      real.out.includes('Initializing Modular Threat Simulation Pipeline'),
      'the named scenario must be executed, not the picker'
    );
    console.log('✔ Test 9 passed: threat-sim --scenario executes the named scenario; unknown id exits 1.');
  }

  // Test 10: documented `audit --sarif report.sarif` writes the file
  {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-audit-test-'));
    const sarifPath = path.join(dir, 'report.sarif');
    const { status } = runCli(['audit', '.', '--sarif', 'report.sarif'], { cwd: dir });
    assert.strictEqual(status, 0);
    assert(fs.existsSync(sarifPath), '--sarif <file> must write the report file');
    const parsed = JSON.parse(fs.readFileSync(sarifPath, 'utf8'));
    assert(parsed.version === '2.1.0' && Array.isArray(parsed.runs), 'written file must be a SARIF log');
    console.log('✔ Test 10 passed: audit --sarif <file> writes a SARIF report.');
  }

  // Test 11: ctf --mock=false / --no-mock take the real provisioning path
  // (a kubectl stub records invocations; mock mode must never call it,
  // real mode must). Previously --mock=false parsed as the string 'false'
  // and Boolean('false') kept the CLI in mock mode.
  if (process.platform !== 'win32') {
    const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-stub-bin-'));
    const callsLog = path.join(stubDir, 'kubectl-calls.log');
    fs.writeFileSync(path.join(stubDir, 'kubectl'), `#!/bin/sh\necho called >> ${callsLog}\nexit 1\n`, { mode: 0o755 });
    const stubEnv = { PATH: `${stubDir}:${process.env.PATH}` };

    runCli(['ctf', 'spawn', 'web-flag-leak', '--mock'], { extraEnv: stubEnv });
    assert(!fs.existsSync(callsLog), 'mock mode must not invoke kubectl');

    runCli(['ctf', 'spawn', 'web-flag-leak', '--mock=false'], { extraEnv: stubEnv });
    assert(fs.existsSync(callsLog), '--mock=false must invoke kubectl (real provisioning path)');

    fs.rmSync(callsLog, { force: true });
    runCli(['ctf', 'spawn', 'web-flag-leak', '--no-mock'], { extraEnv: stubEnv });
    assert(fs.existsSync(callsLog), '--no-mock must invoke kubectl (real provisioning path)');
    console.log('✔ Test 11 passed: --mock=false and --no-mock leave mock mode.');
  }

  // Test 12: details attached to completed tasks render (skip reasons were
  // previously only shown while a task was still running, i.e. never)
  {
    const { out } = runCli(['up', '--non-interactive', '--skip-prereqs']);
    assert(out.includes('Skipped via flag'), 'completed task detail must render');
    console.log('✔ Test 12 passed: completed-task details render.');
  }

  console.log('🎉 ALL CLI CONTRACT TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ CLI contract test failed:', err);
  process.exit(1);
});
