import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

console.log('🧪 Testing CTF integrity: secret handling, flag verification, redaction, registry persistence...');

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const tmpXdg = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-ctf-integrity-'));
process.env.XDG_CONFIG_HOME = tmpXdg;
const SECRET = 'integrity-test-secret';
delete process.env.VIGILANTE_CTF_SECRET;

const {
  deriveTeamHmacFlag,
  spawnEphemeralSandbox,
  listActiveSandboxes,
  terminateSandbox,
  redactSandboxRecord
} = await import('../src/engine/kctf.js');
const { generateTeamDynamicFlag, TournamentEngine } = await import('../src/engine/tournament.js');

function manualFlag(secret, teamId, challengeId) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(`${teamId}:${challengeId}`);
  return `VIGILANTE{${challengeId}_${teamId}_${hmac.digest('hex').slice(0, 16)}}`;
}

// Test 1: Flag derivation fails closed with no configured secret
assert.throws(
  () => deriveTeamHmacFlag({ teamId: 'team_a', challengeId: 'web-flag-leak' }),
  /CTF flag secret is not configured/
);
assert.throws(
  () => generateTeamDynamicFlag({ teamId: 'team_a', challengeId: 'web-flag-leak' }),
  /CTF flag secret is not configured/
);
await assert.rejects(
  () => spawnEphemeralSandbox({ teamId: 'team_a', challengeId: 'web-flag-leak', mock: true }),
  /CTF flag secret is not configured/
);
console.log('✔ Test 1 passed: Derivation and spawn fail closed when no CTF secret is configured.');

// Test 2: With a configured secret, flags derive from THAT secret only
process.env.VIGILANTE_CTF_SECRET = SECRET;
const derived = deriveTeamHmacFlag({ teamId: 'team_a', challengeId: 'web-flag-leak' });
assert.strictEqual(derived, manualFlag(SECRET, 'team_a', 'web-flag-leak'));
assert.strictEqual(generateTeamDynamicFlag({ teamId: 'team_a', challengeId: 'web-flag-leak' }), derived);
assert.notStrictEqual(derived, manualFlag('vigilante-ctf-secret', 'team_a', 'web-flag-leak'),
  'Flag must not be derivable from the old shipped literal secret');
console.log('✔ Test 2 passed: Flags derive from the configured secret; the shipped literal no longer works.');

// Test 3: The guessable static default flag no longer solves a dynamic challenge
{
  const engine = new TournamentEngine({ secretKey: SECRET });
  const team = engine.registerTeam({ name: 'TeamA' });
  engine.addChallenge({ id: 'web-sqli', name: 'web-sqli' }); // dynamic; defaultFlag auto = VIGILANTE{web-sqli_solve}
  engine.start();
  const staticAttempt = engine.submitFlag({ teamId: team.id, challengeId: 'web-sqli', flag: 'VIGILANTE{web-sqli_solve}' });
  assert.strictEqual(staticAttempt.success, false, 'Static default flag must not solve a dynamic challenge');
  const realFlag = generateTeamDynamicFlag({ teamId: team.id, challengeId: 'web-sqli', secretKey: SECRET });
  const realAttempt = engine.submitFlag({ teamId: team.id, challengeId: 'web-sqli', flag: realFlag });
  assert.strictEqual(realAttempt.success, true, 'The team\'s own dynamic flag must still solve');
}
console.log('✔ Test 3 passed: Static default flag rejected for dynamic challenges; per-team flag accepted.');

// Test 4: The old self-certifying pattern (submitted flag registered as expected) no longer verifies
{
  const engine = new TournamentEngine({ secretKey: SECRET });
  const team = engine.registerTeam({ name: 'DemoTeam' });
  engine.addChallenge({ id: 'x', name: 'x', defaultFlag: 'VIGILANTE{anything-i-want}' });
  engine.start();
  const res = engine.submitFlag({ teamId: team.id, challengeId: 'x', flag: 'VIGILANTE{anything-i-want}' });
  assert.strictEqual(res.success, false, 'A flag registered as defaultFlag must not self-certify a dynamic challenge');
}
console.log('✔ Test 4 passed: Self-certifying submission pattern is rejected.');

// Test 5: Static (non-dynamic) challenges still accept their configured flag
{
  const engine = new TournamentEngine({ secretKey: SECRET });
  const team = engine.registerTeam({ name: 'TeamS' });
  engine.addChallenge({ id: 'static-1', name: 'static-1', isDynamicFlag: false, defaultFlag: 'VIGILANTE{static-1_answer}' });
  engine.start();
  const res = engine.submitFlag({ teamId: team.id, challengeId: 'static-1', flag: 'VIGILANTE{static-1_answer}' });
  assert.strictEqual(res.success, true);
}
console.log('✔ Test 5 passed: Static challenges still verify against their configured flag.');

// Test 6: listActiveSandboxes redacts flag + manifest by default; opt-in reveals them
const sbx = await spawnEphemeralSandbox({ teamId: 'team_redact', challengeId: 'web-flag-leak', mock: true });
assert.ok(sbx.flag && sbx.manifest.includes(sbx.flag), 'Spawn return keeps the full record for the direct caller');
const publicList = await listActiveSandboxes({ teamId: 'team_redact' });
const pub = publicList.find(s => s.id === sbx.id);
assert.ok(pub, 'Spawned sandbox is listed');
assert.ok(!('flag' in pub) && !('manifest' in pub), 'Default list view must not contain flag or manifest');
const fullList = await listActiveSandboxes({ teamId: 'team_redact', includeSecrets: true });
const full = fullList.find(s => s.id === sbx.id);
assert.strictEqual(full.flag, sbx.flag);
const redacted = redactSandboxRecord(sbx);
assert.ok(!('flag' in redacted) && !('manifest' in redacted) && redacted.id === sbx.id && redacted.host === sbx.host);
console.log('✔ Test 6 passed: List/spawn surfaces redact flag and manifest; includeSecrets opt-in keeps them.');

// Test 7: A failed kubectl apply fails the spawn and registers nothing
{
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-kubectl-stub-'));
  fs.writeFileSync(path.join(stubDir, 'kubectl'), '#!/bin/sh\necho "cluster unreachable" >&2\nexit 1\n', { mode: 0o755 });
  const oldPath = process.env.PATH;
  process.env.PATH = stubDir + ':' + oldPath;
  try {
    await assert.rejects(
      () => spawnEphemeralSandbox({ teamId: 'team_applyfail', challengeId: 'pwn-nsjail-echo', mock: false }),
      /Kubernetes apply failed/
    );
  } finally {
    process.env.PATH = oldPath;
  }
  const after = await listActiveSandboxes({ teamId: 'team_applyfail', includeSecrets: true });
  assert.strictEqual(after.length, 0, 'Failed apply must not register a sandbox');
}
console.log('✔ Test 7 passed: Failed kubectl apply rejects the spawn and registers nothing.');

// Test 8: The sandbox registry persists across processes
{
  const childXdg = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-ctf-xproc-'));
  const libUrl = pathToFileURL(path.join(repoRoot, 'src/engine/kctf.js')).href;
  const childEnv = { ...process.env, XDG_CONFIG_HOME: childXdg, VIGILANTE_CTF_SECRET: SECRET };
  const runChild = (code) => execFileSync(process.execPath, ['--input-type=module', '-e', code], { env: childEnv, encoding: 'utf8' });

  const spawnOut = runChild(`const m = await import('${libUrl}');
    const s = await m.spawnEphemeralSandbox({ teamId: 'team_child', challengeId: 'crypto-oracle-rsa', mock: true });
    console.log(s.id);`);
  const childId = spawnOut.trim().split('\n').pop();

  const listOut = runChild(`const m = await import('${libUrl}');
    const list = await m.listActiveSandboxes({ includeSecrets: true });
    console.log(JSON.stringify(list.map(s => s.id)));`);
  assert.ok(JSON.parse(listOut.trim().split('\n').pop()).includes(childId),
    'A sandbox spawned in one process must be visible to the next');

  runChild(`const m = await import('${libUrl}');
    await m.terminateSandbox({ sandboxId: '${childId}', mock: true });`);
  const listOut2 = runChild(`const m = await import('${libUrl}');
    const list = await m.listActiveSandboxes({ includeSecrets: true });
    console.log(JSON.stringify(list.map(s => s.id)));`);
  assert.ok(!JSON.parse(listOut2.trim().split('\n').pop()).includes(childId),
    'A sandbox terminated in one process must stay terminated in the next');
}
console.log('✔ Test 8 passed: Sandbox registry persists across processes (spawn → list → terminate → list).');

// Test 9: The registry file lives in the Vigilante config dir
assert.ok(fs.existsSync(path.join(tmpXdg, 'vigilante', 'ctf-sandboxes.json')),
  'ctf-sandboxes.json should be written under the config dir');
console.log('✔ Test 9 passed: Registry persisted to ctf-sandboxes.json in the config directory.');

await terminateSandbox({ sandboxId: sbx.id, mock: true });
console.log('\n🎉 All CTF integrity tests passed successfully!\n');
