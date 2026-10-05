import assert from 'node:assert';
import {
  spawnEphemeralSandbox,
  listActiveSandboxes,
  extendSandboxTtl,
  reapExpiredSandboxes,
  terminateSandbox,
  activeSandboxesRegistry,
  MAX_SANDBOXES_PER_TEAM
} from '../src/engine/kctf.js';

console.log('🧪 Testing Ephemeral Sandbox Spawner, Dynamic Ingress & TTL Reaper...');

// Reset registry for clean test run
activeSandboxesRegistry.clear();

// Test 1: Spawning a valid sandbox
const sbx1 = await spawnEphemeralSandbox({
  teamId: 'team_alpha',
  challengeId: 'web-flag-leak',
  ttlMinutes: 45,
  domain: 'ctf.test',
  mock: true
});

assert.ok(sbx1.id.startsWith('sbx-teamalpha-web-flag-leak-'));
assert.strictEqual(sbx1.teamId, 'team_alpha');
assert.strictEqual(sbx1.challengeId, 'web-flag-leak');
assert.strictEqual(sbx1.port, 8080);
assert.strictEqual(sbx1.host, 'teamalpha-web-flag-leak.ctf.ctf.test');
assert.ok(sbx1.flag.startsWith('VIGILANTE{web-flag-leak_team_alpha_'));
assert.strictEqual(sbx1.status, 'ACTIVE');
assert.ok(sbx1.manifest.includes('kind: Deployment'));
assert.ok(sbx1.manifest.includes('kind: Ingress'));
assert.ok(sbx1.manifest.includes('kind: NetworkPolicy'));
assert.ok(sbx1.manifest.includes('cpu: 250m'));
assert.ok(sbx1.manifest.includes('memory: 128Mi'));
console.log('✔ Test 1 passed: Ephemeral sandbox spawned with isolated NetworkPolicy and dynamic HMAC flag.');

// Test 2: Idempotent return if already active for same challenge
const sbx1Repeat = await spawnEphemeralSandbox({
  teamId: 'team_alpha',
  challengeId: 'web-flag-leak',
  mock: true
});
assert.strictEqual(sbx1Repeat.id, sbx1.id, 'Spawning existing challenge sandbox should return existing instance');
console.log('✔ Test 2 passed: Idempotent handling for duplicate challenge request.');

// Test 3: Concurrency Quota Enforcement (max 3)
const sbx2 = await spawnEphemeralSandbox({
  teamId: 'team_alpha',
  challengeId: 'pwn-nsjail-echo',
  mock: true
});
const sbx3 = await spawnEphemeralSandbox({
  teamId: 'team_alpha',
  challengeId: 'crypto-oracle-rsa',
  mock: true
});

assert.strictEqual(activeSandboxesRegistry.size, 3);

// Attempt 4th sandbox should reject with quota error
let quotaError = null;
try {
  await spawnEphemeralSandbox({
    teamId: 'team_alpha',
    challengeId: 'web-auth-bypass',
    mock: true
  });
} catch (err) {
  quotaError = err;
}
assert.ok(quotaError, 'Should throw error when exceeding team sandbox quota');
assert.ok(quotaError.message.includes('Team concurrency limit exceeded'));
console.log('✔ Test 3 passed: Hard concurrency quota enforced (max 3 active sandboxes per team).');

// Test 4: List active sandboxes with remaining TTL calculation
const activeList = await listActiveSandboxes({ teamId: 'team_alpha' });
assert.strictEqual(activeList.length, 3);
assert.strictEqual(activeList[0].status, 'ACTIVE');
assert.ok(activeList[0].remainingMinutes >= 44 && activeList[0].remainingMinutes <= 45);
console.log('✔ Test 4 passed: listActiveSandboxes returns active instances with calculated TTL remaining.');

// Test 5: Extend sandbox TTL
const extendRes = await extendSandboxTtl({
  sandboxId: sbx1.id,
  additionalMinutes: 15
});
assert.strictEqual(extendRes.success, true);
assert.strictEqual(extendRes.ttlMinutes, 60);
assert.ok(extendRes.remainingMinutes >= 59);
console.log('✔ Test 5 passed: extendSandboxTtl safely extends expiration time.');

// Test 6: Reaper terminates expired sandboxes
// Artificially expire sbx2
const sbx2Record = activeSandboxesRegistry.get(sbx2.id);
sbx2Record.expiresAt = new Date(Date.now() - 5000).toISOString();

const reaped = await reapExpiredSandboxes({ mock: true });
assert.strictEqual(reaped.length, 1);
assert.strictEqual(reaped[0].sandboxId, sbx2.id);
assert.strictEqual(activeSandboxesRegistry.has(sbx2.id), false);
console.log('✔ Test 6 passed: reapExpiredSandboxes detects and prunes expired sandboxes.');

// Test 7: Terminate sandbox manually frees quota
const termRes = await terminateSandbox({ sandboxId: sbx3.id, mock: true });
assert.strictEqual(termRes.success, true);
assert.strictEqual(activeSandboxesRegistry.has(sbx3.id), false);

// Now team should be able to spawn the 4th challenge
const sbx4 = await spawnEphemeralSandbox({
  teamId: 'team_alpha',
  challengeId: 'web-auth-bypass',
  mock: true
});
assert.strictEqual(sbx4.challengeId, 'web-auth-bypass');
console.log('✔ Test 7 passed: terminateSandbox immediately frees up team concurrency quota.');

console.log('\n🎉 All Ephemeral Sandbox Spawner & Ingress tests passed successfully!\n');
