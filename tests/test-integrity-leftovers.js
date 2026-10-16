import assert from 'node:assert';
import { execFileSync } from 'node:child_process';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';

console.log('🧪 Testing integrity leftovers: KotH proof tokens (E11), OOBscan argv construction (D8), LSM codegen (F10)...');

const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-integrity-'));
process.env.XDG_CONFIG_HOME = tmpRoot;

const { TournamentEngine } = await import('../src/engine/tournament.js');
const { OOB_SCAN_PROFILES, runOobScan } = await import('../src/engine/oobscan.js');
const lsm = await import('../src/engine/lsm.js');

// Test 1 (E11): KotH claims require the hill's current proof token
{
  const engine = new TournamentEngine({ id: 'koth-test', title: 'KotH Test' });
  const team1 = engine.registerTeam({ name: 'First' });
  const team2 = engine.registerTeam({ name: 'Second' });
  const hill = () => engine.kothState.hills.find(h => h.id === 'citadel-01');

  // No token at all: no crown, no points
  const noToken = engine.claimHill({ hillId: 'citadel-01', teamId: team1.id });
  assert.strictEqual(noToken.success, false);
  assert.strictEqual(hill().currentKing, null);
  assert.strictEqual(team1.score, 0);

  // Garbage token: still no crown (the sweep's repro stole the bonus this way)
  const garbage = engine.claimHill({ hillId: 'citadel-01', teamId: team1.id, proofToken: 'GARBAGE' });
  assert.strictEqual(garbage.success, false);
  assert.strictEqual(hill().currentKing, null);

  // The token must not leak through a state export
  const token = engine.getHillProofToken('citadel-01');
  assert.ok(token && token.length >= 16);
  assert.ok(!JSON.stringify(engine.exportState()).includes(token), 'exportState must not contain proof tokens');

  // Correct token: claim succeeds, token rotates and the spent one dies
  const claim1 = engine.claimHill({ hillId: 'citadel-01', teamId: team1.id, proofToken: token });
  assert.strictEqual(claim1.success, true);
  assert.strictEqual(claim1.dethroneBonus, 0);
  assert.ok(claim1.newProofToken && claim1.newProofToken !== token, 'Token rotates on claim');
  assert.strictEqual(engine.getHillProofToken('citadel-01'), claim1.newProofToken);

  const spent = engine.claimHill({ hillId: 'citadel-01', teamId: team2.id, proofToken: token });
  assert.strictEqual(spent.success, false, 'A spent token must not dethrone');
  assert.strictEqual(team2.score, 0);

  // Current token dethrones and pays the bonus exactly once
  const claim2 = engine.claimHill({ hillId: 'citadel-01', teamId: team2.id, proofToken: claim1.newProofToken });
  assert.strictEqual(claim2.success, true);
  assert.strictEqual(claim2.dethroneBonus, 50);
  assert.strictEqual(team2.kothScore, 50);
  assert.strictEqual(hill().currentKing, team2.id);
}
console.log('✔ Test 1 passed: KotH crown requires the current proof token; tokens rotate and never leak via exportState (E11).');

// Test 2 (D8): every profile's buildArgs produces the argv the runner uses
{
  const byId = Object.fromEntries(OOB_SCAN_PROFILES.map(p => [p.id, p]));
  assert.deepStrictEqual(byId.standard.buildArgs('10.0.0.1'), ['scan', '-targets', '10.0.0.1']);
  assert.deepStrictEqual(
    byId.standard.buildArgs('10.0.0.1', { disableLogins: true }),
    ['scan', '-targets', '10.0.0.1', '-no-logins']
  );
  for (const p of OOB_SCAN_PROFILES) {
    const argv = p.buildArgs('10.0.0.1', { disableLogins: true, ipmiFull: true });
    assert.ok(!argv.includes('--disable-logins'), `${p.id} must not use the divergent --disable-logins spelling`);
    assert.strictEqual(argv[1], '-targets', `${p.id} passes the target via -targets`);
    assert.strictEqual(argv[2], '10.0.0.1');
  }
  assert.ok(byId.quick.buildArgs('10.0.0.1').includes('-no-logins'));
  assert.ok(byId.passive.buildArgs('10.0.0.1').includes('-no-logins'));
  assert.ok(byId['ipmi-full'].buildArgs('10.0.0.1').includes('-ipmi-full'));
}
console.log('✔ Test 2 passed: Profile argv shapes are unified around buildArgs and one flag spelling (D8).');

// Test 3 (D8): the runner actually executes buildArgs (stub oobscan binary)
{
  const binDir = path.join(tmpRoot, 'bin');
  await fs.mkdir(binDir, { recursive: true });
  const argvFile = path.join(tmpRoot, 'oob-argv.txt');
  const stub = `#!/bin/sh
if [ "$1" = "version" ]; then echo "oobscan version 9.9.9"; exit 0; fi
printf '%s\n' "$@" > ${argvFile}
exit 0
`;
  const stubPath = path.join(binDir, 'oobscan');
  await fs.writeFile(stubPath, stub);
  await fs.chmod(stubPath, 0o755);
  const oldPath = process.env.PATH;
  process.env.PATH = `${binDir}:${oldPath}`;
  try {
    await runOobScan({ target: '10.0.0.9', profile: 'quick' });
  } finally {
    process.env.PATH = oldPath;
  }
  const argv = (await fs.readFile(argvFile, 'utf8')).trim().split('\n');
  assert.strictEqual(argv[0], 'scan');
  assert.strictEqual(argv[1], '-targets', 'Runner must pass -targets (previously dropped)');
  assert.strictEqual(argv[2], '10.0.0.9');
  assert.ok(argv.includes('-no-logins'), 'Quick profile runs with logins disabled');
  assert.ok(!argv.includes('--disable-logins'));
  assert.strictEqual(argv.filter(a => a === '10.0.0.9').length, 1, 'Target appears exactly once (no bare positional duplicate)');
}
console.log('✔ Test 3 passed: runOobScan executes the profile buildArgs argv (D8).');

// Test 4 (F10): EPERM value, empty-input handling, per-hook validation
{
  assert.strictEqual(lsm.EPERM, -1, 'EPERM is errno 1 (denial returns -1); -13 was -EACCES');
  const empty = lsm.generateBpfLsmPolicy('');
  assert.strictEqual(empty.rulesCount, 0, 'Empty policy input must not throw');

  assert.throws(
    () => lsm.generateBpfLsmPolicy({ rules: [{ id: 'bad-port', hook: 'file_open', port: 4444 }] }),
    /cannot evaluate/,
    'A port condition on file_open is rejected instead of generating uncompilable C'
  );
  assert.throws(
    () => lsm.generateBpfLsmPolicy({ rules: [{ id: 'bad-path', hook: 'socket_connect', path: '/etc/passwd' }] }),
    /cannot evaluate/
  );
  assert.throws(
    () => lsm.generateBpfLsmPolicy({ rules: [{ id: 'bad-hook', hook: 'file_permission', comm: 'bash' }] }),
    /unsupported LSM hook/
  );
}
console.log('✔ Test 4 passed: LSM synthesis validates hooks/conditions and handles empty input (F10).');

// Test 5 (F10): generated C escapes rule strings; simulator mirrors C prefix semantics
{
  const policy = lsm.generateBpfLsmPolicy({
    name: 'escape-test',
    rules: [{
      id: 'esc',
      hook: 'bprm_check_security',
      comm: 'ba"; evil();//',
      description: 'breaks out */ int hacked() { return 0; } //',
      action: 'DENY'
    }]
  });
  assert.ok(policy.rules[0].filterExpr.includes('\\"'), 'Quotes in condition values are escaped in the C literal');
  assert.ok(!policy.cSource.includes('*/ int hacked'), 'Comment terminators in descriptions cannot break out');

  const prefixPolicy = lsm.generateBpfLsmPolicy({
    name: 'prefix-test',
    rules: [{ id: 'deny-bash', hook: 'bprm_check_security', comm: 'bash', action: 'DENY' }]
  });
  const blocked = lsm.simulateLsmPolicyEvaluation(prefixPolicy, { hook: 'bprm_check_security', comm: 'bash2' });
  assert.strictEqual(blocked.allowed, false, "Simulator agrees with the C prefix match: 'bash' blocks 'bash2'");
  assert.strictEqual(blocked.returnCode, lsm.EPERM);
  const allowed = lsm.simulateLsmPolicyEvaluation(prefixPolicy, { hook: 'bprm_check_security', comm: 'sh' });
  assert.strictEqual(allowed.allowed, true);
}
console.log('✔ Test 5 passed: C injection via rule fields is escaped; simulator and C agree on prefix matching (F10).');

// Test 6 (F10): the generated C actually compiles (gcc syntax check against
// minimal BPF stub headers — catches undeclared variables per hook)
{
  const policy = lsm.generateBpfLsmPolicy({
    name: 'compile-test',
    rules: [
      { id: 'r1', hook: 'bprm_check_security', comm: 'bash', parentComm: 'sshd', uid: 1000, action: 'DENY' },
      { id: 'r2', hook: 'file_open', path: '/etc/shadow', comm: 'cat', action: 'DENY' },
      { id: 'r3', hook: 'socket_connect', port: 4444, uid: 0, action: 'DENY' }
    ]
  });
  const stubDir = path.join(tmpRoot, 'stubs');
  await fs.mkdir(path.join(stubDir, 'bpf'), { recursive: true });
  await fs.writeFile(path.join(stubDir, 'vmlinux.h'), `#pragma once
typedef unsigned int __u32;
typedef unsigned short __u16;
typedef unsigned long long __u64;
struct path { void *mnt; void *dentry; };
struct file { struct path f_path; };
struct linux_binprm { const char *filename; };
struct socket { int dummy; };
struct sockaddr { unsigned short sa_family; };
struct sockaddr_in { unsigned short sin_family; __u16 sin_port; };
struct task_struct { struct task_struct *parent; char comm[16]; };
#define SEC(x)
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define __always_inline inline
#define BPF_CORE_READ(s, f) (((s)->f))
#define BPF_CORE_READ_STR(dst, sz, src, f) ((void)0)
int bpf_get_current_comm(void *buf, __u32 size);
__u64 bpf_get_current_uid_gid(void);
unsigned long bpf_get_current_task(void);
long bpf_probe_read_kernel_str(void *dst, __u32 size, const void *ptr);
long bpf_d_path(struct path *path, char *buf, __u32 sz);
long bpf_strncmp(const char *s1, __u32 s1_sz, const char *s2);
int bpf_printk(const char *fmt, ...);
`);
  for (const h of ['bpf_helpers.h', 'bpf_tracing.h', 'bpf_core_read.h']) {
    await fs.writeFile(path.join(stubDir, 'bpf', h), '#pragma once\n');
  }
  await fs.writeFile(path.join(stubDir, 'bpf', 'bpf_endian.h'), '#pragma once\n#define bpf_ntohs(x) ((__u16)(x))\n');
  const cPath = path.join(tmpRoot, 'policy.c');
  await fs.writeFile(cPath, policy.cSource);
  execFileSync('gcc', ['-fsyntax-only', '-I', stubDir, '-Wno-unused-variable', cPath], { stdio: 'pipe' });
}
console.log('✔ Test 6 passed: Generated BPF-LSM C compiles for every hook (F10).');

console.log('\n🎉 All integrity-leftover tests passed successfully!\n');
