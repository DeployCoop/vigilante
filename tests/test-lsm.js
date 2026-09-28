import assert from 'node:assert';
import {
  generateBpfLsmPolicy,
  simulateLsmPolicyEvaluation,
  compileLsmRuleToFilter,
  EPERM
} from '../src/engine/lsm.js';

console.log('🧪 Testing Kernel-Level eBPF LSM Policy Synthesizer Engine...');

// Test 1: compileLsmRuleToFilter
const filter1 = compileLsmRuleToFilter({ comm: 'bash', parentComm: 'nginx' });
assert.ok(filter1.includes('current_comm'), 'Must check current_comm');
assert.ok(filter1.includes('parent_comm'), 'Must check parent_comm');
console.log('✔ Test 1 passed: compileLsmRuleToFilter generates valid C BPF helper expressions.');

// Test 2: generateBpfLsmPolicy from YAML definition
const policyYaml = `
name: prod-container-containment
version: "1.2.0"
rules:
  - id: deny-web-shell
    name: Block Reverse Shells from Web Workers
    hook: bprm_check_security
    comm: ["bash", "sh", "nc"]
    parentComm: ["nginx", "node"]
    action: DENY
    mitre: T1059.004
    description: Prevents web servers from executing interactive shells
  - id: deny-preload-tampering
    name: Protect ld.so.preload
    hook: file_open
    path: "/etc/ld.so.preload"
    action: DENY
    mitre: T1574.006
    description: Blocks rootkit dynamic linker hijack
  - id: deny-c2-port
    name: Block Metasploit Default Port
    hook: socket_connect
    port: 4444
    action: DENY
    mitre: T1071
    description: In-kernel egress drop for port 4444
`;

const policy = generateBpfLsmPolicy(policyYaml);
assert.strictEqual(policy.name, 'prod-container-containment');
assert.strictEqual(policy.rulesCount, 3);
assert.strictEqual(policy.hooks.length, 3);
assert.ok(policy.cSource.includes('SEC("lsm/bprm_check_security")'));
assert.ok(policy.cSource.includes('SEC("lsm/file_open")'));
assert.ok(policy.cSource.includes('SEC("lsm/socket_connect")'));
assert.ok(policy.cSource.includes('#define EPERM 13'));
console.log('✔ Test 2 passed: generateBpfLsmPolicy synthesized C source and hook definitions.');

// Test 3: simulateLsmPolicyEvaluation - Block shell spawned by node
const blockedShellEvent = {
  hook: 'bprm_check_security',
  comm: 'bash',
  parentComm: 'node'
};
const evalBlocked = simulateLsmPolicyEvaluation(policy, blockedShellEvent);
assert.strictEqual(evalBlocked.allowed, false);
assert.strictEqual(evalBlocked.action, 'BLOCK');
assert.strictEqual(evalBlocked.returnCode, EPERM);
assert.strictEqual(evalBlocked.matchedRule, 'deny-web-shell');
assert.strictEqual(evalBlocked.mitreTechnique, 'T1059.004');
console.log('✔ Test 3 passed: simulateLsmPolicyEvaluation rejected unauthorized container reverse shell with -EPERM.');

// Test 4: simulateLsmPolicyEvaluation - Block file tampering and allow normal file access
const blockedFileEvent = {
  hook: 'file_open',
  path: '/etc/ld.so.preload'
};
const evalFileBlocked = simulateLsmPolicyEvaluation(policy, blockedFileEvent);
assert.strictEqual(evalFileBlocked.allowed, false);
assert.strictEqual(evalFileBlocked.returnCode, EPERM);
assert.strictEqual(evalFileBlocked.matchedRule, 'deny-preload-tampering');

const allowedFileEvent = {
  hook: 'file_open',
  path: '/var/log/app.log'
};
const evalFileAllowed = simulateLsmPolicyEvaluation(policy, allowedFileEvent);
assert.strictEqual(evalFileAllowed.allowed, true);
assert.strictEqual(evalFileAllowed.returnCode, 0);
console.log('✔ Test 4 passed: simulateLsmPolicyEvaluation protected ld.so.preload while permitting standard file access.');

console.log('🎉 All Kernel-Level eBPF LSM Policy Synthesizer tests passed successfully!\n');
