import assert from 'node:assert';
import {
  parseKallsyms,
  detectSyscallHooking,
  detectHiddenModules,
  analyzeKernelTaint,
  scanRootkitArtifacts,
  generateRootkitReport,
  TAINT_FLAGS,
  ROOTKIT_SIGNATURES
} from '../src/engine/rootkit.js';

async function runTests() {
  console.log('🧪 Testing Ring-0 Kernel Hook & Syscall Rootkit Hunter Engine...');

  // Test 1: parseKallsyms
  const mockKallsyms = `
ffffffff81000000 T _text
ffffffff81200000 T sys_call_table
ffffffff81250100 T sys_read
ffffffff81250200 T sys_write
ffffffff81250300 T sys_openat
ffffffffa0123000 t sys_execve [diamorphine]
ffffffff81800000 T sys_getdents64
ffffffff81a00000 T _etext
0000000000000000 t restricted_symbol
`;

  const parsed = parseKallsyms(mockKallsyms);
  assert.strictEqual(parsed.length, 9, 'Must parse exactly 9 symbols');
  const textSym = parsed.find(s => s.name === '_text');
  assert.ok(textSym, '_text symbol must exist');
  assert.strictEqual(textSym.numAddress > 0n, true, 'numAddress must be converted to BigInt');
  const restricted = parsed.find(s => s.name === 'restricted_symbol');
  assert.strictEqual(restricted.isHashed, true, 'Zero-address symbols must be marked isHashed');
  console.log(`✔ Test 1 passed: parseKallsyms parsed ${parsed.length} symbols with BigInt addresses.`);

  // Test 2: detectSyscallHooking
  const baseline = {
    sys_read: { address: 'ffffffff81250100' },
    sys_write: { address: 'ffffffff81250999' } // simulate mismatch
  };

  const anomalies = detectSyscallHooking(parsed, baseline);
  assert.ok(anomalies.length >= 2, 'Must detect at least 2 syscall anomalies');
  
  // Hijacked by diamorphine module
  const hijacked = anomalies.find(a => a.hookType === 'LKM_MODULE_HIJACK' && a.syscall === 'sys_execve');
  assert.ok(hijacked, 'Must detect sys_execve hijacked by diamorphine LKM');
  assert.strictEqual(hijacked.severity, 'CRITICAL');

  // Baseline address mismatch for sys_write
  const mismatch = anomalies.find(a => a.hookType === 'BASELINE_ADDRESS_MISMATCH' && a.syscall === 'sys_write');
  assert.ok(mismatch, 'Must detect sys_write baseline address mismatch');
  console.log(`✔ Test 2 passed: detectSyscallHooking flagged ${anomalies.length} hook anomalies including LKM hijack.`);

  // Test 3: detectHiddenModules (Diamorphine / Reptile unlinking)
  const mockProcModules = `
ext4 614400 1 - Live 0xffffffffa0000000
tcp_cubic 16384 1 - Live 0xffffffffa0010000
overlay 143360 2 - Live 0xffffffffa0020000
`;
  const mockSysModules = [
    'ext4',
    'tcp_cubic',
    'overlay',
    'reptile_core',      // HIDDEN LKM
    'diamorphine_secret' // HIDDEN LKM
  ];

  const hiddenRes = detectHiddenModules(mockProcModules, mockSysModules);
  assert.strictEqual(hiddenRes.totalProcModules, 3);
  assert.strictEqual(hiddenRes.totalSysfsModules, 5);
  assert.strictEqual(hiddenRes.hiddenModules.length, 2, 'Must find 2 unlinked hidden modules');
  assert.ok(hiddenRes.hiddenModules.some(m => m.name === 'reptile_core'));
  assert.ok(hiddenRes.hiddenModules.some(m => m.name === 'diamorphine_secret'));
  console.log(`✔ Test 3 passed: detectHiddenModules caught ${hiddenRes.hiddenModules.length} hidden kernel modules.`);

  // Test 4: analyzeKernelTaint
  // Bit 12 (4096 = OUT_OF_TREE_MODULE) + Bit 1 (2 = FORCED_MODULE) = 4098
  const taintAnalysis = analyzeKernelTaint(4098);
  assert.strictEqual(taintAnalysis.isTainted, true);
  assert.strictEqual(taintAnalysis.activeFlagsCount, 2);
  assert.ok(taintAnalysis.flags.some(f => f.flag === 'FORCED_MODULE'));
  assert.ok(taintAnalysis.flags.some(f => f.flag === 'OUT_OF_TREE_MODULE'));
  assert.strictEqual(taintAnalysis.riskAssessment, 'HIGH_RISK_TAINTED');

  const pristineAnalysis = analyzeKernelTaint(0);
  assert.strictEqual(pristineAnalysis.isTainted, false);
  assert.strictEqual(pristineAnalysis.riskAssessment, 'PRISTINE_UNTAINTED');
  console.log('✔ Test 4 passed: analyzeKernelTaint accurately decoded Linux kernel taint bitmasks.');

  // Test 5: scanRootkitArtifacts
  const mockEnv = { LD_PRELOAD: '/tmp/malicious.so' };
  const mockFiles = [
    '/var/log/syslog',
    '/root/reptile_client',
    '/lib/modules/diamorphine.ko',
    '/home/user/app.js'
  ];

  const artifactFindings = scanRootkitArtifacts({ env: mockEnv, fileList: mockFiles });
  assert.ok(artifactFindings.length >= 3, 'Must flag LD_PRELOAD and 2 rootkit prefix files');
  assert.ok(artifactFindings.some(f => f.type === 'LD_PRELOAD_ENV_INJECTION'));
  assert.ok(artifactFindings.some(f => f.target.includes('reptile_client')));
  assert.ok(artifactFindings.some(f => f.target.includes('diamorphine.ko')));
  console.log(`✔ Test 5 passed: scanRootkitArtifacts identified ${artifactFindings.length} rootkit artifacts.`);

  // Test 6: generateRootkitReport
  const report = generateRootkitReport({
    syscallAnomalies: anomalies,
    hiddenModules: hiddenRes.hiddenModules,
    taintAssessment: taintAnalysis,
    artifacts: artifactFindings
  });
  assert.strictEqual(report.overallStatus, 'COMPROMISED_CRITICAL');
  assert.ok(report.summary.critical >= 2);
  assert.ok(report.summary.isKernelTainted);
  console.log(`✔ Test 6 passed: generateRootkitReport produced summary with overallStatus: ${report.overallStatus}.`);

  console.log('🎉 All Kernel Hook & Syscall Rootkit Hunter tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ Rootkit Hunter tests failed:', err);
  process.exit(1);
});
