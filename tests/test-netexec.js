import assert from 'node:assert';
import {
  NETEXEC_PROFILES,
  checkNetexecInstalled,
  parseNetexecOutput,
  probeAuthProtocolsNative,
  runNetexecAudit,
  listSavedNetexecAudits
} from '../src/engine/netexec.js';

async function runTests() {
  console.log('🧪 Testing NetExec Protocol & Credential Engine...');

  // Test 1: Profiles
  assert(Array.isArray(NETEXEC_PROFILES) && NETEXEC_PROFILES.length >= 3);
  const smbProf = NETEXEC_PROFILES.find(p => p.id === 'smb-signing');
  assert(smbProf);
  const args = smbProf.buildArgs('192.168.1.100');
  assert(args.includes('smb') && args.includes('192.168.1.100'));
  console.log('✔ Test 1 passed: NetExec profiles and argument builder verified.');

  // Test 2: Tool checks
  const tool = await checkNetexecInstalled();
  assert('installed' in tool && 'runner' in tool);
  console.log(`✔ Test 2 passed: checkNetexecInstalled returned status (runner: ${tool.runner}).`);

  // Test 3: Parse output lines
  const sampleOutput = `
SMB 10.0.0.15 445 DC01 [*] Windows 10 / Server 2019 (name:DC01) (domain:CORP) (signing:False) (SMBv1:False)
SMB 10.0.0.16 445 FILE01 [*] Windows Server 2022 (name:FILE01) (domain:CORP) (signing:True) (SMBv1:False)
`;
  const parsed = parseNetexecOutput(sampleOutput);
  assert.strictEqual(parsed.length, 2);
  assert.strictEqual(parsed[0].ip, '10.0.0.15');
  assert.strictEqual(parsed[0].smbSigning, 'False');
  assert.strictEqual(parsed[0].isVulnerableToRelay, true);
  assert.strictEqual(parsed[1].ip, '10.0.0.16');
  assert.strictEqual(parsed[1].smbSigning, 'True');
  assert.strictEqual(parsed[1].isVulnerableToRelay, false);
  console.log('✔ Test 3 passed: parseNetexecOutput accurately extracted protocol, signing status, and relay exposure.');

  // Test 4: Native protocol reachability probe
  const reachable = await probeAuthProtocolsNative('127.0.0.1');
  assert(Array.isArray(reachable) && reachable.length >= 3);
  console.log(`✔ Test 4 passed: probeAuthProtocolsNative probed ${reachable.length} authentication ports.`);

  // Test 5: Run audit and verify persistence
  const audit = await runNetexecAudit('127.0.0.1', 'smb-signing');
  assert(audit.id && audit.filePath);
  const saved = await listSavedNetexecAudits();
  assert(saved.length >= 1);
  console.log('✔ Test 5 passed: runNetexecAudit completed and recorded audit in directory.');

  console.log('🎉 ALL 5 NETEXEC TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ NetExec test failed:', err);
  process.exit(1);
});
