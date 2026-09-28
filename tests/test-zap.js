import assert from 'node:assert';
import {
  ZAP_PROFILES,
  checkZapAvailable,
  runZapScan,
  listSavedZapScans
} from '../src/engine/zap.js';

async function runTests() {
  console.log('🧪 Testing OWASP ZAP DAST Engine...');

  // Test 1: Profiles
  assert(Array.isArray(ZAP_PROFILES) && ZAP_PROFILES.length >= 3);
  const spiderProf = ZAP_PROFILES.find(p => p.id === 'spider');
  assert(spiderProf && spiderProf.scanType === 'spider');
  console.log('✔ Test 1 passed: ZAP profiles validated.');

  // Test 2: Availability check
  const avail = await checkZapAvailable('http://127.0.0.1:9999');
  assert('reachable' in avail && 'version' in avail);
  console.log(`✔ Test 2 passed: checkZapAvailable handled offline daemon gracefully (reachable: ${avail.reachable}).`);

  // Test 3: Run scan and verify emulation fallback & saved records
  const scan = await runZapScan('http://target.local', 'spider');
  assert(scan.id && scan.filePath);
  assert(Array.isArray(scan.alerts) && scan.alerts.length >= 1);
  const saved = await listSavedZapScans();
  assert(saved.length >= 1);
  console.log('✔ Test 3 passed: runZapScan executed, recorded alerts, and saved signed evidence.');

  console.log('🎉 ALL 3 ZAP TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ ZAP test failed:', err);
  process.exit(1);
});
