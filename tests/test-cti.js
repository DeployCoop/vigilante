import assert from 'node:assert';
import {
  syncFeodoTrackerC2,
  syncUrlhausThreats,
  matchCtiIndicators,
  updateSuricataRules
} from '../src/engine/cti.js';

async function runTests() {
  console.log('🧪 Testing Cyber Threat Intelligence (CTI) & Feed Sync...');

  // Test 1: Feodo Tracker C2 Sync
  const feodo = await syncFeodoTrackerC2();
  assert(feodo && typeof feodo.count === 'number');
  assert(Array.isArray(feodo.indicators) && feodo.indicators.length > 0);
  assert(feodo.source === 'abuse.ch Feodo Tracker');
  console.log(`✔ Test 1 passed: syncFeodoTrackerC2 synced ${feodo.count} C2 indicators.`);

  // Test 2: URLhaus Malicious URLs Sync
  const urlhaus = await syncUrlhausThreats();
  assert(urlhaus && typeof urlhaus.count === 'number');
  assert(Array.isArray(urlhaus.indicators) && urlhaus.indicators.length > 0);
  assert(urlhaus.source === 'abuse.ch URLhaus');
  console.log(`✔ Test 2 passed: syncUrlhausThreats synced ${urlhaus.count} malicious threat indicators.`);

  // Test 3: Match CTI Indicators against incoming traffic
  // Pick one known indicator from feodo and one benign IP
  const knownC2 = feodo.indicators[0].ip;
  const matches = await matchCtiIndicators([knownC2, '8.8.8.8', 'update-system-secure.biz']);

  assert(Array.isArray(matches), 'Matches must be an array');
  const c2Hit = matches.find(m => m.indicator === knownC2);
  assert(c2Hit, `Must find hit for known C2 ${knownC2}`);
  assert(c2Hit.severity === 'CRITICAL');
  assert(c2Hit.type === 'C2_IP');

  const benignHit = matches.find(m => m.indicator === '8.8.8.8');
  assert(!benignHit, 'Benign IP 8.8.8.8 must not trigger a hit');
  console.log(`✔ Test 3 passed: matchCtiIndicators accurately flagged ${matches.length} threats.`);

  // Test 4: Update Suricata Rule Set
  const rules = await updateSuricataRules();
  assert(rules && typeof rules.ruleCount === 'number');
  assert(rules.ruleCount > 0, 'Must compile Suricata rules');
  assert(rules.filePath.endsWith('.rules'), 'Must save .rules file');
  console.log(`✔ Test 4 passed: updateSuricataRules generated ${rules.ruleCount} active IDS rules at ${rules.filePath}.`);

  console.log('🎉 ALL 4 CTI & FEED SYNC TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ CTI test failed:', err);
  process.exit(1);
});
