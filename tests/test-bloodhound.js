import assert from 'node:assert';
import {
  parseBloodhoundData,
  correlateFlamingoCredentials,
  ingestBloodhoundData,
  listBloodhoundIngests,
  checkBloodhoundAvailable
} from '../src/engine/bloodhound.js';

async function runTests() {
  console.log('🧪 Testing BloodHound CE & Active Directory Graph Engine...');

  // Test 1: Check availability gracefully handles offline daemon
  const status = await checkBloodhoundAvailable({ url: 'http://127.0.0.1:59999/health' });
  assert.strictEqual(status.reachable, false, 'Unreachable port returns false without throwing');
  console.log('✔ Test 1 passed: checkBloodhoundAvailable handled offline endpoint gracefully.');

  // Test 2: Parse BloodHound / SharpHound data
  const sampleUsersJson = {
    meta: { type: 'users' },
    data: [
      {
        Properties: {
          name: 'DA_ALICE@CORP.LOCAL',
          domain: 'CORP.LOCAL',
          enabled: true,
          admincount: true,
          pwdneverexpires: true,
          dontreqpreauth: true,
          unconstraineddelegation: true
        }
      },
      {
        Properties: {
          name: 'BOB_DEV@CORP.LOCAL',
          domain: 'CORP.LOCAL',
          enabled: true,
          admincount: false,
          pwdneverexpires: false,
          dontreqpreauth: false,
          unconstraineddelegation: false
        }
      }
    ]
  };

  const parsed = parseBloodhoundData(sampleUsersJson);
  assert.strictEqual(parsed.users.length, 2);
  assert.strictEqual(parsed.statistics.privilegedUsers, 1);
  assert.strictEqual(parsed.statistics.asRepRoastable, 1);
  assert(parsed.attackPathAlerts.length >= 2, 'Should flag AS-REP Roasting and Unconstrained Delegation');
  console.log('✔ Test 2 passed: parseBloodhoundData extracted users and identified identity attack paths.');

  // Test 3: Correlate with Flamingo captured credentials
  const mockFlamingoCreds = [
    { username: 'DA_ALICE', domain: 'CORP.LOCAL', protocol: 'smb', clientIp: '10.0.0.88' },
    { username: 'UNKNOWN_USER', domain: 'CORP.LOCAL', protocol: 'kerberos', clientIp: '10.0.0.99' }
  ];

  const correlation = correlateFlamingoCredentials({
    bloodhoundData: parsed,
    flamingoCredentials: mockFlamingoCreds
  });

  assert.strictEqual(correlation.totalCompromised, 1);
  assert.strictEqual(correlation.tier0CompromisedCount, 1, 'DA_ALICE has admincount=true, should be Tier-0 compromise');
  assert.strictEqual(correlation.riskScore, 100);
  console.log('✔ Test 3 passed: correlateFlamingoCredentials identified compromised Tier-0 / Domain Admin credential.');

  // Test 4: Ingest BloodHound dataset and save evidence
  const ingested = await ingestBloodhoundData(sampleUsersJson, {
    flamingoCredentials: mockFlamingoCreds
  });
  assert(ingested.id.startsWith('bh-'));
  assert.strictEqual(ingested.stats.users, 2);
  assert.strictEqual(ingested.stats.tier0Compromises, 1);
  console.log(`✔ Test 4 passed: ingestBloodhoundData recorded and signed dataset: ${ingested.id}.`);

  // Test 5: List ingests
  const ingests = await listBloodhoundIngests();
  assert(Array.isArray(ingests));
  assert(ingests.some(i => i.id === ingested.id));
  console.log('✔ Test 5 passed: listBloodhoundIngests successfully listed saved ingests.');

  console.log('🎉 ALL 5 BLOODHOUND ENGINE TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ BloodHound Engine test failed:', err);
  process.exit(1);
});
