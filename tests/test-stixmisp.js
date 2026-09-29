import assert from 'node:assert';
import {
  generateStixId,
  parseStixBundle,
  convertMispToStix,
  convertStixToMisp,
  mergeThreatFeeds,
  filterIndicators
} from '../src/engine/stixmisp.js';

async function runTests() {
  console.log('🧪 Testing Standardized STIX 2.1 / TAXII & MISP Threat Feed Pipeline...');

  // Test 1: generateStixId
  const idRandom = generateStixId('indicator');
  assert.ok(idRandom.startsWith('indicator--'));
  const idSeeded1 = generateStixId('attack-pattern', 't1055-seed');
  const idSeeded2 = generateStixId('attack-pattern', 't1055-seed');
  assert.strictEqual(idSeeded1, idSeeded2, 'Seeded STIX IDs must be deterministic');
  console.log('✔ Test 1 passed: generateStixId generated valid deterministic and random STIX 2.1 UUIDs.');

  // Test 2: parseStixBundle
  const mockStixBundle = {
    type: 'bundle',
    id: 'bundle--85e4c3f5-7449-4972-87a4-0ef63e3d93b9',
    spec_version: '2.1',
    objects: [
      {
        type: 'indicator',
        spec_version: '2.1',
        id: 'indicator--d81f86b9-975b-4232-bb80-0bffb1c64e41',
        name: 'Cobalt Strike C2 IP',
        pattern: "[ipv4-addr:value = '198.51.100.55']",
        pattern_type: 'stix',
        valid_from: '2026-09-28T00:00:00Z',
        confidence: 90
      },
      {
        type: 'indicator',
        spec_version: '2.1',
        id: 'indicator--a21b33c1-1122-3344-5566-778899aabbcc',
        name: 'Malicious Payload Hash',
        pattern: "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
        pattern_type: 'stix',
        valid_from: '2026-09-28T00:00:00Z',
        confidence: 95
      },
      {
        type: 'malware',
        spec_version: '2.1',
        id: 'malware--44332211-5566-7788-9900-aabbccddeeff',
        name: 'CobaltStrike'
      },
      {
        type: 'relationship',
        spec_version: '2.1',
        id: 'relationship--11223344-5566-7788-9900-aabbccddeeff',
        relationship_type: 'indicates',
        source_ref: 'indicator--d81f86b9-975b-4232-bb80-0bffb1c64e41',
        target_ref: 'malware--44332211-5566-7788-9900-aabbccddeeff'
      }
    ]
  };

  const parsed = parseStixBundle(mockStixBundle);
  assert.strictEqual(parsed.bundleId, 'bundle--85e4c3f5-7449-4972-87a4-0ef63e3d93b9');
  assert.strictEqual(parsed.totalObjects, 4);
  assert.strictEqual(parsed.indicators.length, 2);
  assert.strictEqual(parsed.relationships.length, 1);
  assert.strictEqual(parsed.indicators[0].iocType, 'ipv4');
  assert.strictEqual(parsed.indicators[0].iocValue, '198.51.100.55');
  assert.strictEqual(parsed.indicators[1].iocType, 'sha256');
  console.log(`✔ Test 2 passed: parseStixBundle extracted ${parsed.indicators.length} typed indicators and ${parsed.relationships.length} relationships.`);

  // Test 3: convertMispToStix
  const mockMisp = {
    Event: {
      uuid: '64f7c1d3-3561-4822-b5e8-112233445566',
      info: 'APT-29 Campaign Telemetry',
      timestamp: '1700000000',
      Attribute: [
        { type: 'ip-dst', value: '203.0.113.88', to_ids: true, comment: 'C2 Gateway' },
        { type: 'domain', value: 'apt-beacon.xyz', to_ids: true, comment: 'DGA Domain' },
        { type: 'sha256', value: '112233445566778899aabbccddeeff00112233445566778899aabbccddeeff00', to_ids: false }
      ]
    }
  };

  const convertedStix = convertMispToStix(mockMisp);
  assert.strictEqual(convertedStix.type, 'bundle');
  assert.ok(convertedStix.objects.length >= 4, 'Must contain 1 report + 3 indicator objects');
  const ipObj = convertedStix.objects.find(o => o.pattern && o.pattern.includes('203.0.113.88'));
  assert.ok(ipObj, 'Must find converted IPv4 indicator');
  assert.strictEqual(ipObj.confidence, 85, 'to_ids=true attributes should get 85 confidence');
  console.log('✔ Test 3 passed: convertMispToStix converted MISP 2.4 Event attributes into STIX 2.1 SDOs.');

  // Test 4: convertStixToMisp (roundtrip)
  const roundtripMisp = convertStixToMisp(convertedStix);
  assert.ok(roundtripMisp.Event, 'Must contain Event structure');
  assert.strictEqual(roundtripMisp.Event.Attribute.length, 3);
  assert.ok(roundtripMisp.Event.Attribute.some(a => a.value === 'apt-beacon.xyz' && a.type === 'domain'));
  console.log('✔ Test 4 passed: convertStixToMisp converted STIX bundle back to MISP event format.');

  // Test 5: mergeThreatFeeds (deduplication)
  const feedA = parseStixBundle(mockStixBundle);
  const feedB = parseStixBundle({
    type: 'bundle',
    objects: [
      {
        type: 'indicator',
        spec_version: '2.1',
        id: 'indicator--99999999-1111-2222-3333-444444444444',
        name: 'Duplicate C2 IP from Secondary Feed',
        pattern: "[ipv4-addr:value = '198.51.100.55']",
        confidence: 95
      }
    ]
  });

  const merged = mergeThreatFeeds([feedA, feedB]);
  assert.strictEqual(merged.length, 2, 'Should deduplicate the shared 198.51.100.55 IP');
  const sharedIp = merged.find(m => m.iocValue === '198.51.100.55');
  assert.strictEqual(sharedIp.sourceFeedCount, 2, 'Must record 2 feed sources');
  assert.strictEqual(sharedIp.maxConfidence, 95, 'Must adopt highest confidence score');
  console.log(`✔ Test 5 passed: mergeThreatFeeds merged feeds with multi-source correlation (Count: ${sharedIp.sourceFeedCount}).`);

  // Test 6: filterIndicators
  const filtered = filterIndicators(parsed.indicators, { type: 'ipv4', minConfidence: 80 });
  assert.strictEqual(filtered.length, 1);
  assert.strictEqual(filtered[0].iocValue, '198.51.100.55');
  console.log('✔ Test 6 passed: filterIndicators queried indicators by IOC type and confidence.');

  console.log('🎉 All Standardized STIX 2.1 / TAXII & MISP tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ STIX/MISP tests failed:', err);
  process.exit(1);
});
