import assert from 'node:assert';
import {
  compileYaraRule,
  scanBufferWithRules,
  extractCobaltStrikeConfig,
  scanProcessMemory,
  generateYaraMemoryReport,
  CS_SETTINGS_MAP
} from '../src/engine/yarascan.js';

async function runTests() {
  console.log('🧪 Testing In-Memory Process YARA & Cobalt Strike Configuration Extractor...');

  // Test 1: Compile YARA rules
  const ruleDef1 = {
    name: 'detect_meterpreter_shell',
    meta: { author: 'Vigilante', mitre: 'T1055' },
    strings: [
      { id: '$mz', type: 'hex', value: '4D 5A ?? 00' },
      { id: '$tag', type: 'text', value: 'meterpreter', nocase: true },
      { id: '$c2', type: 'regex', value: 'connect_[a-z]{3}' }
    ],
    condition: '$mz and ($tag or $c2)'
  };

  const compiled = compileYaraRule(ruleDef1);
  assert.strictEqual(compiled.name, 'detect_meterpreter_shell');
  assert.strictEqual(compiled.strings.length, 3);
  console.log(`✔ Test 1 passed: compileYaraRule successfully parsed rule '${compiled.name}'.`);

  // Test 2: Buffer scanning with rule matching
  // Construct buffer: MZ\x90\x00 followed by padding and 'METERPRETER'
  const testBuf1 = Buffer.concat([
    Buffer.from([0x4D, 0x5A, 0x90, 0x00]),
    Buffer.from(' --- random payload segment --- '),
    Buffer.from('METERPRETER execution shell')
  ]);

  const matches = scanBufferWithRules(testBuf1, [compiled]);
  assert.strictEqual(matches.length, 1, 'Should match 1 rule');
  assert.strictEqual(matches[0].rule, 'detect_meterpreter_shell');
  assert.strictEqual(matches[0].matchedStringIds.includes('$mz'), true);
  assert.strictEqual(matches[0].matchedStringIds.includes('$tag'), true);
  console.log('✔ Test 2 passed: scanBufferWithRules evaluated hex wildcards and nocase conditions.');

  // Test 3: Text-based YARA rule parsing
  const textRule = `
rule CobaltStrike_Beacon_Marker {
    strings:
        $beacon = "BeaconJitter" nocase
        $hdr = { E8 00 00 00 00 }
    condition:
        $beacon or $hdr
}
`;
  const compiledText = compileYaraRule(textRule);
  assert.strictEqual(compiledText.name, 'CobaltStrike_Beacon_Marker');
  const testBuf2 = Buffer.from('Testing process memory containing BeaconJitter value');
  const matches2 = scanBufferWithRules(testBuf2, [compiledText]);
  assert.strictEqual(matches2.length, 1);
  console.log('✔ Test 3 passed: Text-based YARA syntax compiled and evaluated accurately.');

  // Test 4: Cobalt Strike Configuration Extraction
  // Craft a synthetic Cobalt Strike configuration block XOR-encoded with 0x69
  const xorKey = 0x69;
  const rawBytes = [];

  // Helper to append big-endian 2-byte short XOR-encoded
  function pushShort(val) {
    rawBytes.push(((val >> 8) & 0xff) ^ xorKey);
    rawBytes.push((val & 0xff) ^ xorKey);
  }

  // Helper to append big-endian 4-byte int XOR-encoded
  function pushInt(val) {
    rawBytes.push(((val >> 24) & 0xff) ^ xorKey);
    rawBytes.push(((val >> 16) & 0xff) ^ xorKey);
    rawBytes.push(((val >> 8) & 0xff) ^ xorKey);
    rawBytes.push((val & 0xff) ^ xorKey);
  }

  // Helper to append string TLV XOR-encoded
  function pushString(val) {
    pushShort(val.length + 1); // string length including null byte
    for (let i = 0; i < val.length; i++) {
      rawBytes.push(val.charCodeAt(i) ^ xorKey);
    }
    rawBytes.push(0x00 ^ xorKey); // null terminator
  }

  // TLV 1: BEACON_TYPE (short, 1) -> 8 (HTTPS)
  pushShort(1); // Type = 1 (BEACON_TYPE)
  pushShort(1); // ValType = 1 (short)
  pushShort(8); // Value = 8 (HTTPS)

  // TLV 2: PORT (short, 1) -> 443
  pushShort(2); // Type = 2 (PORT)
  pushShort(1); // ValType = 1 (short)
  pushShort(443); // Value = 443

  // TLV 3: SLEEP_TIME (int, 2) -> 5000ms
  pushShort(3); // Type = 3 (SLEEP_TIME)
  pushShort(2); // ValType = 2 (int)
  pushInt(5000); // 5000ms

  // TLV 8: C2_SERVERS (string, 3) -> 'evil-c2.darkcorp.internal'
  pushShort(8); // Type = 8 (C2_SERVERS)
  pushShort(3); // ValType = 3 (string)
  pushString('evil-c2.darkcorp.internal');

  // TLV 9: USER_AGENT (string, 3) -> 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'
  pushShort(9); // Type = 9 (USER_AGENT)
  pushShort(3); // ValType = 3 (string)
  pushString('Mozilla/5.0 (Windows NT 10.0; Win64; x64)');

  const syntheticCsDump = Buffer.concat([
    Buffer.alloc(128, 0x00), // Leading noise
    Buffer.from(rawBytes),
    Buffer.alloc(64, 0x00)   // Trailing noise
  ]);

  const csResult = extractCobaltStrikeConfig(syntheticCsDump);
  assert.strictEqual(csResult.detected, true, 'Cobalt Strike configuration must be detected');
  assert.strictEqual(csResult.xorKey, 0x69, 'Must determine 0x69 XOR key');
  assert.strictEqual(csResult.version, '4.x');
  assert.strictEqual(csResult.settings.BEACON_TYPE, 8);
  assert.strictEqual(csResult.settings.PORT, 443);
  assert.strictEqual(csResult.settings.SLEEP_TIME, 5000);
  assert.strictEqual(csResult.settings.C2_SERVERS, 'evil-c2.darkcorp.internal');
  assert.strictEqual(csResult.settings.USER_AGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)');
  console.log(`✔ Test 4 passed: extractCobaltStrikeConfig decrypted CS 4.x beacon config (C2: ${csResult.settings.C2_SERVERS}, Port: ${csResult.settings.PORT}).`);

  // Test 5: scanProcessMemory & generateYaraMemoryReport
  const scanResult = await scanProcessMemory(1337, [compiledText], { memoryBuffer: syntheticCsDump });
  assert.strictEqual(scanResult.pid, 1337);
  assert.strictEqual(scanResult.c2Config.detected, true);
  assert.strictEqual(scanResult.status, 'SUSPICIOUS_THREAT_DETECTED');

  const report = generateYaraMemoryReport(scanResult);
  assert.strictEqual(report.summary.status, 'CRITICAL_MALWARE_ACTIVE');
  assert.strictEqual(report.summary.c2Extracted, true);
  console.log('✔ Test 5 passed: scanProcessMemory and generateYaraMemoryReport generated complete incident triage output.');

  console.log('🎉 All In-Memory Process YARA & Cobalt Strike Extractor tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ YARA/Cobalt Strike tests failed:', err);
  process.exit(1);
});
