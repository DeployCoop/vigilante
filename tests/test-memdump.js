import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  parseProcMaps,
  detectMemoryAnomalies,
  extractProcessStrings,
  saveMemoryArtifact
} from '../src/engine/memdump.js';

async function runTests() {
  console.log('🧪 Testing In-Memory & Process Forensics Engine...');

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-memdump-'));

  // Test 1: Parse Linux /proc/$PID/maps
  const mockMaps = `
00400000-00452000 r-xp 00000000 08:02 173521  /usr/bin/nginx
00651000-00652000 r--p 00051000 08:02 173521  /usr/bin/nginx
00652000-00655000 rw-p 00052000 08:02 173521  /usr/bin/nginx
7f123400-7f124000 rwxp 00000000 00:00 0       [anonymous]
7f567800-7f568000 r-xp 00000000 08:02 998877  /tmp/.hidden-injected.so
55a8e000-55a90000 r-xp 00000000 08:02 554433  /usr/bin/backdoor (deleted)
7f880000-7f882000 r-xp 00000000 00:00 123456  /memfd:x64_payload (deleted)
`;

  const segments = parseProcMaps(mockMaps);
  if (segments.length !== 7) {
    throw new Error(`Expected 7 parsed segments, got: ${segments.length}`);
  }
  console.log(`✔ Test 1 passed: Parsed ${segments.length} process memory segments from /proc/maps.`);

  // Test 2: Detect Memory Anomalies (RWX, Deleted Binaries, Injected SO, Memfd)
  const anomalies = detectMemoryAnomalies(segments);
  if (anomalies.length !== 4) {
    throw new Error(`Expected 4 memory anomalies, got: ${anomalies.length}`);
  }

  const rwx = anomalies.find(a => a.type === 'RWX_MEMORY_SEGMENT');
  const deleted = anomalies.find(a => a.type === 'DELETED_EXECUTABLE_RUNNING');
  const injected = anomalies.find(a => a.type === 'SUSPICIOUS_LIBRARY_INJECTION');
  const memfd = anomalies.find(a => a.type === 'FILELESS_MEMFD_EXECUTION');

  if (!rwx || !deleted || !injected || !memfd) {
    throw new Error('Missing expected memory anomaly types');
  }
  console.log(`✔ Test 2 passed: Accurately flagged 4 critical in-memory anomalies (RWX, Memfd, Deleted Binary, /tmp Library).`);

  // Test 3: Strings Extraction & Shannon Entropy
  const payloadBuffer = Buffer.from(
    'GET /c2_beacon HTTP/1.1\r\nHost: evil.c2.net\r\nUser-Agent: Mozilla\r\n\x00\x00\xff\xee\xdd\xcc\xbb\xaa'
  );
  const stringResults = extractProcessStrings(payloadBuffer, 4);
  if (!stringResults.strings.includes('GET /c2_beacon HTTP/1.1') || stringResults.entropy <= 0) {
    throw new Error('Failed to extract strings or compute entropy');
  }
  console.log(`✔ Test 3 passed: Extracted ${stringResults.stringsCount} ASCII strings (Entropy: ${stringResults.entropy}).`);

  // Test 4: Save Memory Artifact Record
  const savedPath = await saveMemoryArtifact('nginx-ingress', 1337, { anomalies, segments }, payloadBuffer);
  const exists = await fs.stat(savedPath);
  if (!exists) throw new Error('Artifact metadata not persisted');
  console.log(`✔ Test 4 passed: Saved memory triage artifact and raw dump to Evidence Vault: ${savedPath}`);

  console.log('🎉 ALL 4 IN-MEMORY FORENSICS TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Memory Forensics test failure:', err);
  process.exit(1);
});
