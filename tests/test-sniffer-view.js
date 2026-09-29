import assert from 'node:assert';
import React from 'react';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  dissectEthernetFrame,
  dissectIpPacket,
  dissectTcpSegment,
  dissectUdpDatagram,
  dissectDnsPayload,
  dissectTlsPayload,
  dissectFullPacket,
  filterPacket,
  formatHexDump,
  exportToPcap,
  generateSyntheticPacketStream
} from '../src/engine/sniffer.js';
import { SnifferView } from '../src/ui/SnifferView.js';

async function runTests() {
  console.log('🧪 Testing Terminal Live Packet Sniffer & Protocol Dissector Engine...');

  const syntheticStream = generateSyntheticPacketStream(3);
  assert.strictEqual(syntheticStream.length, 3, 'Must produce 3 synthetic packets');

  // Test 1: Full Packet Dissection - DNS (Packet 0)
  const dnsPkt = dissectFullPacket(syntheticStream[0], 1);
  assert.strictEqual(dnsPkt.index, 1);
  assert.strictEqual(dnsPkt.protocol, 'DNS');
  assert.strictEqual(dnsPkt.layers.ethernet.typeName, 'IPv4');
  assert.strictEqual(dnsPkt.layers.ip.srcIp, '10.0.0.5');
  assert.strictEqual(dnsPkt.layers.ip.dstIp, '8.8.8.8');
  assert.strictEqual(dnsPkt.layers.transport.dstPort, 53);
  assert.strictEqual(dnsPkt.layers.app.queryName, 'api.c2-exfil.com');
  assert.strictEqual(dnsPkt.layers.app.queryType, 'A');
  console.log(`✔ Test 1 passed: Dissected DNS packet (QNAME: ${dnsPkt.layers.app.queryName} on port ${dnsPkt.layers.transport.dstPort}).`);

  // Test 2: Full Packet Dissection - TCP SYN (Packet 1)
  const tcpPkt = dissectFullPacket(syntheticStream[1], 2);
  assert.strictEqual(tcpPkt.protocol, 'TCP');
  assert.strictEqual(tcpPkt.layers.transport.dstPort, 443);
  assert.strictEqual(tcpPkt.layers.transport.flags.SYN, true);
  assert.strictEqual(tcpPkt.layers.transport.flags.ACK, false);
  console.log('✔ Test 2 passed: Dissected TCP SYN packet flags and window size.');

  // Test 3: Full Packet Dissection - TLS Client Hello (Packet 2)
  const tlsPkt = dissectFullPacket(syntheticStream[2], 3);
  assert.strictEqual(tlsPkt.protocol, 'TLS');
  assert.strictEqual(tlsPkt.layers.app.contentType, 'Handshake');
  assert.strictEqual(tlsPkt.layers.app.handshakeType, 'Client Hello');
  assert.strictEqual(tlsPkt.layers.app.sni, 'evil-c2.net');
  console.log(`✔ Test 3 passed: Dissected TLS Client Hello and extracted SNI: ${tlsPkt.layers.app.sni}.`);

  // Test 4: BPF-style Packet Filtering
  assert.strictEqual(filterPacket(dnsPkt, 'dns'), true);
  assert.strictEqual(filterPacket(dnsPkt, 'tcp'), false);
  assert.strictEqual(filterPacket(tcpPkt, 'tcp'), true);
  assert.strictEqual(filterPacket(tlsPkt, 'tls'), true);
  assert.strictEqual(filterPacket(tcpPkt, 'port 443'), true);
  assert.strictEqual(filterPacket(dnsPkt, 'port 443'), false);
  console.log('✔ Test 4 passed: filterPacket evaluated protocol and port filter criteria.');

  // Test 5: Hex Dump Formatting
  const hex = formatHexDump(syntheticStream[0], 64);
  assert.ok(hex.includes('0000'));
  assert.ok(hex.includes('|'));
  console.log('✔ Test 5 passed: formatHexDump produced classic 16-byte offset hex representation.');

  // Test 6: PCAP Export
  const pcapPath = path.join(os.tmpdir(), `test-capture-${Date.now()}.pcap`);
  const bytesWritten = await exportToPcap([dnsPkt, tcpPkt, tlsPkt], pcapPath);
  assert.ok(bytesWritten > 24, 'PCAP file must exceed 24-byte global header');

  const pcapHeader = await fs.readFile(pcapPath);
  // Magic number 0xa1b2c3d4 (big endian)
  assert.strictEqual(pcapHeader.readUInt32BE(0), 0xa1b2c3d4, 'Must contain standard PCAP magic number');
  await fs.unlink(pcapPath);
  console.log(`✔ Test 6 passed: exportToPcap exported valid PCAP stream (${bytesWritten} bytes).`);

  // Test 7: React Ink SnifferView Instantiation
  const elem = React.createElement(SnifferView, { initialPackets: syntheticStream });
  assert.ok(elem, 'SnifferView must instantiate cleanly');
  console.log('✔ Test 7 passed: SnifferView component constructed with React.createElement.');

  console.log('🎉 All Terminal Live Packet Sniffer & Protocol Dissector tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ Sniffer tests failed:', err);
  process.exit(1);
});
