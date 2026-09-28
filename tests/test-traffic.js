import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  parseSuricataEve,
  parseZeekConnLogs,
  summarizeTrafficAlerts,
  replayPcap,
  listPcapRecordings
} from '../src/engine/traffic.js';

async function runTests() {
  console.log('🧪 Testing Traffic & PCAP Replay Engine (Suricata & Zeek)...');

  // Test 1: Parse Suricata Eve NDJSON
  const sampleEve = `
{"timestamp":"2026-09-26T20:00:01.000Z","event_type":"alert","src_ip":"192.168.1.100","src_port":44444,"dest_ip":"10.0.0.5","dest_port":80,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2000001,"rev":1,"signature":"ET EXPLOIT Apache Struts RCE","category":"Web Application Attack","severity":1}}
{"timestamp":"2026-09-26T20:00:02.000Z","event_type":"alert","src_ip":"192.168.1.100","src_port":44445,"dest_ip":"10.0.0.5","dest_port":443,"proto":"TCP","alert":{"action":"allowed","gid":1,"signature_id":2000002,"rev":1,"signature":"ET SCAN Nmap Scripting Engine Probe","category":"Attempted Information Leak","severity":2}}
{"timestamp":"2026-09-26T20:00:03.000Z","event_type":"dns","src_ip":"10.0.0.5","dest_ip":"1.1.1.1","dns":{"type":"query","rrname":"c2.malicious.io","rrtype":"A","rcode":"NOERROR"}}
{"timestamp":"2026-09-26T20:00:04.000Z","event_type":"http","src_ip":"192.168.1.100","dest_ip":"10.0.0.5","http":{"hostname":"10.0.0.5","url":"/upload.php","http_method":"POST","status":200,"http_user_agent":"curl/8.0"}}
`;

  const parsedEve = parseSuricataEve(sampleEve);
  assert.strictEqual(parsedEve.alerts.length, 2, 'Should parse 2 alerts');
  assert.strictEqual(parsedEve.alerts[0].severity, 'critical', 'Severity 1 maps to critical');
  assert.strictEqual(parsedEve.alerts[1].severity, 'high', 'Severity 2 maps to high');
  assert.strictEqual(parsedEve.dnsEvents.length, 1, 'Should parse 1 DNS query');
  assert.strictEqual(parsedEve.httpEvents.length, 1, 'Should parse 1 HTTP event');
  assert.strictEqual(parsedEve.statistics.severityCounts.critical, 1);
  assert.strictEqual(parsedEve.statistics.severityCounts.high, 1);
  console.log('✔ Test 1 passed: parseSuricataEve parsed NDJSON events, mapped severities, and generated statistics.');

  // Test 2: Parse Zeek TSV / JSON connections
  const sampleZeekTsv = `#separator \\x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	proto	service	duration	orig_bytes	resp_bytes	conn_state	local_orig	local_resp	missed_bytes	history	orig_pkts	orig_ip_bytes	resp_pkts	resp_ip_bytes	tunnel_parents
1758920400.000000	CHhAvV3ryKddrqovdl	192.168.1.100	54321	10.0.0.5	4444	tcp	-	0.001	0	0	S0	-	-	0	S	1	60	0	0	-
1758920401.000000	C2x1vV3ryKddrqovdl	192.168.1.100	54322	10.0.0.5	80	tcp	http	0.521	340	1200	SF	-	-	0	ShADadfF	5	540	8	1500	-
`;

  const parsedZeek = parseZeekConnLogs(sampleZeekTsv);
  assert.strictEqual(parsedZeek.totalConnections, 2, 'Should parse 2 Zeek connections');
  assert.strictEqual(parsedZeek.connections[0].srcIp, '192.168.1.100');
  assert.strictEqual(parsedZeek.connections[0].destPort, 4444);
  assert.strictEqual(parsedZeek.connections[0].connState, 'S0');
  assert.strictEqual(parsedZeek.suspiciousConnections.length, 1, 'Connection with S0 / port 4444 should be flagged as suspicious');
  console.log('✔ Test 2 passed: parseZeekConnLogs parsed TSV connections and flagged suspicious states.');

  // Test 3: Summarize traffic alerts
  const summary = summarizeTrafficAlerts({ suricataResult: parsedEve, zeekResult: parsedZeek });
  assert.strictEqual(summary.riskTier, 'CRITICAL', 'Critical alert should produce CRITICAL risk tier');
  assert.strictEqual(summary.score, 95);
  assert.strictEqual(summary.suricata.alertCount, 2);
  assert.strictEqual(summary.zeek.suspiciousCount, 1);
  console.log('✔ Test 3 passed: summarizeTrafficAlerts generated composite threat score and tier.');

  // Test 4: Replay PCAP
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-traffic-test-'));
  const dummyPcap = path.join(tmpDir, 'test-capture.pcap');
  await fs.writeFile(dummyPcap, 'DUMMY_PCAP_DATA_MAGIC_HEADER_VIGILANTE');

  const replayResult = await replayPcap(dummyPcap, { copyToPod: false });
  assert.strictEqual(replayResult.fileName, 'test-capture.pcap');
  assert(replayResult.sizeBytes > 0);
  assert(replayResult.id.startsWith('pcap-'));
  console.log(`✔ Test 4 passed: replayPcap staged file in dropzone and recorded evidence ID: ${replayResult.id}.`);

  // Test 5: List staged PCAPs
  const pcaps = await listPcapRecordings();
  assert(Array.isArray(pcaps));
  assert(pcaps.some(p => p.name === 'test-capture.pcap'), 'Should list staged test pcap');
  console.log('✔ Test 5 passed: listPcapRecordings successfully listed staged PCAPs.');

  await fs.rm(tmpDir, { recursive: true, force: true });
  console.log('🎉 ALL 5 TRAFFIC ENGINE TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Traffic Engine test failed:', err);
  process.exit(1);
});
