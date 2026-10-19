import assert from 'node:assert';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Isolated config home BEFORE any engine state is touched.
const tmpXdg = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-suspects-xdg-'));
process.env.XDG_CONFIG_HOME = tmpXdg;
process.env.VIGILANTE_CTF_SECRET = '<MASKED_SECRET_001>';

const repoRoot = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const engine = (name) => path.join(repoRoot, 'packages/vigilante_lib/src/engine', name);

const { queryDataLake, runRetrospectiveThreatHunt, ingestSecurityEvents, closeDataLake } = await import(engine('datalake.js'));
const { spawnEphemeralSandbox, terminateSandbox } = await import(engine('kctf.js'));
const { parseZeekConnLogs } = await import(engine('traffic.js'));
const { triggerRansomwareContainment } = await import(engine('ransomware.js'));
const { buildCausalTimeline, identifyRootCause, calculateDwellTime } = await import(engine('timeline.js'));
const { findShortestAttackPath, calculateBlastRadius } = await import(engine('attackgraph.js'));
const { generateAdTickFlag, AttackDefenseRunner } = await import(engine('ad-runner.js'));
const { parseFalcoRulesYaml, validateFalcoRule } = await import(engine('falco.js'));
const { auditCloudStorageExposure, calculateCloudRiskScore } = await import(engine('cloudsec.js'));
const { buildAttackGraphFromBloodhound, calculateAdversaryResilienceScore } = await import(engine('adversary.js'));
const { recordNamespaceDeployment, saveInstanceMetadata, getDeployedNamespaces, loadInstanceMetadata } = await import(engine('instances.js'));
const { saveTriageBundle, listHostEvidence } = await import(engine('evidence.js'));
const { reconstructTcpStreams, carveFilesFromPayload } = await import(engine('forensics.js'));
const { detectAnomalousSocketConnections } = await import(engine('observability.js'));
const { runPipelineAudit } = await import(engine('audit.js'));
const { getVigilanteContainmentsDir, getHostEvidenceDir } = await import(engine('config.js'));

// ---------------------------------------------------------------------------
// 1. datalake: the query API is async now and returns real rows (SQLite
//    backend here; the DuckDB adapter returns a Promise from the same API).
// ---------------------------------------------------------------------------
{
  const pending = queryDataLake('SELECT 1 AS one');
  assert.ok(pending instanceof Promise, 'queryDataLake must return a Promise (DuckDB cannot be queried synchronously)');
  await pending;
  ingestSecurityEvents('PORT_SCAN', [{ id: 'suspect-evt-1', severity: 'HIGH', sourceIp: '198.51.100.7', destIp: '10.0.0.5', destPort: 22, indicator: 'evil.example', timestamp: new Date().toISOString() }]);
  const rows = await queryDataLake('SELECT id, indicator FROM security_events WHERE indicator = ?', ['evil.example']);
  assert.strictEqual(rows.length, 1);
  const hunt = await runRetrospectiveThreatHunt(['evil.example']);
  assert.strictEqual(hunt.length, 1);
  closeDataLake();
}
console.log('✔ Group 1 passed: datalake query API is async and returns rows.');

// ---------------------------------------------------------------------------
// 2. kctf: sandbox cleanup deletes type-qualified names only — never the
//    types x names cross-product.
// ---------------------------------------------------------------------------
{
  const stubDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-kubectl-argv-'));
  const argvLog = path.join(stubDir, 'argv.log');
  fs.writeFileSync(path.join(stubDir, 'kubectl'), `#!/bin/sh\necho "$@" >> ${argvLog}\nexit 0\n`, { mode: 0o755 });
  const oldPath = process.env.PATH;
  process.env.PATH = stubDir + ':' + oldPath;
  try {
    const sbx = await spawnEphemeralSandbox({ teamId: 'teamargv', challengeId: 'crypto-oracle-rsa', mock: true });
    await terminateSandbox({ sandboxId: sbx.id, mock: false });
  } finally {
    process.env.PATH = oldPath;
  }
  const deleteLine = fs.readFileSync(argvLog, 'utf8').split('\n').find(l => l.startsWith('delete '));
  assert.ok(deleteLine, 'kubectl delete must have been invoked');
  assert.ok(deleteLine.includes('deployment/teamargv-crypto-oracle-rsa'), deleteLine);
  assert.ok(deleteLine.includes('service/teamargv-crypto-oracle-rsa'), deleteLine);
  assert.ok(deleteLine.includes('ingress/teamargv-crypto-oracle-rsa-ingress'), deleteLine);
  assert.ok(deleteLine.includes('networkpolicy/teamargv-crypto-oracle-rsa-netpol'), deleteLine);
  assert.ok(!deleteLine.includes('deployment,service'), 'cross-product type list must be gone');
}
console.log('✔ Group 2 passed: kCTF cleanup deletes exactly the four owned objects, type-qualified.');

// ---------------------------------------------------------------------------
// 3. traffic: Zeek TSV rows split on the declared separator, so a field
//    containing a space no longer shifts every later column.
// ---------------------------------------------------------------------------
{
  const header = [
    '#separator \\x09',
    '#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tservice\tduration\torig_bytes\tresp_bytes\tconn_state\tlocal_orig\tlocal_resp\tmissed_bytes\thistory\torig_pkts\torig_ip_bytes\tresp_pkts\tresp_ip_bytes\ttunnel_parents'
  ];
  const row = ['1700000000.5', 'Cabc', '10.0.0.1', '51514', '93.184.216.34', '80', 'tcp', 'http proxy', '1.5', '1200', '3400', 'SF', '-', '-', '0', 'ShADadfF', '6', '1456', '5', '3656', '(empty)'].join('\t');
  const parsed = parseZeekConnLogs([...header, row].join('\n'));
  assert.strictEqual(parsed.connections.length, 1);
  const conn = parsed.connections[0];
  assert.strictEqual(conn.service, 'http proxy');
  assert.strictEqual(conn.duration, 1.5);
  assert.strictEqual(conn.origBytes, 1200);
  assert.strictEqual(conn.connState, 'SF');
}
console.log('✔ Group 3 passed: Zeek TSV parsing honors the tab separator; spaced fields stay in their column.');

// ---------------------------------------------------------------------------
// 4. timeline: honest confidence (no +0.2), honest dwell (never detected
//    => null, not 0), duplicate event ids collapse consistently.
// ---------------------------------------------------------------------------
{
  // Dwell: no HIGH/CRITICAL event -> never detected.
  const quietDag = buildCausalTimeline([
    { id: 'q1', timestamp: '2026-01-01T00:00:00.000Z', severity: 'LOW', entity: 'pod-a' },
    { id: 'q2', timestamp: '2026-01-01T01:00:00.000Z', severity: 'MEDIUM', entity: 'pod-a' }
  ]);
  const dwell = calculateDwellTime(quietDag);
  assert.strictEqual(dwell.firstDetectionTime, null);
  assert.strictEqual(dwell.timeToDetectMs, null);
  assert.strictEqual(dwell.timeToRemediateMs, null);
  assert.strictEqual(dwell.dwellTimeMs, 3600000);

  // Dwell control: with a CRITICAL event, detection metrics are numeric.
  const loudDag = buildCausalTimeline([
    { id: 'l1', timestamp: '2026-01-01T00:00:00.000Z', severity: 'LOW', entity: 'pod-a' },
    { id: 'l2', timestamp: '2026-01-01T00:30:00.000Z', severity: 'CRITICAL', entity: 'pod-a' }
  ]);
  const loudDwell = calculateDwellTime(loudDag);
  assert.strictEqual(loudDwell.timeToDetectMs, 1800000);

  // Confidence is the plain reachable fraction: craft a DAG whose best
  // root reaches 2 of 4 nodes -> 0.5, not 0.7.
  const manualDag = {
    nodes: [{ id: 'r' }, { id: 'a' }, { id: 'x' }, { id: 'y' }],
    adjacency: new Map([
      ['r', [{ from: 'r', to: 'a' }]],
      ['a', []],
      ['x', [{ from: 'x', to: 'y' }]],
      ['y', []]
    ]),
    inDegrees: new Map([['r', 0], ['a', 1], ['x', 0], ['y', 1]])
  };
  const rc = identifyRootCause(manualDag);
  assert.strictEqual(rc.confidence, 0.5, `confidence must be reach/total (got ${rc.confidence})`);

  // Duplicate ids: nodes, adjacency, and stats must agree.
  const dupDag = buildCausalTimeline([
    { id: 'dup', timestamp: '2026-01-01T00:00:00.000Z', severity: 'LOW', entity: 'pod-a' },
    { id: 'dup', timestamp: '2026-01-01T00:01:00.000Z', severity: 'HIGH', entity: 'pod-b' },
    { id: 'solo', timestamp: '2026-01-01T00:02:00.000Z', severity: 'LOW', entity: 'pod-c' }
  ]);
  assert.strictEqual(dupDag.nodes.length, 2);
  assert.strictEqual(dupDag.stats.totalEvents, 2);
  assert.strictEqual(dupDag.adjacency.size, 2);
}
console.log('✔ Group 4 passed: timeline confidence, dwell, and duplicate-id handling are honest.');

// ---------------------------------------------------------------------------
// 5. attackgraph: shortest path means cheapest under edge cost.
// ---------------------------------------------------------------------------
{
  const nodes = [
    { id: 'A', label: 'Attacker', type: 'Identity', tier: 'Edge' },
    { id: 'B', label: 'Jump host', type: 'Host', tier: 'Restricted' },
    { id: 'C', label: 'Crown jewel DB', type: 'Datastore', tier: 'CrownJewel' }
  ];
  const edges = [
    { from: 'A', to: 'C', cost: 100 },
    { from: 'A', to: 'B', cost: 1 },
    { from: 'B', to: 'C', cost: 1 }
  ];
  const adjacency = new Map(nodes.map(n => [n.id, []]));
  for (const e of edges) adjacency.get(e.from).push(e);
  const graph = { nodes, edges, adjacency, stats: { totalNodes: 3, totalEdges: 3 } };
  const cheapest = findShortestAttackPath('A', 'C', graph);
  assert.strictEqual(cheapest.pathFound, true);
  assert.deepStrictEqual(cheapest.nodePath, ['A', 'B', 'C']);
  assert.strictEqual(cheapest.totalCost, 2);
  const blast = calculateBlastRadius('A', graph);
  assert.strictEqual(blast.criticalPaths.length, 1);
  assert.deepStrictEqual(blast.criticalPaths[0].nodePath, ['A', 'B', 'C']);
}
console.log('✔ Group 5 passed: attack path search minimizes total edge cost (Dijkstra).');

// ---------------------------------------------------------------------------
// 6. ad-runner: no published-literal flag secret; ticks never overlap.
// ---------------------------------------------------------------------------
{
  assert.throws(() => generateAdTickFlag({ teamId: 't1', serviceId: 'svc', tick: 1 }), /requires a secretKey/);
  assert.throws(() => generateAdTickFlag({ teamId: 't1', serviceId: 'svc', tick: 1, secretKey: '' }), /requires a secretKey/);
  const flag = generateAdTickFlag({ teamId: 't1', serviceId: 'svc', tick: 1, secretKey: 'real-secret' });
  assert.ok(flag.startsWith('VIGILANTE{ad__svc__t1__t1__'));

  const fakeTournament = {
    secretKey: 'real-secret',
    teams: new Map(),
    adState: { currentTick: 0 }
  };
  const runner = new AttackDefenseRunner({ tournamentEngine: fakeTournament, mockProbes: true });
  runner.tickInFlight = true; // simulate a tick slower than the interval
  const skipped = await runner.stepTick();
  assert.strictEqual(skipped, null);
  assert.strictEqual(fakeTournament.adState.currentTick, 0, 'an overlapped tick must not advance the tick counter');
}
console.log('✔ Group 6 passed: AD flags fail closed without a secret; overlapping ticks are skipped.');

// ---------------------------------------------------------------------------
// 7. falco: dict-shaped YAML parses; quoted parens are data, not syntax.
// ---------------------------------------------------------------------------
{
  const listForm = '- rule: R1\n  condition: proc.name = cat\n';
  assert.strictEqual(parseFalcoRulesYaml(listForm).length, 1);
  const wrapped = 'rules:\n  - rule: R2\n    condition: proc.name = cat\n';
  const wrappedParsed = parseFalcoRulesYaml(wrapped);
  assert.strictEqual(wrappedParsed.length, 1);
  assert.strictEqual(wrappedParsed[0].rule, 'R2');
  const single = 'rule: R3\ncondition: proc.name = cat\n';
  assert.strictEqual(parseFalcoRulesYaml(single).length, 1);

  const base = { rule: 'R', output: 'out %proc.name', priority: 'WARNING' };
  const quoted = validateFalcoRule({ ...base, condition: 'proc.cmdline contains ")" and (fd.name = /tmp)' });
  assert.strictEqual(quoted.valid, true, JSON.stringify(quoted.errors));
  const unbalanced = validateFalcoRule({ ...base, condition: 'proc.name = cat and (fd.name = /tmp' });
  assert.strictEqual(unbalanced.valid, false);
}
console.log('✔ Group 7 passed: Falco YAML dict forms parse; the paren counter respects quotes.');

// ---------------------------------------------------------------------------
// 8. cloudsec: object grants count, publicAccessBlock alone does not flag,
//    {enabled:false} is not encryption, severity casing is normalized.
// ---------------------------------------------------------------------------
{
  const pub = (findings) => findings.filter(f => f.type === 'STORAGE_PUBLIC_READ');
  assert.strictEqual(pub(auditCloudStorageExposure([{ bucketName: 'gcs-obj', grants: [{ entity: 'allUsers', role: 'READER' }], encryptionEnabled: true }])).length, 1, 'GCS object grant must flag');
  assert.strictEqual(pub(auditCloudStorageExposure([{ bucketName: 'aws-obj', grants: [{ grantee: { type: 'Group', uri: 'http://acs.amazonaws.com/groups/global/AllUsers' }, permission: 'READ' }], encryptionEnabled: true }])).length, 1, 'AWS object grant must flag');
  assert.strictEqual(pub(auditCloudStorageExposure([{ bucketName: 'private-bucket', publicAccessBlock: false, encryptionEnabled: true }])).length, 0, 'publicAccessBlock:false alone is not exposure');
  const unenc = (findings) => findings.filter(f => f.type === 'STORAGE_UNENCRYPTED');
  assert.strictEqual(unenc(auditCloudStorageExposure([{ bucketName: 'enc-off', encryption: { enabled: false } }])).length, 1);
  assert.strictEqual(unenc(auditCloudStorageExposure([{ bucketName: 'enc-kms', encryption: { defaultKmsKeyName: 'key-1' } }])).length, 0);
  const risk = calculateCloudRiskScore([{ severity: 'critical' }, { severity: 'Critical' }]);
  assert.strictEqual(risk.score, 70);
  assert.strictEqual(risk.criticalCount, 2);
}
console.log('✔ Group 8 passed: cloud storage audit reads real grant shapes and scores severities case-insensitively.');

// ---------------------------------------------------------------------------
// 9. adversary: an isolated HVT is not its own attack path; the resilience
//    score never goes NaN.
// ---------------------------------------------------------------------------
{
  const paths = buildAttackGraphFromBloodhound({
    nodes: [
      { id: 'user-a', label: 'User A' },
      { id: 'workstation', label: 'WS' },
      { id: 'cluster-admin', label: 'cluster-admin', isHVT: true }
    ],
    edges: [{ source: 'user-a', target: 'workstation', relationship: 'AdminTo' }]
  }, 'cluster-admin');
  assert.ok(paths.every(p => (p.hops || p.path?.length || 1) > 0 || (Array.isArray(p.nodePath) && p.nodePath.length > 1) || p.startNodeId !== 'cluster-admin'),
    'no 0-hop self path for the isolated HVT');
  assert.ok(!paths.some(p => Array.isArray(p.nodePath) && p.nodePath.length === 1 && p.nodePath[0] === 'cluster-admin'));

  const score = calculateAdversaryResilienceScore({ contained: true, containmentStep: 1, totalHops: 0 });
  assert.ok(Number.isFinite(score.score), `score must be finite, got ${score.score}`);
}
console.log('✔ Group 9 passed: adversary paths exclude the HVT self-path; resilience score is finite at totalHops 0.');

// ---------------------------------------------------------------------------
// 10. instances: concurrent metadata writers lose nothing.
// ---------------------------------------------------------------------------
{
  await Promise.all(Array.from({ length: 8 }, (_, i) =>
    recordNamespaceDeployment('race-inst', `ns-${i}`, ['mod-a'])));
  const deployed = await getDeployedNamespaces('race-inst');
  assert.strictEqual(Object.keys(deployed).length, 8, `expected 8 namespaces, got ${Object.keys(deployed).length}`);

  await Promise.all(Array.from({ length: 8 }, (_, i) =>
    saveInstanceMetadata('race-inst-2', { [`key${i}`]: i })));
  const meta = await loadInstanceMetadata('race-inst-2');
  for (let i = 0; i < 8; i++) assert.strictEqual(meta[`key${i}`], i);
}
console.log('✔ Group 10 passed: instance metadata writes are serialized; no lost updates under concurrency.');

// ---------------------------------------------------------------------------
// 11. evidence: triage total equals the returned artifact count;
//     signaturePath names the signature file that exists.
// ---------------------------------------------------------------------------
{
  const bundle = {
    ping: { success: true, minRtt: '0.04ms', avgRtt: '0.05ms' },
    mtr: 'Start: test\nHOST: gw Loss% 0.0%',
    dns: { aRecords: ['192.0.2.10'], ptr: 'host.example' },
    tls: '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----',
    http: 'HTTP/1.1 200 OK\nServer: nginx',
    arp: '192.0.2.10 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE'
  };
  const res = await saveTriageBundle('10.0.0.0/24', '192.0.2.10', bundle);
  const summary = JSON.parse(await fsp.readFile(path.join(res.hostDir, 'triage_summary.json'), 'utf8'));
  assert.strictEqual(summary.totalArtifacts, res.artifacts.length,
    `stamped total ${summary.totalArtifacts} vs returned artifacts ${res.artifacts.length}`);

  const hostDir = getHostEvidenceDir('10.0.0.0/24', '192.0.2.10');
  await fsp.writeFile(path.join(hostDir, 'sig-only.json'), '{}');
  await fsp.writeFile(path.join(hostDir, 'sig-only.json.sig'), 'FAKESIG');
  const listed = await listHostEvidence('10.0.0.0/24', '192.0.2.10');
  const entry = listed.find(a => a.name === 'sig-only.json');
  assert.ok(entry && entry.isSigned === true);
  assert.ok(entry.signaturePath.endsWith('sig-only.json.sig'), entry.signaturePath);
  assert.ok(fs.existsSync(entry.signaturePath));
}
console.log('✔ Group 11 passed: evidence counts are exact and signature paths point at real files.');

// ---------------------------------------------------------------------------
// 12. forensics: stream packet lengths match the byte totals, stream
//     bounds are min/max, carve filenames cannot escape or overwrite.
// ---------------------------------------------------------------------------
{
  const streams = reconstructTcpStreams([
    { srcIp: '10.0.0.1', srcPort: 1111, dstIp: '10.0.0.2', dstPort: 80, payload: 'hello', timestamp: '2026-01-01T00:00:10.000Z' },
    { srcIp: '10.0.0.2', srcPort: 80, dstIp: '10.0.0.1', dstPort: 1111, payload: 'world!', timestamp: '2026-01-01T00:00:05.000Z' }
  ]);
  assert.strictEqual(streams.length, 1);
  const s = streams[0];
  assert.strictEqual(s.bytesTransferred, 11);
  assert.deepStrictEqual(s.packets.map(p => p.length).sort(), [5, 6]);
  assert.strictEqual(s.startTime, '2026-01-01T00:00:05.000Z');
  assert.strictEqual(s.endTime, '2026-01-01T00:00:10.000Z');

  const carveDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-carve-'));
  const mkHttp = (filename, body) => `HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename="${filename}"\r\n\r\n${body}`;
  const dotdot = await carveFilesFromPayload(mkHttp('..', 'DOTDOT'), { outputDir: carveDir });
  assert.strictEqual(dotdot.length, 1);
  assert.ok(dotdot[0].filePath.startsWith(carveDir + path.sep), dotdot[0].filePath);
  assert.strictEqual(await fsp.readFile(dotdot[0].filePath, 'utf8'), 'DOTDOT');

  const first = await carveFilesFromPayload(mkHttp('loot.txt', 'FIRST'), { outputDir: carveDir });
  const second = await carveFilesFromPayload(mkHttp('loot.txt', 'SECOND'), { outputDir: carveDir });
  assert.notStrictEqual(first[0].filePath, second[0].filePath);
  assert.strictEqual(await fsp.readFile(first[0].filePath, 'utf8'), 'FIRST');
  assert.strictEqual(await fsp.readFile(second[0].filePath, 'utf8'), 'SECOND');
}
console.log('✔ Group 12 passed: forensics stream accounting is consistent; carving is contained and non-destructive.');

// ---------------------------------------------------------------------------
// 13. observability: non-string destinations never throw.
// ---------------------------------------------------------------------------
{
  const matrix = { connections: [
    { source: 'pod-a', destination: 12345, dstPort: 8081, protocol: 'TCP', lastSeen: '2026-01-01T00:00:00.000Z' },
    { source: 'pod-a', destination: null, dstPort: 8082, protocol: 'TCP', lastSeen: '2026-01-01T00:00:00.000Z' },
    { source: 'pod-a', destination: { ip: '203.0.113.9' }, dstPort: 8083, protocol: 'TCP', lastSeen: '2026-01-01T00:00:00.000Z' },
    { source: 'pod-a', destination: '203.0.113.9', dstPort: 8084, protocol: 'TCP', lastSeen: '2026-01-01T00:00:00.000Z' }
  ] };
  let anomalies;
  assert.doesNotThrow(() => { anomalies = detectAnomalousSocketConnections(matrix, {}); });
  assert.ok(anomalies.some(a => a.type === 'UNAUTHORIZED_EXTERNAL_EGRESS_PORT' && a.destination === '203.0.113.9'),
    'the string-destination control must still be flagged');
}
console.log('✔ Group 13 passed: socket anomaly detection tolerates non-string destinations.');

// ---------------------------------------------------------------------------
// 14. audit: symlink cycles neither abort the audit nor double-count.
// ---------------------------------------------------------------------------
{
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'vigilante-audit-tree-'));
  fs.mkdirSync(path.join(root, 'sub'));
  fs.writeFileSync(path.join(root, 'sub', 'deploy.yaml'), 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: x\nspec:\n  containers:\n    - name: c\n      image: busybox\n      securityContext:\n        privileged: true\n');
  fs.symlinkSync(path.join(root, 'sub'), path.join(root, 'alias'));
  fs.symlinkSync(root, path.join(root, 'sub', 'loop'));
  const audit = await runPipelineAudit(root);
  assert.strictEqual(audit.filesScanned, 1, `expected the one real file scanned once, got ${audit.filesScanned}`);
}
console.log('✔ Group 14 passed: pipeline audit survives symlink cycles and counts each real file once.');

// ---------------------------------------------------------------------------
// 15. ransomware: containment reports failure when both SOAR actions fail.
//     (Runs last: it sabotages the containments dir of this process's
//     isolated config home.)
// ---------------------------------------------------------------------------
{
  const okRes = await triggerRansomwareContainment('web-0', 'prod', 4242, { apply: true });
  assert.strictEqual(okRes.containmentSuccess, true);
  assert.deepStrictEqual(okRes.containmentFailures, []);

  const containmentsDir = getVigilanteContainmentsDir();
  await fsp.rm(containmentsDir, { recursive: true, force: true });
  await fsp.writeFile(containmentsDir, 'not a directory');
  const failRes = await triggerRansomwareContainment('web-0', 'prod', 4242, { apply: true });
  assert.strictEqual(failRes.freezeResult, null);
  assert.strictEqual(failRes.isolateResult, null);
  assert.strictEqual(failRes.containmentSuccess, false);
  assert.deepStrictEqual(failRes.containmentFailures.sort(), ['freeze', 'isolate']);
}
console.log('✔ Group 15 passed: ransomware containment success is earned, not hardcoded.');

console.log('\n🎉 All suspect-engine regression tests passed successfully!\n');
