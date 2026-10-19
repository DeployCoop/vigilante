import assert from 'node:assert';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';

console.log('🧪 Testing engine leftovers: Sigma correctness (A2/A3/A4), PCAP replay honesty (D12/D13), recon partial-output handling (D14), sandbox TTL policy (D16)...');

const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-leftovers-'));
process.env.XDG_CONFIG_HOME = tmpRoot;
process.env.VIGILANTE_CTF_SECRET = 'leftovers-test-secret';

const { parseSigmaRule, transpileSigmaToSql, runSigmaThreatHunt } = await import('../src/engine/sigma.js');
const { initDataLake, ingestSecurityEvents, closeDataLake } = await import('../src/engine/datalake.js');
const { replayPcap } = await import('../src/engine/traffic.js');
const { runReconScan } = await import('../src/engine/recon.js');
const kctf = await import('../src/engine/kctf.js');

// Test 1 (A2): boolean normalization must not rewrite words inside literal values
{
  initDataLake(path.join(tmpRoot, 'events.db'));
  ingestSecurityEvents('network', [
    { sourceIp: '10.0.0.1', destIp: '10.0.0.2', destPort: 443, severity: 'HIGH', indicator: 'this or that', sourcePod: 'pod-a' },
    { sourceIp: '10.0.0.3', destIp: '10.0.0.4', destPort: 443, severity: 'HIGH', indicator: 'other', sourcePod: 'pod-b' }
  ]);
  const rule = {
    title: 'literal-words', level: 'high',
    detection: { selection: { indicator: 'this or that' }, condition: 'selection' }
  };
  const matches = await runSigmaThreatHunt([rule]);
  assert.strictEqual(matches.length, 1, 'Rule with an "or" inside its literal value must still match');
  assert.strictEqual(matches[0].matchCount, 1);
  assert.strictEqual(matches[0].events[0].indicator, 'this or that');
}
console.log('✔ Test 1 passed: Sigma literals containing and/or/not survive transpilation (A2).');

// Test 2 (A3): "1 of <pattern>" / "all of <pattern>" honor the named group
{
  const ruleFor = (condition) => ({
    title: 'grouped', level: 'high',
    detection: {
      selection_port: { 'destination.port': 443 },
      selection_ioc: { indicator: 'evil' },
      condition
    }
  });
  const onlyPort = transpileSigmaToSql(ruleFor('1 of selection_port'));
  assert.ok(onlyPort.sql.includes('dest_port = 443'), 'Port clause present');
  assert.ok(!onlyPort.sql.includes("indicator = 'evil'"), '"1 of selection_port" must not pull in the IOC selection');

  const onlyIoc = transpileSigmaToSql(ruleFor('all of selection_ioc'));
  assert.ok(onlyIoc.sql.includes("indicator = 'evil'"));
  assert.ok(!onlyIoc.sql.includes('dest_port = 443'), '"all of selection_ioc" must not pull in the port selection');

  const both = transpileSigmaToSql(ruleFor('1 of selection*'));
  assert.ok(both.sql.includes('dest_port = 443') && both.sql.includes("indicator = 'evil'"), '"1 of selection*" still combines all selections');

  // End to end: only the port rows match the narrowed rule
  const matches = await runSigmaThreatHunt([ruleFor('1 of selection_port')]);
  assert.strictEqual(matches.length, 1);
  assert.strictEqual(matches[0].matchCount, 2, 'Both seeded rows have dest_port 443');
  closeDataLake();
}
console.log('✔ Test 2 passed: Sigma group selections honor the captured pattern (A3).');

// Test 3 (A4): YAML list values survive parsing and transpile to an OR of clauses
{
  const yaml = [
    'title: List Ports',
    'level: high',
    'detection:',
    '  selection:',
    '    destination.port:',
    '      - 445',
    '      - 443',
    '  condition: selection'
  ].join('\n');
  const parsed = parseSigmaRule(yaml);
  assert.deepStrictEqual(parsed.detection.selection['destination.port'], ['445', '443']);
  const { sql } = transpileSigmaToSql(parsed);
  assert.ok(sql.includes('dest_port = 445') && sql.includes('dest_port = 443'), `List transpiles to both ports: ${sql}`);
  assert.ok(sql.includes(' OR '), 'List values combine with OR');
}
console.log('✔ Test 3 passed: YAML list values parse into arrays and transpile correctly (A4).');

// Test 4 (D12/D13): replayPcap validates captures and reports staging honestly
{
  const textFile = path.join(tmpRoot, 'fake.pcap');
  await fs.writeFile(textFile, 'this is not a capture');
  await assert.rejects(() => replayPcap(textFile, { copyToPod: false }), /magic bytes/);

  const wrongExt = path.join(tmpRoot, 'real.txt');
  const header = Buffer.alloc(24);
  header.writeUInt32BE(0xa1b2c3d4, 0);
  await fs.writeFile(wrongExt, header);
  await assert.rejects(() => replayPcap(wrongExt, { copyToPod: false }), /capture file/);

  const good = path.join(tmpRoot, 'real.pcap');
  await fs.writeFile(good, header);
  const staged = await replayPcap(good, { copyToPod: false });
  assert.strictEqual(staged.status, 'staged');
  assert.strictEqual(staged.copiedToPods, false);

  // No cluster in this environment: pods cannot be listed, so the result
  // must say staged_locally rather than dispatched
  const noCluster = await replayPcap(good, {});
  assert.strictEqual(noCluster.copiedToPods, false);
  assert.strictEqual(noCluster.status, 'staged_locally');
}
console.log('✔ Test 4 passed: replayPcap rejects non-captures and never fabricates dispatch (D12/D13).');

// Test 5 (D14): a scanner exiting non-zero with findings on stdout still yields a scan record
{
  const binDir = path.join(tmpRoot, 'bin');
  await fs.mkdir(binDir, { recursive: true });
  const stub = `#!/bin/sh
if [ "$1" = "-version" ]; then echo "naabu 2.3.0"; exit 0; fi
echo "127.0.0.1:8443"
exit 1
`;
  const stubPath = path.join(binDir, 'naabu');
  await fs.writeFile(stubPath, stub);
  await fs.chmod(stubPath, 0o755);
  const oldPath = process.env.PATH;
  process.env.PATH = `${binDir}:${oldPath}`;
  try {
    const record = await runReconScan('127.0.0.1', 'fast-ports');
    assert.ok(record.openPorts.some(p => p.port === 8443), `Non-zero scanner exit must not lose findings: ${JSON.stringify(record.openPorts)}`);
  } finally {
    process.env.PATH = oldPath;
  }
}
console.log('✔ Test 5 passed: Recon parses partial stdout on non-zero scanner exits (D14).');

// Test 6 (D16): sandbox TTL is clamped at spawn, not only on extension
{
  const huge = await kctf.spawnEphemeralSandbox({
    teamId: 'ttl-team', challengeId: 'web-flag-leak', ttlMinutes: 99999, mock: true
  });
  assert.strictEqual(huge.ttlMinutes, 120, 'Spawn TTL clamps to MAX_SANDBOX_TTL_MINUTES');
  const ttlMs = new Date(huge.expiresAt) - new Date(huge.createdAt);
  assert.ok(Math.abs(ttlMs - 120 * 60 * 1000) < 5000, 'Expiry reflects the clamped TTL');

  const zero = await kctf.spawnEphemeralSandbox({
    teamId: 'ttl-team', challengeId: 'pwn-nsjail-echo', ttlMinutes: 0, mock: true
  });
  assert.strictEqual(zero.ttlMinutes, 1, 'Spawn TTL floors at 1 minute');

  await assert.rejects(
    () => kctf.spawnEphemeralSandbox({ teamId: 'ttl-team', challengeId: 'crypto-oracle-rsa', ttlMinutes: 'forever', mock: true }),
    /Invalid ttlMinutes/
  );
}
console.log('✔ Test 6 passed: Sandbox spawn enforces the TTL policy (D16).');

console.log('\n🎉 All engine-leftover tests passed successfully!\n');
