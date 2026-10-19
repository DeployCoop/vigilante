import assert from 'node:assert';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';

console.log('🧪 Testing fail-closed cryptography: federation, cosign, ledger, evidence pack, snapshot, ctf-client...');

const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-failclosed-'));
process.env.XDG_CONFIG_HOME = tmpRoot;
delete process.env.VIGILANTE_LEDGER_SECRET;
delete process.env.VIGILANTE_TSA_KEY;
delete process.env.VIGILANTE_SNAPSHOT_KEY;

const { signThreatRecord, verifyThreatRecord, canonicalJson } = await import('../src/engine/federation.js');
const { verifyCosignSignature } = await import('../src/engine/supplychain.js');
const ledger = await import('../src/engine/ledger.js');
const ep = await import('../src/engine/evidencepack.js');
const snap = await import('../src/engine/snapshot.js');
const cc = await import('../src/engine/ctf-client.js');

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const edPair = () => crypto.generateKeyPairSync('ed25519', {
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

// Test 1: Federation — trust comes from the caller's pinned key, never the envelope
{
  const node = edPair();
  const other = edPair();
  const payload = { indicator: '198.51.100.99', type: 'IP', severity: 'CRITICAL' };
  const envelope = signThreatRecord(payload, node.privateKey, { nodeId: 'node-a', publicKey: node.publicKey });

  assert.strictEqual(verifyThreatRecord(envelope, node.publicKey).valid, true, 'Pinned signer key verifies');
  assert.strictEqual(verifyThreatRecord(envelope).valid, false, 'No key supplied must fail closed');
  assert.strictEqual(verifyThreatRecord(envelope, other.publicKey).valid, false, 'Wrong key must not verify');

  // Signer identity and timestamp are signed: relabeling invalidates
  const relabeled = { ...envelope, signerNodeId: 'node-b', timestamp: '1970-01-01T00:00:00Z' };
  assert.strictEqual(verifyThreatRecord(relabeled, node.publicKey).valid, false, 'Relabeled signer/timestamp must not verify');

  // Canonicalization: key order does not affect verification
  const reordered = { ...envelope, payload: { severity: 'CRITICAL', type: 'IP', indicator: '198.51.100.99' } };
  assert.strictEqual(verifyThreatRecord(reordered, node.publicKey).valid, true, 'Key-reordered payload must still verify');
  assert.strictEqual(canonicalJson({ b: 1, a: { d: 4, c: 3 } }), '{"a":{"c":3,"d":4},"b":1}');
}
console.log('✔ Test 1 passed: Federation verification requires a pinned key and covers identity + timestamp canonically.');

// Test 2: Cosign — digest and cryptographic check are mandatory
{
  const digest = 'sha256:4f5a89b7829d67bc11eef453982';
  const claimFor = (d) => Buffer.from(JSON.stringify({
    critical: { identity: { 'docker-reference': 'registry.example/app' }, image: d ? { 'docker-manifest-digest': d } : {}, type: 'cosign container image signature' },
    optional: {}
  })).toString('base64');

  const noDigest = verifyCosignSignature(digest, { payload: claimFor(null), signature: 'AAAAgarbage' });
  assert.strictEqual(noDigest.verified, false, 'Claim without a manifest digest must not verify');

  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  const payload = claimFor(digest);
  const signer = crypto.createSign('SHA256');
  signer.update(payload);
  signer.end();
  const signature = signer.sign(privateKey, 'base64');

  assert.strictEqual(verifyCosignSignature(digest, { payload, signature }).verified, false, 'Missing public key must fail closed');
  assert.strictEqual(verifyCosignSignature(digest, { payload, signature }, publicKey).verified, true, 'Valid signature + key + digest verifies');
  assert.strictEqual(verifyCosignSignature('sha256:different', { payload, signature }, publicKey).verified, false, 'Digest mismatch rejected');
  assert.strictEqual(verifyCosignSignature(digest, { payload, signature: 'AAAAgarbage' }, publicKey).verified, false, 'Garbage signature rejected');
}
console.log('✔ Test 2 passed: Cosign verification fails closed on missing digest, missing key, and bad signatures.');

// Test 3: Ledger — no shipped default secret
{
  const dir = path.join(tmpRoot, 'ledger');
  await assert.rejects(
    () => ledger.appendLedgerEntry('INCIDENT', { id: 1 }, {}, { ledgerDir: dir }),
    /Ledger signing secret is not configured/
  );

  process.env.VIGILANTE_LEDGER_SECRET = 'suite-ledger-secret';
  await ledger.appendLedgerEntry('INCIDENT', { id: 1, note: 'first' }, {}, { ledgerDir: dir });
  await ledger.appendLedgerEntry('VERDICT', { id: 2, note: 'second' }, {}, { ledgerDir: dir });
  const ok = await ledger.verifyLedgerIntegrity(dir);
  assert.strictEqual(ok.valid, true, 'Ledger signed with the configured secret verifies');

  // Tampering with a stored payload breaks the chain
  const file = path.join(dir, 'ledger.jsonl');
  const lines = (await fs.readFile(file, 'utf8')).trim().split('\n');
  const entry = JSON.parse(lines[0]);
  entry.payload = { id: 1, note: 'altered' };
  lines[0] = JSON.stringify(entry);
  await fs.writeFile(file, lines.join('\n') + '\n');
  const tampered = await ledger.verifyLedgerIntegrity(dir);
  assert.strictEqual(tampered.valid, false, 'Tampered entry must fail verification');

  // Without the configured secret, verification cannot pass
  delete process.env.VIGILANTE_LEDGER_SECRET;
  const unconfigured = await ledger.verifyLedgerIntegrity(dir);
  assert.strictEqual(unconfigured.valid, false, 'Verification without the configured secret must fail closed');
}
console.log('✔ Test 3 passed: Ledger refuses unconfigured signing and detects tampering.');

// Test 4: Evidence pack — the TSA token signature is verified; duplicates are rejected
{
  const hash = sha256('payload');
  assert.throws(() => ep.generateRfc3161Timestamp(hash), /RFC 3161 TSA key is not configured/);

  process.env.VIGILANTE_TSA_KEY = 'suite-tsa-key';
  const outDir = path.join(tmpRoot, 'bundles');
  const bundle = await ep.createEvidenceBundle({ caseNumber: 'CASE-SUITE-1' },
    [{ filename: 'notes.txt', content: 'genuine' }], { outputDir: outDir });
  const pristine = await ep.verifyEvidenceBundle(bundle.bundleDir);
  assert.strictEqual(pristine.valid, true, `Pristine bundle verifies: ${JSON.stringify(pristine.failures)}`);

  // Rewrite the evidence AND the manifest hashes/imprint to match; the stale
  // token signature is what must catch it now
  const manifest = JSON.parse(await fs.readFile(bundle.manifestPath, 'utf8'));
  await fs.writeFile(path.join(bundle.bundleDir, 'notes.txt'), 'forged');
  manifest.evidenceItems[0].sha256 = sha256('forged');
  manifest.rfc3161Token.tstInfo.messageImprint.hashedMessage =
    sha256(manifest.evidenceItems.map(i => i.sha256).sort().join(''));
  await fs.writeFile(bundle.manifestPath, JSON.stringify(manifest, null, 2));
  const forged = await ep.verifyEvidenceBundle(bundle.bundleDir);
  assert.strictEqual(forged.valid, false, 'Re-written bundle must fail token signature verification');
  assert.ok(forged.failures.some(f => f.includes('signature')), 'Failure should name the token signature');

  await assert.rejects(
    () => ep.createEvidenceBundle({ caseNumber: 'CASE-SUITE-2' },
      [{ filename: 'a.txt', content: '1' }, { filename: 'sub/a.txt', content: '2' }], { outputDir: outDir }),
    /Duplicate evidence filename/
  );
  delete process.env.VIGILANTE_TSA_KEY;
}
console.log('✔ Test 4 passed: Evidence bundles verify the token signature and reject duplicate filenames.');

// Test 5: Snapshot — the seal is keyed and covers identity
{
  const outDir = path.join(tmpRoot, 'snapshots');
  await assert.rejects(
    () => snap.createForensicsSnapshot({ podName: 'web-pod', containerId: 'cid123456', pid: 999999 }, { outputDir: outDir }),
    /Snapshot sealing key is not configured/
  );

  process.env.VIGILANTE_SNAPSHOT_KEY = 'suite-snapshot-key';
  const created = await snap.createForensicsSnapshot({ podName: 'web-pod', containerId: 'cid123456', pid: 999999 }, { outputDir: outDir });
  assert.ok(created.manifest.sealSignature, 'Manifest carries a seal signature');
  const pristine = await snap.verifySnapshotIntegrity(created.snapshotDir);
  assert.strictEqual(pristine.valid, true, 'Pristine snapshot verifies');

  // Identity tampering alone invalidates the seal
  const manifest = JSON.parse(await fs.readFile(created.manifestPath, 'utf8'));
  manifest.podName = 'other-pod';
  await fs.writeFile(created.manifestPath, JSON.stringify(manifest, null, 2));
  const relabeled = await snap.verifySnapshotIntegrity(created.snapshotDir);
  assert.strictEqual(relabeled.valid, false, 'Identity tampering must fail seal verification');

  // Verification without the key fails closed
  delete process.env.VIGILANTE_SNAPSHOT_KEY;
  const unconfigured = await snap.verifySnapshotIntegrity(created.snapshotDir);
  assert.strictEqual(unconfigured.valid, false, 'Verification without the sealing key must fail closed');
}
console.log('✔ Test 5 passed: Snapshot seals are keyed, cover identity, and fail closed without the key.');

// Test 6: ctf-client — seals really anchor in the ledger; local submit does not fabricate success
{
  process.env.VIGILANTE_LEDGER_SECRET = 'suite-ledger-secret';
  const vaultDir = path.join(tmpRoot, 'vault');
  const sealLedgerDir = path.join(tmpRoot, 'seal-ledger');
  const seal = await cc.sealSolveEvidence({
    teamId: 'team_01', challengeId: 'web-sqli', flag: 'VIGILANTE{x}',
    solveScriptContent: 'print(1)', writeupContent: 'wp', sessionCastContent: '{}',
    outputDir: vaultDir, ledgerDir: sealLedgerDir
  });
  assert.strictEqual(seal.ledgerAnchored, true, 'Seal is anchored in the ledger');
  assert.ok(seal.merkleRoot, 'Seal carries the real Merkle root');
  assert.ok(seal.merkleEntryHash && seal.merkleEntryHash.length === 64, 'Seal carries the ledger entry hash');
  const entries = await ledger.getLedgerEntries(sealLedgerDir);
  assert.strictEqual(entries.length, 1);
  assert.strictEqual(entries[0].entryType, 'CTF_SOLVE_EVIDENCE');
  assert.strictEqual(entries[0].entryHash, seal.merkleEntryHash);

  const local = await cc.submitLocalFlag({ challengeId: 'web-sqli', flag: 'VIGILANTE{whatever}' });
  assert.strictEqual(local.success, false, 'Unvalidated local submission must not report success');
  delete process.env.VIGILANTE_LEDGER_SECRET;
}
console.log('✔ Test 6 passed: Solve-evidence seals anchor in the ledger; unvalidated submissions report failure.');

console.log('\n🎉 All fail-closed cryptography tests passed successfully!\n');
