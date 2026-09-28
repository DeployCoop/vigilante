import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  initAuditLedger,
  appendLedgerEntry,
  getLedgerEntries,
  buildMerkleRoot,
  generateInclusionProof,
  verifyInclusionProof,
  verifyLedgerIntegrity,
  exportLegalChainOfCustody,
  GENESIS_PREV_HASH
} from '../src/engine/ledger.js';

async function runTests() {
  console.log('🧪 Testing Cryptographic Merkle Ledger & Legal Chain-of-Custody...');

  const tempDir = path.join(os.tmpdir(), `vigilante-ledger-test-${Date.now()}`);

  try {
    // Test 1: Initialize Ledger
    const meta = await initAuditLedger(tempDir);
    assert.strictEqual(meta.entryCount, 0);
    assert.strictEqual(meta.lastHash, GENESIS_PREV_HASH);
    console.log('✔ Test 1 passed: initAuditLedger initialized directory and genesis metadata.');

    // Test 2: Append Entries & Validate Hash Chaining
    const entry1 = await appendLedgerEntry('INCIDENT_TRIGGER', {
      incidentId: 'IR-2026-001',
      rule: 'Terminal shell in container',
      pod: 'payment-svc-11a'
    }, { role: 'FalcoSensor', id: 'sensor:ebpf-01' }, { ledgerDir: tempDir });

    assert.strictEqual(entry1.index, 0);
    assert.strictEqual(entry1.prevHash, GENESIS_PREV_HASH);
    assert.ok(entry1.entryHash.length === 64, 'Entry hash must be 64-char SHA256 hex');
    assert.ok(entry1.signature.length === 64, 'Signature must be HMAC hex');

    const entry2 = await appendLedgerEntry('SOAR_CONTAINMENT', {
      incidentId: 'IR-2026-001',
      action: 'isolatePod',
      target: 'payment-svc-11a'
    }, { role: 'IncidentCommander', id: 'agent:commander-ai' }, { ledgerDir: tempDir });

    assert.strictEqual(entry2.index, 1);
    assert.strictEqual(entry2.prevHash, entry1.entryHash, 'entry2.prevHash must equal entry1.entryHash');

    const entry3 = await appendLedgerEntry('EVIDENCE_MEMDUMP', {
      incidentId: 'IR-2026-001',
      memorySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    }, { role: 'ForensicsSpecialist', id: 'agent:forensics-ai' }, { ledgerDir: tempDir });

    assert.strictEqual(entry3.index, 2);
    assert.strictEqual(entry3.prevHash, entry2.entryHash);

    const entry4 = await appendLedgerEntry('WAR_ROOM_VERDICT', {
      incidentId: 'IR-2026-001',
      verdict: 'TRUE_POSITIVE_MALWARE',
      consensusScore: 92
    }, { role: 'ConsensusBoard', id: 'agent:consortium' }, { ledgerDir: tempDir });

    assert.strictEqual(entry4.index, 3);
    assert.strictEqual(entry4.prevHash, entry3.entryHash);

    const allEntries = await getLedgerEntries(tempDir);
    assert.strictEqual(allEntries.length, 4);
    console.log('✔ Test 2 passed: appendLedgerEntry strictly chained SHA-256 hashes across 4 sequential entries.');

    // Test 3: Merkle Tree Construction (Even and Odd leaves)
    const { root: root4, leafCount: leafCount4 } = buildMerkleRoot(allEntries);
    assert.strictEqual(leafCount4, 4);
    assert.ok(root4 && root4.length === 64, 'Merkle root must be valid SHA256 hex');

    // Test odd leaves (first 3 entries)
    const { root: root3, leafCount: leafCount3 } = buildMerkleRoot(allEntries.slice(0, 3));
    assert.strictEqual(leafCount3, 3);
    assert.ok(root3 && root3.length === 64, 'Merkle root for odd leaves must compute');
    console.log(`✔ Test 3 passed: buildMerkleRoot computed Merkle root for even and odd leaf counts (Root: ${root4.slice(0, 16)}...).`);

    // Test 4: Merkle Inclusion Proof Generation & Verification
    for (let i = 0; i < allEntries.length; i++) {
      const proofObj = generateInclusionProof(i, allEntries);
      assert.strictEqual(proofObj.entryIndex, i);
      assert.strictEqual(proofObj.root, root4);
      assert.ok(Array.isArray(proofObj.proof));

      const isValid = verifyInclusionProof(proofObj.entryHash, proofObj.proof, root4);
      assert.strictEqual(isValid, true, `Inclusion proof for entry ${i} must verify against root`);
    }

    // Negative verification test
    const fakeHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
    const proof0 = generateInclusionProof(0, allEntries);
    assert.strictEqual(verifyInclusionProof(fakeHash, proof0.proof, root4), false, 'Tampered hash must fail inclusion verification');
    console.log('✔ Test 4 passed: Merkle inclusion proofs verified authentic membership and rejected forged hashes.');

    // Test 5: Whole Ledger Integrity Verification
    const integrityResult = await verifyLedgerIntegrity(tempDir);
    assert.strictEqual(integrityResult.valid, true);
    assert.strictEqual(integrityResult.count, 4);
    assert.strictEqual(integrityResult.merkleRoot, root4);
    console.log('✔ Test 5 passed: verifyLedgerIntegrity verified pristine hash chain, content hashes, and signatures.');

    // Test 6: Tamper Detection
    const ledgerFile = path.join(tempDir, 'ledger.jsonl');
    const rawContent = await fs.readFile(ledgerFile, 'utf8');
    const lines = rawContent.trim().split('\n');

    // Tamper with second entry payload
    const tamperedEntry = JSON.parse(lines[1]);
    tamperedEntry.payload.action = 'unauthorizedBypass';
    lines[1] = JSON.stringify(tamperedEntry);
    await fs.writeFile(ledgerFile, lines.join('\n') + '\n', 'utf8');

    const tamperedResult = await verifyLedgerIntegrity(tempDir);
    assert.strictEqual(tamperedResult.valid, false, 'Tampered ledger must fail integrity check');
    assert.strictEqual(tamperedResult.corruptedIndex, 1, 'Corrupted index must point to altered entry');
    console.log(`✔ Test 6 passed: Tamper detection identified modified entry: "${tamperedResult.issue}".`);

    // Restore pristine content for affidavit test
    lines[1] = JSON.stringify(allEntries[1]);
    await fs.writeFile(ledgerFile, lines.join('\n') + '\n', 'utf8');

    // Test 7: Legal Chain of Custody Report Generation
    const affidavit = await exportLegalChainOfCustody('IR-2026-001', tempDir);
    assert.strictEqual(affidavit.incidentId, 'IR-2026-001');
    assert.ok(affidavit.markdown.includes('LEGAL CHAIN-OF-CUSTODY AUDIT AFFIDAVIT'));
    assert.ok(affidavit.markdown.includes(root4));
    assert.strictEqual(affidavit.entries.length, 4);
    console.log('✔ Test 7 passed: exportLegalChainOfCustody generated court-admissible legal affidavit.');

    console.log('🎉 ALL 7 CRYPTOGRAPHIC MERKLE LEDGER TESTS PASSED SUCCESSFULLY!\n');
  } finally {
    await fs.rm(tempDir, { recursive: true, force: true }).catch(() => {});
  }
}

runTests().catch(err => {
  console.error('❌ Merkle Ledger test failed:', err);
  process.exit(1);
});
