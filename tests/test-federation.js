import assert from 'node:assert';
import fs from 'node:fs/promises';
import {
  createFederationNode,
  signThreatRecord,
  verifyThreatRecord,
  broadcastThreatIndicator,
  ingestFederatedThreatRecord
} from '../src/engine/federation.js';
import * as soar from '../src/engine/soar.js';

console.log('🧪 Testing Multi-Cluster Defense Federation & Threat Sharing Engine...');

// Test 1: createFederationNode
const node = await createFederationNode({
  clusterName: 'cluster-us-east',
  peers: ['cluster-eu-west', 'cluster-ap-south'],
  forceNew: true
});

assert.ok(node.nodeId, 'Node must have an ID');
assert.strictEqual(node.clusterName, 'cluster-us-east');
assert.ok(node.publicKey.includes('BEGIN PUBLIC KEY'), 'Public key must be PEM formatted');
assert.ok(node.privateKey.includes('BEGIN PRIVATE KEY'), 'Private key must be PEM formatted');
assert.strictEqual(node.peers.length, 2);
console.log('✔ Test 1 passed: createFederationNode generated Ed25519 identity and initialized peer list.');

// Test 2: signThreatRecord & verifyThreatRecord
const threatPayload = {
  indicator: '198.51.100.99',
  type: 'IP',
  severity: 'CRITICAL',
  mitre: 'T1059.004',
  reason: 'Automated brute-force SSH attack detected on worker node'
};

const envelope = signThreatRecord(threatPayload, node.privateKey, {
  nodeId: node.nodeId,
  publicKey: node.publicKey
});

assert.ok(envelope.signature, 'Signature must be generated');
assert.strictEqual(envelope.algorithm, 'Ed25519');
assert.strictEqual(envelope.signerNodeId, node.nodeId);

// Valid signature verification
const verifyResult = verifyThreatRecord(envelope);
assert.strictEqual(verifyResult.valid, true);
assert.strictEqual(verifyResult.payload.indicator, '198.51.100.99');

// Tampered payload verification
const tamperedEnvelope = {
  ...envelope,
  payload: { ...threatPayload, indicator: '203.0.113.1' }
};
const tamperedResult = verifyThreatRecord(tamperedEnvelope);
assert.strictEqual(tamperedResult.valid, false, 'Tampered payload should fail verification');
console.log('✔ Test 2 passed: signThreatRecord and verifyThreatRecord cryptographically validate authentic envelopes and reject tampered payloads.');

// Test 3: broadcastThreatIndicator
const broadcast = broadcastThreatIndicator(envelope, ['cluster-eu-west', 'cluster-ap-south']);
assert.ok(broadcast.broadcastId.startsWith('bc-'));
assert.strictEqual(broadcast.sentTo, 2);
assert.strictEqual(broadcast.delivered.length, 2);
assert.strictEqual(broadcast.delivered[0].status, 'DELIVERED');
console.log('✔ Test 3 passed: broadcastThreatIndicator dispatched indicator to peer mesh nodes.');

// Test 4: ingestFederatedThreatRecord
const ingestResult = await ingestFederatedThreatRecord(envelope, {
  verifySignature: true,
  runHunt: true
});

assert.strictEqual(ingestResult.ingested, true);
assert.ok(ingestResult.recordId);
assert.strictEqual(ingestResult.indicator, '198.51.100.99');
assert.ok(ingestResult.actionsTaken.some(a => a.action === 'SOAR_BLOCK_IP'), 'Should execute SOAR IP block');
assert.ok(ingestResult.actionsTaken.some(a => a.action === 'DATALAKE_RETROSPECTIVE_HUNT'), 'Should execute Data Lake hunt');

// Verify that the IP is indeed recorded as blocked in SOAR
const activeContainments = await soar.listActiveContainments();
const blocked = activeContainments.find(c => c.target === '198.51.100.99');
assert.ok(blocked, 'Blocked IP must appear in active containments');

console.log('✔ Test 4 passed: ingestFederatedThreatRecord validated signature, executed SOAR IP block, and ran retrospective threat hunt.');

console.log('🎉 All Multi-Cluster Defense Federation tests passed successfully!\n');
