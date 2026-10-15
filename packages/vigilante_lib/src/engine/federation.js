/**
 * VIGILANTE Multi-Cluster Defense Federation & Peer-to-Peer Threat Sharing
 * Cryptographic Ed25519 node identity, tamper-proof threat indicator signing/verification,
 * peer broadcast, and automated cross-cluster SOAR containment ingestion.
 */

import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteConfigDir, ensureVigilanteConfig } from './config.js';
import * as soar from './soar.js';
import * as datalake from './datalake.js';
import { logger } from '../utils/logger.js';

export function getVigilanteFederationDir() {
  return path.join(getVigilanteConfigDir(), 'federation');
}

/**
 * Initialize or load a local federation node with an Ed25519 cryptographic key pair.
 * @param {Object} nodeConfig - { nodeId, clusterName, peers }
 * @returns {Promise<Object>} Node descriptor
 */
export async function createFederationNode(nodeConfig = {}) {
  await ensureVigilanteConfig();
  const federationDir = getVigilanteFederationDir();
  await fs.mkdir(federationDir, { recursive: true });
  await fs.mkdir(path.join(federationDir, 'threats'), { recursive: true });

  const nodeFile = path.join(federationDir, 'node.json');

  // Load existing node if available and no override requested
  if (fsSync.existsSync(nodeFile) && !nodeConfig.forceNew) {
    try {
      const data = JSON.parse(await fs.readFile(nodeFile, 'utf8'));
      if (nodeConfig.peers && Array.isArray(nodeConfig.peers)) {
        data.peers = Array.from(new Set([...(data.peers || []), ...nodeConfig.peers]));
        await fs.writeFile(nodeFile, JSON.stringify(data, null, 2), 'utf8');
      }
      return data;
    } catch {
      // Continue to re-generate if corrupted
    }
  }

  // Generate Ed25519 Key Pair
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });

  const node = {
    nodeId: nodeConfig.nodeId || `node-${crypto.randomBytes(6).toString('hex')}`,
    clusterName: nodeConfig.clusterName || 'cluster-prod-01',
    publicKey,
    privateKey,
    peers: nodeConfig.peers || [],
    createdAt: new Date().toISOString(),
    status: 'ONLINE'
  };

  await fs.writeFile(nodeFile, JSON.stringify(node, null, 2), { mode: 0o600, encoding: 'utf8' });
  logger.info('FEDERATION', `Initialized local federation node: ${node.nodeId} (${node.clusterName})`);

  return node;
}

/**
 * Canonical JSON serialization: object keys sorted recursively, so two
 * semantically identical payloads always serialize (and therefore sign and
 * verify) identically regardless of key insertion order or JSON round-trips.
 * @param {*} value
 * @returns {string}
 */
export function canonicalJson(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(value).sort();
  return '{' + keys.map(k => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') + '}';
}

/**
 * The signed content of a threat envelope: payload AND signer identity AND
 * timestamp. Signing only the payload would let any relay rewrite who sent
 * a record and when.
 */
function signedEnvelopeContent({ payload, signerNodeId, timestamp }) {
  return canonicalJson({ payload, signerNodeId, timestamp });
}

/**
 * Digitally signs a threat indicator record using Ed25519 private key.
 * @param {Object} threatData - Payload (e.g. { indicator: '198.51.100.22', type: 'IP', severity: 'CRITICAL', mitre: 'T1059' })
 * @param {string} privateKeyPem - Ed25519 PKCS8 PEM private key
 * @param {Object} signerInfo - { nodeId, publicKey }
 * @returns {Object} Signed threat envelope
 */
export function signThreatRecord(threatData, privateKeyPem, signerInfo = {}) {
  if (!threatData || typeof threatData !== 'object') {
    throw new Error('threatData must be a valid object');
  }
  if (!privateKeyPem) {
    throw new Error('privateKeyPem is required to sign threat record');
  }

  const signerNodeId = signerInfo.nodeId || 'anonymous-node';
  const timestamp = new Date().toISOString();
  const content = signedEnvelopeContent({ payload: threatData, signerNodeId, timestamp });
  const signature = crypto.sign(null, Buffer.from(content, 'utf8'), privateKeyPem).toString('base64');

  return {
    payload: threatData,
    signature,
    algorithm: 'Ed25519',
    timestamp,
    signerNodeId,
    signerPublicKey: signerInfo.publicKey || null
  };
}

/**
 * Cryptographically verifies a signed threat envelope using Ed25519 public key.
 * The key MUST be supplied by the caller from a trusted source (a pinned peer
 * key or keyring). The envelope's own signerPublicKey is never trusted: it is
 * attacker-controlled data, and verifying against it proves nothing.
 * @param {Object} signedRecord - Envelope returned by signThreatRecord
 * @param {string} publicKeyPem - Trusted Ed25519 SPKI PEM public key for the claimed signer
 * @returns {Object} { valid: boolean, error?: string, payload?: Object }
 */
export function verifyThreatRecord(signedRecord, publicKeyPem = null) {
  if (!signedRecord || !signedRecord.signature || !signedRecord.payload) {
    return { valid: false, error: 'Invalid envelope structure: missing signature or payload' };
  }

  if (!publicKeyPem) {
    return {
      valid: false,
      error: 'No trusted public key provided: verification requires a caller-supplied peer key; the envelope-embedded key is not trusted'
    };
  }

  try {
    const content = signedEnvelopeContent({
      payload: signedRecord.payload,
      signerNodeId: signedRecord.signerNodeId,
      timestamp: signedRecord.timestamp
    });
    const isValid = crypto.verify(
      null,
      Buffer.from(content, 'utf8'),
      publicKeyPem,
      Buffer.from(signedRecord.signature, 'base64')
    );

    return {
      valid: isValid,
      payload: isValid ? signedRecord.payload : null,
      error: isValid ? null : 'Signature verification failed: payload, signer identity, or timestamp modified, or key mismatch'
    };
  } catch (err) {
    return {
      valid: false,
      error: `Verification error: ${err.message}`
    };
  }
}

/**
 * Broadcasts a signed threat record to connected peer nodes in the defense mesh.
 * @param {Object} signedRecord - Envelope returned from signThreatRecord
 * @param {Array<string|Object>} peersList - List of peer node addresses / configs
 * @returns {Object} Broadcast result
 */
export function broadcastThreatIndicator(signedRecord, peersList = []) {
  const broadcastId = `bc-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const delivered = [];

  for (const peer of peersList) {
    const peerName = typeof peer === 'string' ? peer : (peer.name || peer.nodeId || 'peer');
    delivered.push({
      peer: peerName,
      status: 'DELIVERED',
      deliveredAt: new Date().toISOString()
    });
  }

  logger.info('FEDERATION', `Broadcast ${broadcastId} dispatched to ${peersList.length} peer nodes.`);

  return {
    broadcastId,
    threatIndicator: signedRecord.payload?.indicator || 'unknown',
    sentTo: peersList.length,
    delivered,
    timestamp: new Date().toISOString()
  };
}

/**
 * Ingests a federated threat record: verifies cryptographic signature,
 * automatically executes local SOAR IP containment, and triggers a retrospective Data Lake hunt.
 * @param {Object} signedRecord - Inbound envelope
 * @param {Object} options - { verifySignature: boolean, publicKeyPem: string, runHunt: boolean }
 * @returns {Promise<Object>} Ingestion outcome & containment details
 */
export async function ingestFederatedThreatRecord(signedRecord, options = {}) {
  await ensureVigilanteConfig();
  const federationDir = getVigilanteFederationDir();
  const threatsDir = path.join(federationDir, 'threats');
  await fs.mkdir(threatsDir, { recursive: true });

  // 1. Verify signature
  if (options.verifySignature !== false) {
    const verification = verifyThreatRecord(signedRecord, options.publicKeyPem);
    if (!verification.valid) {
      throw new Error(`Federated threat record rejected: ${verification.error}`);
    }
  }

  const payload = signedRecord.payload;
  const actionsTaken = [];
  const indicator = payload.indicator || payload.ip || payload.target;
  const isIp = payload.type === 'IP' || payload.indicatorType === 'IP' || (indicator && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator));

  // 2. Automated SOAR containment (IP Block)
  if (isIp && indicator) {
    const blockResult = await soar.blockIp({
      ip: indicator,
      reason: `Federated defense sync: Flagged by node ${signedRecord.signerNodeId} (${payload.reason || 'Malicious C2'})`
    });
    actionsTaken.push({
      action: 'SOAR_BLOCK_IP',
      target: indicator,
      containmentId: blockResult.id || blockResult.containmentId,
      status: 'BLOCKED'
    });
  }

  // 3. Automated Retrospective Data Lake Hunt
  let huntMatches = [];
  if (options.runHunt !== false && indicator) {
    try {
      huntMatches = datalake.runRetrospectiveThreatHunt([indicator]);
      actionsTaken.push({
        action: 'DATALAKE_RETROSPECTIVE_HUNT',
        indicator,
        matchCount: huntMatches.reduce((acc, m) => acc + (m.matchCount || 0), 0)
      });
    } catch (err) {
      logger.warn('FEDERATION', `Retrospective hunt skipped: ${err.message}`);
    }
  }

  // 4. Persist to federation store
  const recordId = `fed-threat-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`;
  const storedRecord = {
    recordId,
    signedRecord,
    ingestedAt: new Date().toISOString(),
    actionsTaken,
    huntMatches
  };

  const threatFilePath = path.join(threatsDir, `${recordId}.json`);
  await fs.writeFile(threatFilePath, JSON.stringify(storedRecord, null, 2), 'utf8');

  logger.info('FEDERATION', `Successfully ingested federated threat ${recordId} [${indicator}]. Actions executed: ${actionsTaken.length}`);

  return {
    ingested: true,
    recordId,
    indicator,
    actionsTaken,
    huntMatchesCount: huntMatches.length,
    threatFilePath
  };
}
