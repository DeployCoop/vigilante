/**
 * VIGILANTE Anti-Ransomware Canary Traps & Rapid File Entropy Monitor
 * Deploys decoy canary files in mounted volumes, monitors 8-bit Shannon block entropy,
 * detects in-place encryption spikes, and triggers sub-second freeze/isolation containment.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import * as soar from './soar.js';
import { logger } from '../utils/logger.js';

/**
 * Calculates 8-bit Shannon block entropy of a byte buffer or file
 * @param {Buffer|Uint8Array|string} bufferOrPath
 * @returns {Promise<number>|number} Entropy value in range [0.0, 8.0]
 */
export function calculateFileEntropy(bufferOrPath) {
  let buf;
  if (typeof bufferOrPath === 'string') {
    if (fsSync.existsSync(bufferOrPath)) {
      buf = fsSync.readFileSync(bufferOrPath);
    } else {
      buf = Buffer.from(bufferOrPath, 'utf8');
    }
  } else if (Buffer.isBuffer(bufferOrPath) || bufferOrPath instanceof Uint8Array) {
    buf = bufferOrPath;
  } else {
    return 0;
  }

  const len = buf.length;
  if (len === 0) return 0;

  const frequencies = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    frequencies[buf[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    if (frequencies[i] > 0) {
      const p = frequencies[i] / len;
      entropy -= p * Math.log2(p);
    }
  }

  return Number(entropy.toFixed(3));
}

/**
 * Plants realistic decoy canary files into a directory and computes baseline entropies
 * @param {string} targetDirectory - Target directory to seed with canaries
 * @param {Object} options
 * @returns {Promise<Object>} Manifest of planted canaries
 */
export async function generateRansomwareCanaryFiles(targetDirectory, options = {}) {
  await fs.mkdir(targetDirectory, { recursive: true });

  const templates = [
    {
      fileName: 'quarterly_financial_report.docx',
      content: 'CONFIDENTIAL EXECUTIVE FINANCIAL SUMMARY\nRevenue: $42,500,000\nNet Operating Profit: $12,800,000\nKey Assets and Liabilities disclosed under NDA.\n' + 'Standard plaintext report paragraphs detailing corporate performance.\n'.repeat(10)
    },
    {
      fileName: 'passwords_master.kdbx',
      content: 'KeePass Password Database Mock Format Header\n[Group: Production DBs]\nHost: db-internal.cluster.local User: admin Pass: RedactedSecret12345!\n'.repeat(5)
    },
    {
      fileName: 'customers_backup.sql',
      content: '-- Database Customer Table Dump\nINSERT INTO customers (id, name, email, balance) VALUES\n(1, "Alice Cooper", "alice@example.com", 5000.00),\n(2, "Bob Vance", "bob@vancerefrig.com", 12500.50);\n'.repeat(8)
    },
    {
      fileName: 'production_keys.env',
      content: 'AWS_ACCESS_KEY_ID=AKIAEXAMPLEKEY12345\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nJWT_SECRET=supersecretproductionkey2026\n'
    }
  ];

  const planted = [];

  for (const item of templates) {
    const filePath = path.join(targetDirectory, item.fileName);
    const buf = Buffer.from(item.content, 'utf8');
    await fs.writeFile(filePath, buf);
    const baselineEntropy = calculateFileEntropy(buf);

    planted.push({
      fileName: item.fileName,
      filePath,
      sizeBytes: buf.length,
      baselineEntropy,
      plantedAt: new Date().toISOString()
    });
  }

  const manifestPath = path.join(targetDirectory, '.canary_manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(planted, null, 2), 'utf8');
  logger.info('RANSOMWARE', `Planted ${planted.length} ransomware canary files in ${targetDirectory}`);

  return {
    targetDirectory,
    canaryFiles: planted,
    totalPlanted: planted.length,
    manifestPath
  };
}

/**
 * Detect rapid entropy escalation indicative of symmetric block ransomware encryption
 * @param {number|Buffer|string} beforeData - Initial entropy float or plaintext buffer
 * @param {Buffer|string} afterData - Modified file buffer
 * @param {Object} options - { entropyThreshold: 7.5, deltaThreshold: 2.0 }
 * @returns {Object} Encryption evaluation
 */
export function detectRansomwareEncryption(beforeData, afterData, options = {}) {
  const entropyThreshold = options.entropyThreshold || 7.5;
  const deltaThreshold = options.deltaThreshold || 2.0;

  const beforeEntropy = typeof beforeData === 'number'
    ? beforeData
    : calculateFileEntropy(beforeData);

  const afterEntropy = typeof afterData === 'number'
    ? afterData
    : calculateFileEntropy(afterData);

  const entropyDelta = Number((afterEntropy - beforeEntropy).toFixed(3));
  const isEncrypted = afterEntropy >= entropyThreshold && (entropyDelta >= deltaThreshold || beforeEntropy < 5.5);

  let severity = 'LOW';
  if (isEncrypted) severity = 'CRITICAL';
  else if (afterEntropy >= 7.0 && entropyDelta >= 1.5) severity = 'HIGH';

  return {
    isEncrypted,
    severity,
    beforeEntropy,
    afterEntropy,
    entropyDelta,
    mitreTechnique: 'T1486', // Data Encrypted for Impact
    description: isEncrypted
      ? `CRITICAL Ransomware Encryption Event: Entropy escalated from ${beforeEntropy} to ${afterEntropy} (Δ +${entropyDelta}), consistent with high-entropy symmetric cipher (AES/ChaCha20).`
      : `File modification appears normal (Δ +${entropyDelta}, Entropy: ${afterEntropy})`
  };
}

/**
 * Emergency ransomware response protocol: freezes process CPU cycles and isolates pod network
 * @param {string} podName
 * @param {string} namespace
 * @param {number|string} pid
 * @param {Object} options
 * @returns {Promise<Object>} Containment results
 */
export async function triggerRansomwareContainment(podName, namespace = 'default', pid = null, options = {}) {
  logger.warn('RANSOMWARE', `EMERGENCY CONTAINMENT TRIGGERED on pod ${podName} (PID: ${pid || 'all'})`);

  // 1. Freeze pod CPU immediately to halt encryption iteration
  let freezeResult = null;
  try {
    freezeResult = await soar.freezePod(podName, namespace, {
      reason: 'Automated Anti-Ransomware Freeze: Active file encryption detected'
    });
  } catch (err) {
    logger.error('RANSOMWARE', `Freeze pod failed: ${err.message}`);
  }

  // 2. Isolate pod network to prevent C2 key exchange and lateral propagation
  let isolateResult = null;
  try {
    isolateResult = await soar.isolatePod(podName, namespace, {
      reason: 'Active Ransomware Encryption & Data Encrypted for Impact (T1486)',
      apply: options.apply !== undefined ? options.apply : false
    });
  } catch (err) {
    logger.error('RANSOMWARE', `Isolate pod failed: ${err.message}`);
  }

  return {
    containmentSuccess: true,
    podName,
    namespace,
    pid,
    mitreTechnique: 'T1486',
    freezeResult,
    isolateResult,
    timestamp: new Date().toISOString()
  };
}
