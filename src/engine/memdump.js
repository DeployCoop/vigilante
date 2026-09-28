/**
 * In-Memory & Process Forensics Engine
 * Live container memory inspection, /proc/$PID/maps parser, shellcode buffer detection,
 * fileless memfd_create tracking, and deleted binary execution identification.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getVigilanteEvidenceDir } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Parse Linux /proc/$PID/maps content into structured memory segments
 * @param {string} mapsContent Content of /proc/$PID/maps
 * @returns {Array<Object>}
 */
export function parseProcMaps(mapsContent = '') {
  const lines = mapsContent.split(/\r?\n/);
  const segments = [];

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Format: 00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/nginx
    const parts = trimmed.split(/\s+/);
    if (parts.length < 5) continue;

    const [addrRange, perms, offset, dev, inode, ...pathParts] = parts;
    const [startAddr, endAddr] = addrRange.split('-');
    const pathname = pathParts.join(' ') || '[anonymous]';

    segments.push({
      startAddr,
      endAddr,
      perms,
      isRead: perms.includes('r'),
      isWrite: perms.includes('w'),
      isExec: perms.includes('x'),
      isShared: perms.includes('s'),
      isPrivate: perms.includes('p'),
      offset,
      dev,
      inode: parseInt(inode, 10) || 0,
      pathname
    });
  }

  return segments;
}

/**
 * Analyze parsed memory segments for suspicious process anomalies
 * @param {Array<Object>} segments
 * @param {Object} [options={}]
 * @returns {Array<Object>} Discovered anomalies
 */
export function detectMemoryAnomalies(segments = [], options = {}) {
  const anomalies = [];
  const segList = typeof segments === 'string' ? parseProcMaps(segments) : (Array.isArray(segments) ? segments : []);

  for (const seg of segList) {
    // 1. RWX Memory Segments (Shellcode / JIT Abuse)
    if (seg.isRead && seg.isWrite && seg.isExec) {
      anomalies.push({
        type: 'RWX_MEMORY_SEGMENT',
        severity: 'CRITICAL',
        mitreTechnique: 'T1055',
        startAddr: seg.startAddr,
        endAddr: seg.endAddr,
        pathname: seg.pathname,
        description: `Memory region has Read-Write-Execute permissions (${seg.perms}), typical of in-memory shellcode buffers.`
      });
    }

    // 2. Deleted Executable Execution (Unlinked Binary on disk)
    if (seg.isExec && seg.pathname.includes('(deleted)') && !seg.pathname.includes('memfd:')) {
      anomalies.push({
        type: 'DELETED_EXECUTABLE_RUNNING',
        severity: 'HIGH',
        mitreTechnique: 'T1070.004',
        startAddr: seg.startAddr,
        endAddr: seg.endAddr,
        pathname: seg.pathname,
        description: `Executable binary was deleted from filesystem while remaining running in memory: ${seg.pathname}`
      });
    }

    // 3. Fileless Memory Execution (memfd_create)
    if (seg.isExec && (seg.pathname.includes('memfd:') || seg.pathname.includes('/dev/shm'))) {
      anomalies.push({
        type: 'FILELESS_MEMFD_EXECUTION',
        severity: 'CRITICAL',
        mitreTechnique: 'T1620',
        startAddr: seg.startAddr,
        endAddr: seg.endAddr,
        pathname: seg.pathname,
        description: `Executable code running from in-memory file descriptor or shared memory: ${seg.pathname}`
      });
    }

    // 4. Suspicious Shared Object Injection (/tmp or /var/tmp)
    if (seg.isExec && (seg.pathname.startsWith('/tmp/') || seg.pathname.startsWith('/var/tmp/'))) {
      anomalies.push({
        type: 'SUSPICIOUS_LIBRARY_INJECTION',
        severity: 'HIGH',
        mitreTechnique: 'T1574.006',
        startAddr: seg.startAddr,
        endAddr: seg.endAddr,
        pathname: seg.pathname,
        description: `Executable library loaded from temporary directory: ${seg.pathname}`
      });
    }
  }

  logger.info('MEMDUMP', `Memory anomaly scan evaluated ${segments.length} segments, flagged ${anomalies.length} findings.`);
  return anomalies;
}

/**
 * Extract printable strings and calculate Shannon entropy from memory dump buffer
 * @param {Buffer|Uint8Array} buffer
 * @param {number} [minLength=4]
 * @returns {{ stringsCount: number, strings: Array<string>, entropy: number }}
 */
export function extractProcessStrings(buffer, minLength = 4) {
  if (!buffer) return { stringsCount: 0, strings: [], entropy: 0 };

  const buf = Buffer.isBuffer(buffer) ? buffer : Buffer.from(buffer);
  const foundStrings = [];
  let current = [];

  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    // Printable ASCII 32 - 126
    if (byte >= 32 && byte <= 126) {
      current.push(String.fromCharCode(byte));
    } else {
      if (current.length >= minLength) {
        foundStrings.push(current.join(''));
      }
      current = [];
    }
  }
  if (current.length >= minLength) {
    foundStrings.push(current.join(''));
  }

  // Calculate Shannon entropy of the buffer
  const freq = {};
  for (let i = 0; i < buf.length; i++) {
    const b = buf[i];
    freq[b] = (freq[b] || 0) + 1;
  }
  let entropy = 0;
  for (const count of Object.values(freq)) {
    const p = count / buf.length;
    entropy -= p * Math.log2(p);
  }

  return {
    stringsCount: foundStrings.length,
    strings: foundStrings.slice(0, 100),
    entropy: Number(entropy.toFixed(3))
  };
}

/**
 * Save memory triage artifacts and dump to the Evidence Vault
 * @param {string} podName
 * @param {number} pid
 * @param {Object} metadata
 * @param {Buffer} [dumpBuffer]
 * @returns {Promise<string>} Path to saved artifact record
 */
export async function saveMemoryArtifact(podName, pid, metadata = {}, dumpBuffer = null) {
  const baseEvidenceDir = getVigilanteEvidenceDir();
  const memDir = path.join(baseEvidenceDir, 'memdumps', podName);

  if (!fsSync.existsSync(memDir)) {
    await fs.mkdir(memDir, { recursive: true });
  }

  const timestamp = Date.now();
  const artifactId = `mem-${podName}-pid${pid}-${timestamp}`;

  let dumpFile = null;
  let sha256 = null;

  if (dumpBuffer) {
    dumpFile = path.join(memDir, `${artifactId}.raw`);
    await fs.writeFile(dumpFile, dumpBuffer);
    sha256 = crypto.createHash('sha256').update(dumpBuffer).digest('hex');
  }

  const record = {
    artifactId,
    podName,
    pid,
    sha256,
    dumpFile,
    anomalies: metadata.anomalies || [],
    segmentCount: metadata.segments ? metadata.segments.length : 0,
    timestamp: new Date().toISOString()
  };

  const metadataPath = path.join(memDir, `${artifactId}.json`);
  await fs.writeFile(metadataPath, JSON.stringify(record, null, 2), 'utf8');

  logger.info('MEMDUMP', `Saved memory artifact record to ${metadataPath}`);
  return metadataPath;
}

export {
  parseProcMaps as parseProcessMemoryMaps,
  extractProcessStrings as extractStringsAndEntropy,
  saveMemoryArtifact as saveProcessDumpArtifact
};
