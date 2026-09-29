/**
 * VIGILANTE Live Container Memory & Ephemeral Disk Snapshot Engine
 * Captures container volatile state (/proc/$PID), overlayfs upper-layer disk diffs,
 * hashes modified/added binaries, and produces cryptographically sealed forensic snapshot archives.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { getVigilanteEvidenceDir } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Capture volatile runtime state of a containerized process
 * @param {number|string} pid Process ID
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Volatile process record
 */
export async function captureContainerVolatiles(pid, options = {}) {
  const p = Number(pid);
  const volatiles = {
    pid: p,
    timestamp: new Date().toISOString(),
    cmdline: null,
    status: {},
    openFds: [],
    networkSockets: [],
    environment: {},
    isMock: false
  };

  const procPath = `/proc/${p}`;

  if (fsSync.existsSync(procPath)) {
    try {
      // 1. Read cmdline
      if (fsSync.existsSync(path.join(procPath, 'cmdline'))) {
        const rawCmd = await fs.readFile(path.join(procPath, 'cmdline'));
        volatiles.cmdline = rawCmd.toString('utf8').replace(/\0/g, ' ').trim();
      }

      // 2. Read status
      if (fsSync.existsSync(path.join(procPath, 'status'))) {
        const rawStatus = await fs.readFile(path.join(procPath, 'status'), 'utf8');
        const lines = rawStatus.split('\n');
        for (const line of lines) {
          const [k, v] = line.split(':');
          if (k && v) volatiles.status[k.trim()] = v.trim();
        }
      }

      // 3. Read open FDs
      const fdDir = path.join(procPath, 'fd');
      if (fsSync.existsSync(fdDir)) {
        try {
          const fds = await fs.readdir(fdDir);
          for (const fd of fds.slice(0, 50)) {
            try {
              const link = await fs.readlink(path.join(fdDir, fd));
              volatiles.openFds.push({ fd: Number(fd), target: link });
            } catch {}
          }
        } catch {}
      }
    } catch (err) {
      logger.warn(`Snapshot: error reading /proc/${p}: ${err.message}`);
    }
  } else {
    // Simulated volatile state for testing or remote container inspection
    volatiles.isMock = true;
    volatiles.cmdline = options.mockCmdline || '/usr/local/bin/worker --config=/etc/prod.yaml';
    volatiles.status = { Name: 'worker', State: 'R (running)', PPid: '1', Threads: '4' };
    volatiles.openFds = [
      { fd: 0, target: '/dev/null' },
      { fd: 1, target: '/var/log/worker.log' },
      { fd: 3, target: 'socket:[44192]' }
    ];
  }

  return volatiles;
}

/**
 * Scan a container's overlayfs upper directory and compute file differential manifest
 * @param {string} rootfsDir Path to container rootfs or overlayfs upper layer
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Differential disk manifest
 */
export async function captureContainerDiff(rootfsDir, options = {}) {
  const manifest = [];
  let totalFiles = 0;
  let addedCount = 0;
  let suspiciousCount = 0;

  if (fsSync.existsSync(rootfsDir)) {
    async function traverse(currentDir, relPath = '') {
      const entries = await fs.readdir(currentDir, { withFileTypes: true });
      for (const entry of entries) {
        const fullPath = path.join(currentDir, entry.name);
        const relative = path.join(relPath, entry.name);

        if (entry.isDirectory()) {
          await traverse(fullPath, relative);
        } else if (entry.isFile()) {
          totalFiles++;
          const stat = await fs.stat(fullPath);
          const buf = await fs.readFile(fullPath);
          const sha256 = crypto.createHash('sha256').update(buf).digest('hex');

          // Whiteout file in overlayfs starts with .wh.
          const isWhiteout = entry.name.startsWith('.wh.');
          const isSuspicious = relative.startsWith('tmp') || 
                               relative.startsWith('dev/shm') || 
                               entry.name.endsWith('.sh') || 
                               entry.name.endsWith('.elf');

          if (isSuspicious) suspiciousCount++;
          addedCount++;

          manifest.push({
            path: relative,
            size: stat.size,
            sha256,
            isWhiteout,
            isSuspicious,
            modifiedAt: stat.mtime.toISOString()
          });
        }
      }
    }

    try {
      await traverse(rootfsDir);
    } catch (err) {
      logger.warn(`Snapshot: error traversing rootfs ${rootfsDir}: ${err.message}`);
    }
  }

  return {
    rootfsDir,
    timestamp: new Date().toISOString(),
    summary: {
      totalFiles,
      addedOrModified: addedCount,
      suspiciousFiles: suspiciousCount
    },
    files: manifest
  };
}

/**
 * Create a complete, cryptographically sealed container forensic snapshot bundle
 * @param {Object} containerInfo { podName, containerId, pid, rootfsDir }
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Snapshot metadata & path
 */
export async function createForensicsSnapshot(containerInfo = {}, options = {}) {
  const podName = containerInfo.podName || 'unknown-pod';
  const containerId = containerInfo.containerId || 'cid-' + crypto.randomBytes(4).toString('hex');
  const pid = containerInfo.pid || 1;

  const baseEvidenceDir = options.outputDir || path.join(getVigilanteEvidenceDir(), 'snapshots');
  await fs.mkdir(baseEvidenceDir, { recursive: true });

  const timestamp = Date.now();
  const snapshotId = `snapshot-${podName}-${containerId.substring(0, 8)}-${timestamp}`;
  const snapshotBundleDir = path.join(baseEvidenceDir, snapshotId);
  await fs.mkdir(snapshotBundleDir, { recursive: true });

  // 1. Harvest volatiles
  const volatiles = await captureContainerVolatiles(pid, options);
  const volatilesFile = path.join(snapshotBundleDir, 'volatiles.json');
  await fs.writeFile(volatilesFile, JSON.stringify(volatiles, null, 2), 'utf8');

  // 2. Harvest disk differential
  const diffManifest = await captureContainerDiff(containerInfo.rootfsDir || '', options);
  const diffFile = path.join(snapshotBundleDir, 'disk_diff.json');
  await fs.writeFile(diffFile, JSON.stringify(diffManifest, null, 2), 'utf8');

  // 3. Compute bundle payload seal (SHA-256 over volatiles + diff)
  const bundlePayload = Buffer.concat([
    Buffer.from(JSON.stringify(volatiles)),
    Buffer.from(JSON.stringify(diffManifest))
  ]);
  const sha256Seal = crypto.createHash('sha256').update(bundlePayload).digest('hex');

  // 4. Create immutable snapshot manifest
  const manifest = {
    snapshotId,
    podName,
    containerId,
    pid,
    timestamp: new Date(timestamp).toISOString(),
    sha256Seal,
    volatilesCount: volatiles.openFds.length,
    modifiedFilesCount: diffManifest.files.length,
    suspiciousFilesCount: diffManifest.summary.suspiciousFiles,
    filesIncluded: ['volatiles.json', 'disk_diff.json']
  };

  const manifestPath = path.join(snapshotBundleDir, 'manifest.json');
  await fs.writeFile(manifestPath, JSON.stringify(manifest, null, 2), 'utf8');

  logger.info('SNAPSHOT', `Created sealed forensics snapshot [${snapshotId}] (Seal: ${sha256Seal.substring(0, 16)}...)`);

  return {
    snapshotId,
    snapshotDir: snapshotBundleDir,
    manifestPath,
    sha256Seal,
    manifest
  };
}

/**
 * Verify cryptographic seal and integrity of a snapshot directory
 * @param {string} snapshotDir
 * @returns {Promise<Object>} Verification status
 */
export async function verifySnapshotIntegrity(snapshotDir) {
  const manifestPath = path.join(snapshotDir, 'manifest.json');
  const volatilesFile = path.join(snapshotDir, 'volatiles.json');
  const diffFile = path.join(snapshotDir, 'disk_diff.json');

  if (!fsSync.existsSync(manifestPath)) {
    return { valid: false, issue: 'Missing manifest.json' };
  }

  const manifest = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
  const volatiles = JSON.parse(await fs.readFile(volatilesFile, 'utf8'));
  const diffManifest = JSON.parse(await fs.readFile(diffFile, 'utf8'));

  const payload = Buffer.concat([
    Buffer.from(JSON.stringify(volatiles)),
    Buffer.from(JSON.stringify(diffManifest))
  ]);
  const calculatedSeal = crypto.createHash('sha256').update(payload).digest('hex');

  const isValid = calculatedSeal === manifest.sha256Seal;

  return {
    valid: isValid,
    snapshotId: manifest.snapshotId,
    expectedSeal: manifest.sha256Seal,
    calculatedSeal,
    podName: manifest.podName,
    timestamp: manifest.timestamp
  };
}

/**
 * List saved container snapshots in the evidence directory
 * @param {Object} [options={}]
 * @returns {Promise<Array<Object>>}
 */
export async function listSavedSnapshots(options = {}) {
  const baseEvidenceDir = options.outputDir || path.join(getVigilanteEvidenceDir(), 'snapshots');
  if (!fsSync.existsSync(baseEvidenceDir)) return [];

  const entries = await fs.readdir(baseEvidenceDir, { withFileTypes: true });
  const snapshots = [];

  for (const entry of entries) {
    if (entry.isDirectory() && entry.name.startsWith('snapshot-')) {
      const manifestPath = path.join(baseEvidenceDir, entry.name, 'manifest.json');
      if (fsSync.existsSync(manifestPath)) {
        try {
          const m = JSON.parse(await fs.readFile(manifestPath, 'utf8'));
          snapshots.push(m);
        } catch {}
      }
    }
  }

  return snapshots.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}
