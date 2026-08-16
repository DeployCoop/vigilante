import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteEvidenceDir, getHostEvidenceDir, sanitizePathComponent, ensureVigilanteConfig } from './config.js';
import { autoSignIfConfigured, verifyFileSignature } from './gpg.js';
import { logger } from '../utils/logger.js';

/**
 * Save an evidence file into $XDG_CONFIG_HOME/vigilante/evidence/<network_cidr>/<host_ip>/<fileName>
 * If GPG is configured, automatically creates a detached signature <fileName>.asc alongside it
 * @param {string} networkCidr e.g. "10.0.1.0/24"
 * @param {string} hostIp e.g. "10.0.1.5"
 * @param {string} fileName e.g. "mtr.xml", "tls_certificates.pem", "ping.json"
 * @param {string|Object} content Text content or JSON serializable object
 * @returns {Promise<{ filePath: string, signaturePath?: string, isSigned: boolean, signerKeyId?: string }>}
 */
export async function saveEvidenceFile(networkCidr, hostIp, fileName, content) {
  await ensureVigilanteConfig();
  const hostDir = getHostEvidenceDir(networkCidr, hostIp);
  await fs.mkdir(hostDir, { recursive: true });

  const safeFileName = path.basename(fileName);
  const filePath = path.join(hostDir, safeFileName);

  const dataStr = typeof content === 'string'
    ? content
    : JSON.stringify(content, null, 2);

  await fs.writeFile(filePath, dataStr, 'utf8');
  logger.info('EVIDENCE:SAVE', `Saved evidence artifact: ${filePath} (${dataStr.length} bytes)`);

  // Automatically sign if GPG is configured
  let signatureInfo = { isSigned: false };
  if (!safeFileName.endsWith('.asc') && !safeFileName.endsWith('.sig')) {
    try {
      signatureInfo = await autoSignIfConfigured(filePath);
      if (signatureInfo.isSigned) {
        logger.info('EVIDENCE:GPG_SIGN', `Signed ${safeFileName} with key ${signatureInfo.keyId}`);
      }
    } catch (err) {
      logger.warn('EVIDENCE:GPG_SIGN_ERR', `Could not sign ${safeFileName}: ${err.message}`);
    }
  }

  return {
    filePath,
    signaturePath: signatureInfo.signaturePath || null,
    isSigned: !!signatureInfo.isSigned,
    signerKeyId: signatureInfo.keyId || null
  };
}

/**
 * Save a complete triage evidence bundle for a host
 * @param {string} networkCidr
 * @param {string} hostIp
 * @param {Object} bundle Object containing diagnostic results
 * @returns {Promise<Object>} Summary of saved evidence
 */
export async function saveTriageBundle(networkCidr, hostIp, bundle = {}) {
  await ensureVigilanteConfig();
  const hostDir = getHostEvidenceDir(networkCidr, hostIp);
  await fs.mkdir(hostDir, { recursive: true });

  const savedFiles = [];
  const timestamp = new Date().toISOString();

  // 1. Ping evidence
  if (bundle.ping) {
    const res = await saveEvidenceFile(networkCidr, hostIp, 'ping.json', bundle.ping);
    savedFiles.push({
      name: 'ping.json',
      path: res.filePath,
      type: 'ICMP Latency',
      isSigned: res.isSigned,
      signaturePath: res.signaturePath
    });
  }

  // 2. MTR / Trace evidence
  if (bundle.mtr) {
    const res = await saveEvidenceFile(networkCidr, hostIp, 'mtr.txt', bundle.mtr.output || bundle.mtr);
    savedFiles.push({
      name: 'mtr.txt',
      path: res.filePath,
      type: 'Route Path & Loss',
      isSigned: res.isSigned,
      signaturePath: res.signaturePath
    });
  }

  // 3. DNS evidence
  if (bundle.dns) {
    const res = await saveEvidenceFile(networkCidr, hostIp, 'dns_records.json', bundle.dns);
    savedFiles.push({
      name: 'dns_records.json',
      path: res.filePath,
      type: 'DNS Records & PTR',
      isSigned: res.isSigned,
      signaturePath: res.signaturePath
    });
  }

  // 4. TLS Certificates evidence
  if (bundle.tls) {
    const res = await saveEvidenceFile(networkCidr, hostIp, 'tls_certificates.pem', bundle.tls.output || bundle.tls);
    savedFiles.push({
      name: 'tls_certificates.pem',
      path: res.filePath,
      type: 'TLS Certificate Chain',
      isSigned: res.isSigned,
      signaturePath: res.signaturePath
    });
  }

  // 5. HTTP Headers & Banners evidence
  if (bundle.http) {
    const res = await saveEvidenceFile(networkCidr, hostIp, 'http_headers.txt', bundle.http.output || bundle.http);
    savedFiles.push({
      name: 'http_headers.txt',
      path: res.filePath,
      type: 'HTTP Headers & Security Tokens',
      isSigned: res.isSigned,
      signaturePath: res.signaturePath
    });
  }

  // 6. ARP / Neighbors evidence
  if (bundle.arp) {
    const res = await saveEvidenceFile(networkCidr, hostIp, 'arp_neighbors.json', bundle.arp);
    savedFiles.push({
      name: 'arp_neighbors.json',
      path: res.filePath,
      type: 'Kernel ARP & Neighbor Table',
      isSigned: res.isSigned,
      signaturePath: res.signaturePath
    });
  }

  // 7. Benchmark evidence
  if (bundle.benchmark) {
    const res = await saveEvidenceFile(networkCidr, hostIp, 'benchmark.txt', bundle.benchmark.output || bundle.benchmark);
    savedFiles.push({
      name: 'benchmark.txt',
      path: res.filePath,
      type: 'HTTP Load & Concurrency',
      isSigned: res.isSigned,
      signaturePath: res.signaturePath
    });
  }

  // 8. Triage summary index
  const summary = {
    network: networkCidr,
    host: hostIp,
    capturedAt: timestamp,
    totalArtifacts: savedFiles.length,
    artifacts: savedFiles,
    metadata: bundle.metadata || {}
  };

  const summaryRes = await saveEvidenceFile(networkCidr, hostIp, 'triage_summary.json', summary);
  savedFiles.push({
    name: 'triage_summary.json',
    path: summaryRes.filePath,
    type: 'IR Triage Summary Index',
    isSigned: summaryRes.isSigned,
    signaturePath: summaryRes.signaturePath
  });

  logger.info('EVIDENCE:TRIAGE_BUNDLE', `Completed triage bundle for ${hostIp} in ${networkCidr} (${savedFiles.length} artifacts)`);
  return {
    hostDir,
    network: networkCidr,
    host: hostIp,
    timestamp,
    artifacts: savedFiles
  };
}

/**
 * List all saved evidence in the evidence vault categorized by network and host
 * Hierarchy: EvidenceVault -> Networks -> Hosts -> Evidence Files
 * @returns {Promise<Array<Object>>}
 */
export async function listEvidenceVault() {
  await ensureVigilanteConfig();
  const baseDir = getVigilanteEvidenceDir();
  const vault = [];

  try {
    const netEntries = await fs.readdir(baseDir, { withFileTypes: true });

    for (const netEntry of netEntries) {
      if (!netEntry.isDirectory()) continue;
      const netDirName = netEntry.name;
      const netPath = path.join(baseDir, netDirName);
      const networkCidr = netDirName.replace(/_/g, '/');

      const hostEntries = await fs.readdir(netPath, { withFileTypes: true });
      const hosts = [];

      for (const hostEntry of hostEntries) {
        if (!hostEntry.isDirectory()) continue;
        const hostIp = hostEntry.name.replace(/_/g, '.');
        const hostPath = path.join(netPath, hostEntry.name);

        const files = await fs.readdir(hostPath);
        const artifacts = [];
        const ascFiles = new Set(files.filter(f => f.endsWith('.asc') || f.endsWith('.sig')));

        for (const file of files) {
          if (file.endsWith('.asc') || file.endsWith('.sig')) continue;
          const filePath = path.join(hostPath, file);
          const hasAsc = ascFiles.has(`${file}.asc`) || ascFiles.has(`${file}.sig`);
          try {
            const stats = await fs.stat(filePath);
            artifacts.push({
              name: file,
              path: filePath,
              sizeBytes: stats.size,
              mtime: stats.mtime,
              isSigned: hasAsc,
              signaturePath: hasAsc ? path.join(hostPath, `${file}.asc`) : null
            });
          } catch {
            // Ignore stat errors
          }
        }

        hosts.push({
          hostIp,
          hostDir: hostPath,
          artifactCount: artifacts.length,
          artifacts: artifacts.sort((a, b) => b.mtime - a.mtime),
          lastCaptured: artifacts.length > 0 ? artifacts[0].mtime : null
        });
      }

      vault.push({
        networkCidr,
        networkDir: netPath,
        hostCount: hosts.length,
        hosts: hosts.sort((a, b) => (b.lastCaptured || 0) - (a.lastCaptured || 0))
      });
    }
  } catch (err) {
    logger.warn('EVIDENCE:LIST', `Failed to read evidence vault: ${err.message}`);
  }

  return vault;
}

/**
 * List evidence artifacts for a specific network and host
 * @param {string} networkCidr
 * @param {string} hostIp
 * @returns {Promise<Array<Object>>}
 */
export async function listHostEvidence(networkCidr, hostIp) {
  const hostDir = getHostEvidenceDir(networkCidr, hostIp);
  const artifacts = [];

  try {
    const files = await fs.readdir(hostDir);
    const ascFiles = new Set(files.filter(f => f.endsWith('.asc') || f.endsWith('.sig')));

    for (const file of files) {
      if (file.endsWith('.asc') || file.endsWith('.sig')) continue;
      const filePath = path.join(hostDir, file);
      const hasAsc = ascFiles.has(`${file}.asc`) || ascFiles.has(`${file}.sig`);
      const stats = await fs.stat(filePath);
      artifacts.push({
        name: file,
        path: filePath,
        sizeBytes: stats.size,
        mtime: stats.mtime,
        isSigned: hasAsc,
        signaturePath: hasAsc ? path.join(hostDir, `${file}.asc`) : null
      });
    }
  } catch {
    // Directory might not exist yet
  }

  return artifacts.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Read content of an evidence file
 * @param {string|Object} target - File path string or object containing filePath/path
 * @returns {Promise<string>}
 */
export async function readEvidenceContent(target) {
  const targetPath = typeof target === 'string' ? target : (target?.filePath || target?.path);
  return await fs.readFile(targetPath, 'utf8');
}

/**
 * Delete host evidence directory
 * @param {string} networkCidr
 * @param {string} hostIp
 */
export async function deleteHostEvidence(networkCidr, hostIp) {
  const hostDir = getHostEvidenceDir(networkCidr, hostIp);
  await fs.rm(hostDir, { recursive: true, force: true });
  logger.info('EVIDENCE:DELETE', `Deleted evidence for ${hostIp} in ${networkCidr}`);
}
