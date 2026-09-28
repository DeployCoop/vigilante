import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  getVigilanteOobscansDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { detectNetworkSubnets } from './nmap.js';
import { logger } from '../utils/logger.js';

export const OOB_SCAN_PROFILES = [
  {
    id: 'standard',
    name: '🔍 Standard BMC Security Audit',
    description: 'Complete BMC identification, protocol fingerprinting, default credential verification & RAKP hash capture',
    args: ['scan'],
    buildArgs: (target, opts = {}) => {
      const a = ['scan', '-targets', target];
      if (opts.disableLogins) a.push('-no-logins');
      if (opts.ipmiFull) a.push('-ipmi-full');
      return a;
    }
  },
  {
    id: 'quick',
    name: '⚡ Quick Discovery (Passive, No Logins)',
    description: 'Fast passive enumeration of RMCP, Device ID, and TLS banners without active authentication attempts (--disable-logins)',
    args: ['scan', '--disable-logins'],
    buildArgs: (target, opts = {}) => {
      const a = ['scan', '-targets', target, '-no-logins'];
      if (opts.ipmiFull) a.push('-ipmi-full');
      return a;
    }
  },
  {
    id: 'ipmi-full',
    name: '🔬 Full IPMI & Sensor Walk',
    description: 'In-depth IPMI walk querying sensors, channel auth capabilities, cipher suite matrices, and user slots (--ipmi-full)',
    args: ['scan', '--ipmi-full'],
    buildArgs: (target, opts = {}) => {
      const a = ['scan', '-targets', target, '-ipmi-full'];
      if (opts.disableLogins) a.push('-no-logins');
      return a;
    }
  },
  {
    id: 'link-local',
    name: '🌐 IPv6 Link-Local Multicast Sweep',
    description: 'Sweep IPv6 all-nodes multicast (ff02::1) to discover freshly racked or unaddressed BMCs on the local L2 segment',
    args: ['scan'],
    buildArgs: (target, opts = {}) => {
      const a = ['scan', '-targets', target];
      if (opts.disableLogins) a.push('-no-logins');
      if (opts.ipmiFull) a.push('-ipmi-full');
      return a;
    }
  },
  {
    id: 'passive',
    name: '🛡️ Non-Intrusive Fingerprint (Safe for OT)',
    description: 'Zero authentication attempts and minimal traffic profile for sensitive industrial/OT environments',
    args: ['scan', '--disable-logins'],
    buildArgs: (target) => {
      return ['scan', '-targets', target, '-no-logins'];
    }
  },
  {
    id: 'custom',
    name: '⚙️ Custom Arguments',
    description: 'User-specified oobscan flags, checks, and parameters',
    args: ['scan'],
    buildArgs: (target) => {
      return ['scan', '-targets', target];
    }
  }
];

// Attach key lookup aliases so OOB_SCAN_PROFILES.standard or OOB_SCAN_PROFILES.quick works
OOB_SCAN_PROFILES.standard = OOB_SCAN_PROFILES[0];
OOB_SCAN_PROFILES.quick = OOB_SCAN_PROFILES[1];
OOB_SCAN_PROFILES['ipmi-full'] = OOB_SCAN_PROFILES[2];
OOB_SCAN_PROFILES.ipmi = OOB_SCAN_PROFILES[2];
OOB_SCAN_PROFILES['link-local'] = OOB_SCAN_PROFILES[3];
OOB_SCAN_PROFILES.ipv6 = OOB_SCAN_PROFILES[3];
OOB_SCAN_PROFILES.passive = OOB_SCAN_PROFILES[4];
OOB_SCAN_PROFILES.custom = OOB_SCAN_PROFILES[5];

/**
 * Check if oobscan binary is installed and executable
 * @returns {Promise<{ installed: boolean, version: string, error?: string }>}
 */
export async function checkOobscanInstalled() {
  try {
    const { stdout: whichOut } = await execa('which', ['oobscan']).catch(() => ({ stdout: '' }));
    const execPath = whichOut.trim() || null;
    const { stdout, stderr } = await execa('oobscan', ['version']);
    const output = (stdout || stderr || '').trim();
    const match = output.match(/version\s+([^\s,]+)/i) || output.match(/([0-9]+\.[0-9]+(?:\.[0-9]+)?)/);
    const version = match ? match[1] : (output.slice(0, 30) || 'installed');
    return { installed: true, version, path: execPath };
  } catch (err) {
    // Try --version fallback
    try {
      const { stdout: whichOut } = await execa('which', ['oobscan']).catch(() => ({ stdout: '' }));
      const execPath = whichOut.trim() || null;
      const { stdout } = await execa('oobscan', ['--version']);
      const match = stdout.match(/version\s+([^\s,]+)/i);
      return { installed: true, version: match ? match[1] : 'installed', path: execPath };
    } catch {
      return {
        installed: false,
        version: null,
        path: null,
        error: `oobscan not found in PATH (${err.message}). Install via 'go install github.com/runZeroInc/oobscan/cmd/oobscan@latest' or download pre-built binary from https://github.com/runZeroInc/oobscan/releases.`
      };
    }
  }
}

/**
 * Detect smart targets for OOB/BMC scanning including IPv4 subnets and IPv6 link-local multicast interfaces
 * @param {Object} [options]
 * @param {string} [options.ip='127.0.0.1']
 * @param {string} [options.domain='vigilante.local']
 * @returns {Array<{ label: string, value: string, isCidr: boolean, isLinkLocal: boolean }>}
 */
export function detectOobTargets({ ip = '127.0.0.1', domain = 'vigilante.local' } = {}) {
  const targets = [];

  // 1. IPv6 Link-Local Multicast Groups (all interfaces & specific ifaces)
  targets.push({
    label: 'IPv6 Multicast Sweep (All Up Interfaces) [ff02::1]',
    value: 'ff02::1',
    type: 'ipv6-multicast',
    isCidr: false,
    isLinkLocal: true
  });

  try {
    const interfaces = os.networkInterfaces();
    for (const [ifaceName, addrs] of Object.entries(interfaces)) {
      if (!addrs) continue;
      const hasIpv6LinkLocal = addrs.some(a => a.family === 'IPv6' && a.address.startsWith('fe80:'));
      if (hasIpv6LinkLocal) {
        targets.push({
          label: `IPv6 Multicast Sweep (${ifaceName}) [ff02::1%${ifaceName}]`,
          value: `ff02::1%${ifaceName}`,
          type: 'ipv6-multicast',
          isCidr: false,
          isLinkLocal: true
        });
      }
    }
  } catch (err) {
    logger.warn('OOBSCAN:TARGETS', `Failed to enumerate IPv6 interfaces: ${err.message}`);
  }

  // 2. Local Subnets from Nmap engine
  const subnets = detectNetworkSubnets();
  for (const s of subnets) {
    targets.push({
      label: `${s.label} [${s.cidr}]`,
      value: s.cidr,
      type: 'subnet',
      isCidr: true,
      isLinkLocal: false
    });
  }

  // 3. Common BMC Subnet Ranges
  const commonBmcRanges = [
    { label: 'Out-of-Band Management VLAN (Common)', value: '10.0.100.0/24' },
    { label: 'Private Subnet Range', value: '192.168.1.0/24' },
    { label: 'Localhost / Management Bridge', value: '127.0.0.1' }
  ];

  for (const item of commonBmcRanges) {
    if (!targets.some(t => t.value === item.value)) {
      targets.push({
        label: `${item.label} [${item.value}]`,
        value: item.value,
        type: item.value.includes('/') ? 'subnet' : 'host',
        isCidr: item.value.includes('/'),
        isLinkLocal: false
      });
    }
  }

  return targets;
}

/**
 * Parse NDJSON output generated by oobscan into structured BMC and vulnerability models
 * @param {string} content - Raw NDJSON string
 * @param {string} [filename='']
 * @returns {Object}
 */
export function parseOobReportContent(content, filename = '') {
  if (!content || typeof content !== 'string') {
    return {
      target: extractTargetFromFilename(filename),
      totalTargets: 0,
      totalBmcs: 0,
      totalFindings: 0,
      totalCves: 0,
      totalRakpHashes: 0,
      totalCreds: 0,
      bmcs: [],
      rawRecords: [],
      summary: 'No scan records found.'
    };
  }

  const lines = content.split('\n').map(l => l.trim()).filter(Boolean);
  const rawRecords = [];
  const bmcsByHost = new Map();

  let totalFindings = 0;
  let totalCves = 0;
  let totalRakpHashes = 0;
  let totalCreds = 0;

  for (const line of lines) {
    try {
      const record = JSON.parse(line);
      rawRecords.push(record);

      const host = record.host || record.ip || record.target || 'unknown-host';
      const existing = bmcsByHost.get(host) || {
        host,
        ip: record.ip || host.split('%')[0],
        zone: record.zone || (host.includes('%') ? host.split('%')[1] : null),
        vendor: record.vendor || record.manufacturer || 'Generic / Unknown',
        product: record.product || record.model || record.device || 'BMC',
        firmware: record.firmware || record.version || record.fw_version || null,
        deviceClass: record.device_class || record.class || 'bmc',
        guid: record.guid || record.system_guid || null,
        mac: record.mac || record.board_mac || null,
        serial: record.serial || record.service_tag || null,
        protocols: new Set(),
        findings: [],
        cves: [],
        rakp: [],
        creds: []
      };

      // Protocols & Ports
      if (record.protocol) existing.protocols.add(record.protocol);
      if (record.proto) existing.protocols.add(record.proto);
      if (record.protocols && Array.isArray(record.protocols)) {
        for (const p of record.protocols) existing.protocols.add(p);
      }
      if (record.ports && Array.isArray(record.ports)) {
        for (const p of record.ports) {
          if (p.service) existing.protocols.add(p.service);
        }
      }
      if (record.ipmi || record.service === 'ipmi') existing.protocols.add('ipmi');
      if (record.redfish) existing.protocols.add('redfish');
      if (record.ilo) existing.protocols.add('ilo');
      if (record.idrac) existing.protocols.add('idrac');
      if (record.amt) existing.protocols.add('amt');
      if (record.snmp) existing.protocols.add('snmp');
      if (record.wsman) existing.protocols.add('wsman');

      // Findings & Checks (from arrays, record.type === 'finding', or record.check)
      if (record.type === 'finding' || record.title || record.findings || record.finding) {
        if (record.type === 'finding' || (record.title && !record.type)) {
          const findingObj = {
            title: record.title || 'Vulnerability Finding',
            severity: record.severity || 'MEDIUM',
            cve: record.cve || null,
            description: record.description || record.detail || ''
          };
          if (!existing.findings.some(ef => ef.title === findingObj.title)) {
            existing.findings.push(findingObj);
            totalFindings++;
          }
          if (record.cve && !existing.cves.includes(record.cve)) {
            existing.cves.push(record.cve);
            totalCves++;
          }
        }
        if (record.findings || record.finding) {
          const rawFindings = record.findings || record.finding;
          const findingsList = Array.isArray(rawFindings) ? rawFindings : [rawFindings];
          for (const f of findingsList) {
            const findingObj = typeof f === 'string' ? { title: f, severity: 'MEDIUM' } : f;
            if (!existing.findings.some(ef => ef.title === findingObj.title)) {
              existing.findings.push(findingObj);
              totalFindings++;
            }
          }
        }
      }
      if (record.check) {
        existing.findings.push({ title: record.check, detail: record.detail || '', severity: record.severity || 'INFO' });
        totalFindings++;
      }

      // CVEs
      if (record.cves && Array.isArray(record.cves)) {
        for (const cve of record.cves) {
          const cveStr = String(cve);
          if (!existing.cves.includes(cveStr)) {
            existing.cves.push(cveStr);
            totalCves++;
          }
        }
      }
      if (record.cve && !existing.cves.includes(record.cve)) {
        existing.cves.push(record.cve);
        totalCves++;
      }

      // RAKP records (IPMI 2.0 RAKP-2 hashes)
      if (record.rakp || record.rakp_hash || record.rakp_hashes) {
        const rawRakp = record.rakp || record.rakp_hashes || record.rakp_hash;
        const rakpList = Array.isArray(rawRakp)
          ? rawRakp
          : (typeof rawRakp === 'string' ? [{ hash: rawRakp, hashcat: rawRakp, user: record.rakp_username || record.username || 'root' }] : [rawRakp]);
        for (const r of rakpList) {
          const hashcatStr = r.hashcat || (typeof r.hash === 'string' && (r.hash.startsWith('$rakp') || r.hash.includes('rakp')) ? r.hash : null) || (typeof r === 'string' ? r : null);
          existing.rakp.push({
            user: r.user || r.username || record.rakp_username || 'admin',
            role: r.role || 'ADMINISTRATOR',
            cipher: r.cipher || 'RAKP-HMAC-SHA1',
            hashcat: hashcatStr,
            hash: r.hash || hashcatStr,
            raw: r
          });
          totalRakpHashes++;
        }
      }

      // Discovered Weak / Default Credentials
      if (record.type === 'credential' || record.creds || record.credential || record.credentials) {
        if (record.type === 'credential' || (record.username && record.password && !record.creds && !record.credential && !record.credentials)) {
          existing.creds.push({
            user: record.username || record.user,
            pass: record.password || record.pass,
            protocol: record.service || record.protocol || 'ipmi',
            status: record.valid !== false ? 'valid' : 'invalid'
          });
          totalCreds++;
        }
        if (record.creds || record.credential || record.credentials) {
          const rawCreds = record.creds || record.credential || record.credentials;
          const credsList = Array.isArray(rawCreds) ? rawCreds : [rawCreds];
          for (const c of credsList) {
            existing.creds.push({
              user: c.user || c.username,
              pass: c.pass || c.password,
              protocol: c.protocol || c.service || 'ipmi',
              status: c.status || (c.valid !== false ? 'valid' : 'invalid')
            });
            totalCreds++;
          }
        }
      }

      bmcsByHost.set(host, existing);
    } catch {
      // Ignore malformed non-JSON lines (e.g. progress logs)
    }
  }

  // Convert Set to Array
  const bmcs = Array.from(bmcsByHost.values()).map(b => ({
    ...b,
    protocols: Array.from(b.protocols)
  }));

  const target = extractTargetFromFilename(filename) || (bmcs[0]?.host || 'unknown-target');

  // Generate summary
  let summaryText = '';
  if (bmcs.length === 0) {
    summaryText = 'No out-of-band management devices (BMCs) responded.';
  } else {
    const vendors = Array.from(new Set(bmcs.map(b => b.vendor).filter(Boolean)));
    const vendorSummary = vendors.length > 0 ? ` (${vendors.slice(0, 3).join(', ')})` : '';
    summaryText = `${bmcs.length} BMC device${bmcs.length === 1 ? '' : 's'} identified${vendorSummary}. ${totalRakpHashes} RAKP hash${totalRakpHashes === 1 ? '' : 'es'} captured, ${totalCreds} valid credential${totalCreds === 1 ? '' : 's'}, ${totalCves} CVE${totalCves === 1 ? '' : 's'}.`;
  }

  const rakpHashes = bmcs.flatMap(b => (b.rakp || []).map(r => ({
    ip: b.ip,
    host: b.host,
    username: r.user,
    cipher: r.cipher,
    hashcatLine: r.hashcat || r.hash
  }))).filter(h => Boolean(h.hashcatLine));

  const summary = {
    text: summaryText,
    toString() { return summaryText; },
    valueOf() { return summaryText; },
    totalLines: rawRecords.length,
    hostsCount: bmcs.length,
    bmcsCount: bmcs.length,
    rakpHashesCount: totalRakpHashes,
    findingsCount: totalFindings,
    defaultCredentialsCount: totalCreds,
    cvesCount: totalCves
  };

  return {
    target,
    totalTargets: bmcs.length,
    totalBmcs: bmcs.length,
    totalFindings,
    totalCves,
    totalRakpHashes,
    totalCreds,
    bmcs,
    rakpHashes,
    rawRecords,
    summary
  };
}

/**
 * Helper to extract target from standard oobscan filename
 */
function extractTargetFromFilename(filename) {
  if (!filename) return 'unknown-target';
  const clean = filename.replace(/^oobscan-/, '').replace(/-\d+\.(jsonl|ndjson|txt)$/, '');
  return clean ? clean.replace(/_/g, '/') : 'unknown-target';
}

/**
 * Execute an OOBscan against an IP, CIDR block, or IPv6 multicast group
 * @param {Object} options
 * @param {string} options.target - IP, CIDR (e.g. 10.0.1.0/24), or IPv6 link-local (e.g. ff02::1%en0)
 * @param {string} [options.profile='standard'] - Scan profile id
 * @param {Array<string>} [options.customArgs=[]] - Additional CLI arguments
 * @param {boolean} [options.disableLogins=false] - Disable default credential checks
 * @param {boolean} [options.ipmiFull=false] - Perform full IPMI walk
 * @param {Function} [options.onLog] - Streaming log callback
 * @returns {Promise<Object>}
 */
export async function runOobScan({
  target = '127.0.0.1',
  profile = 'standard',
  customArgs = [],
  disableLogins = false,
  ipmiFull = false,
  onLog = null
} = {}) {
  await ensureVigilanteConfig();
  const oobscansDir = getVigilanteOobscansDir();
  const check = await checkOobscanInstalled();
  if (!check.installed) {
    throw new Error(check.error);
  }

  const cleanTarget = (target || '127.0.0.1').trim();
  const safeTargetName = cleanTarget.replace(/[/:]/g, '_').replace(/[^a-zA-Z0-9._-]/g, '');
  const timestamp = Date.now();
  const baseName = `oobscan-${safeTargetName}-${timestamp}`;
  const jsonlFilePath = path.join(oobscansDir, `${baseName}.jsonl`);
  const hashcatFilePath = path.join(oobscansDir, `${baseName}.hashcat`);

  const profileDef = OOB_SCAN_PROFILES.find(p => p.id === profile) || OOB_SCAN_PROFILES[0];
  const profileArgs = profile === 'custom' ? customArgs : [...profileDef.args];

  const args = [
    ...profileArgs,
    '-o', jsonlFilePath,
    '-v'
  ];

  if ((disableLogins || profile === 'quick' || profile === 'passive') && !args.includes('--disable-logins')) {
    args.push('--disable-logins');
  }
  if ((ipmiFull || profile === 'ipmi-full') && !args.includes('--ipmi-full')) {
    args.push('--ipmi-full');
  }

  // Target goes last
  args.push(cleanTarget);

  logger.info('OOBSCAN:START', `Running scan: oobscan ${args.join(' ')}`);
  if (onLog) {
    onLog(`🎯 Starting OOBscan [${profileDef.name}] against: ${cleanTarget}`);
    onLog(`⚙️  Command: oobscan ${args.join(' ')}`);
    onLog(`💾 Destination: ${jsonlFilePath}`);
  }

  const startTime = Date.now();
  let fullOutput = '';

  try {
    const subprocess = execa('oobscan', args);

    if (subprocess.stdout) {
      subprocess.stdout.on('data', (chunk) => {
        const text = chunk.toString();
        fullOutput += text;
        if (onLog) {
          for (const line of text.split('\n').filter(Boolean)) {
            onLog(line);
          }
        }
      });
    }

    if (subprocess.stderr) {
      subprocess.stderr.on('data', (chunk) => {
        const text = chunk.toString();
        fullOutput += text;
        if (onLog) {
          for (const line of text.split('\n').filter(Boolean)) {
            onLog(line);
          }
        }
      });
    }

    await subprocess;
    const durationMs = Date.now() - startTime;

    if (onLog) {
      onLog(`✔ OOBscan finished in ${(durationMs / 1000).toFixed(2)}s!`);
      onLog(`📁 Saved results to: ${jsonlFilePath}`);
    }

    logger.info('OOBSCAN:SUCCESS', `Scan completed for ${cleanTarget} in ${durationMs}ms`);

    // Auto-sign scan reports if GPG is configured
    try {
      await autoSignIfConfigured(jsonlFilePath);
    } catch (err) {
      logger.warn('OOBSCAN:GPG', `Failed to auto-sign scan outputs: ${err.message}`);
    }

    // Read and parse resulting NDJSON file
    let fileContent = '';
    try {
      fileContent = await fs.readFile(jsonlFilePath, 'utf8');
    } catch {
      fileContent = fullOutput;
    }

    const parsed = parseOobReportContent(fileContent, `${baseName}.jsonl`);

    // Export any RAKP hashcat lines to sibling .hashcat file
    const hashcatLines = [];
    for (const b of parsed.bmcs) {
      for (const r of b.rakp) {
        if (r.hashcat) {
          hashcatLines.push(r.hashcat);
        }
      }
    }

    let hasHashes = false;
    if (hashcatLines.length > 0) {
      await fs.writeFile(hashcatFilePath, hashcatLines.join('\n') + '\n', 'utf8');
      hasHashes = true;
      try {
        await autoSignIfConfigured(hashcatFilePath);
      } catch {
        // Ignore
      }
      if (onLog) {
        onLog(`🔑 Exported ${hashcatLines.length} Hashcat -m 7300 RAKP hash lines to: ${hashcatFilePath}`);
      }
    }

    // Copy to host evidence directory if applicable
    if (!cleanTarget.includes('/') && !cleanTarget.startsWith('ff02')) {
      try {
        await saveEvidenceFile({
          networkCidr: 'out-of-band',
          hostIp: cleanTarget,
          category: 'oobscan',
          filename: `${baseName}.jsonl`,
          content: fileContent,
          command: `oobscan ${args.join(' ')}`
        });
      } catch (err) {
        logger.warn('OOBSCAN:EVIDENCE', `Failed to save host evidence: ${err.message}`);
      }
    }

    return {
      id: baseName,
      target: cleanTarget,
      profile: profileDef.id,
      profileName: profileDef.name,
      jsonlFilePath,
      hashcatFilePath: hasHashes ? hashcatFilePath : null,
      durationMs,
      output: fullOutput,
      parsed
    };
  } catch (err) {
    logger.error('OOBSCAN:ERROR', `Scan failed: ${err.message}`, err);
    throw new Error(`OOBscan failed: ${err.message}`);
  }
}

/**
 * List all saved OOBscan results in $XDG_CONFIG_HOME/vigilante/oobscans/
 * @returns {Promise<Array<Object>>}
 */
export async function listSavedOobScans() {
  await ensureVigilanteConfig();
  const oobscansDir = getVigilanteOobscansDir();
  const scans = [];

  try {
    const files = await fs.readdir(oobscansDir);
    const jsonlFiles = files.filter(f => f.endsWith('.jsonl') || f.endsWith('.ndjson'));

    for (const file of jsonlFiles) {
      const filePath = path.join(oobscansDir, file);
      try {
        const stats = await fs.stat(filePath);
        const content = await fs.readFile(filePath, 'utf8');

        const baseName = file.replace(/\.(jsonl|ndjson)$/, '');
        const hashcatPath = path.join(oobscansDir, `${baseName}.hashcat`);
        const hasHashcat = fsSync.existsSync(hashcatPath);

        const parsed = parseOobReportContent(content, file);

        scans.push({
          id: baseName,
          filename: file,
          filePath,
          hashcatFilePath: hasHashcat ? hashcatPath : null,
          target: parsed.target,
          totalBmcs: parsed.totalBmcs,
          totalFindings: parsed.totalFindings,
          totalCves: parsed.totalCves,
          totalRakpHashes: parsed.totalRakpHashes,
          totalCreds: parsed.totalCreds,
          summary: parsed.summary,
          bmcs: parsed.bmcs,
          sizeBytes: stats.size,
          mtime: stats.mtime,
          createdAt: stats.birthtime || stats.mtime
        });
      } catch (err) {
        logger.warn('OOBSCAN:LIST', `Failed to parse scan file ${file}: ${err.message}`);
      }
    }
  } catch (err) {
    logger.warn('OOBSCAN:LIST', `Failed to read oobscans directory: ${err.message}`);
  }

  // Sort newest first
  return scans.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Read the raw content of a saved OOBscan file
 * @param {string} filePath
 * @returns {Promise<string>}
 */
export async function readSavedOobScan(filePathOrFilename) {
  let targetPath = filePathOrFilename;
  if (!path.isAbsolute(targetPath)) {
    const oobscansDir = getVigilanteOobscansDir();
    targetPath = path.join(oobscansDir, filePathOrFilename);
  }
  const content = await fs.readFile(targetPath, 'utf8');
  const parsed = parseOobReportContent(content, path.basename(targetPath));
  return {
    filename: path.basename(targetPath),
    filePath: targetPath,
    ...parsed,
    rawContent: content
  };
}

/**
 * Delete a saved OOBscan file and its signature / hashcat exports
 * @param {string} filePathOrFilename
 */
export async function deleteSavedOobScan(filePathOrFilename) {
  let filePath = filePathOrFilename;
  if (!path.isAbsolute(filePath)) {
    const oobscansDir = getVigilanteOobscansDir();
    filePath = path.join(oobscansDir, filePathOrFilename);
  }
  try {
    await fs.unlink(filePath);
    const hashcatPath = filePath.replace(/\.(jsonl|ndjson)$/, '.hashcat');
    try { await fs.unlink(hashcatPath); } catch {}
    try { await fs.unlink(`${filePath}.asc`); } catch {}
    try { await fs.unlink(`${hashcatPath}.asc`); } catch {}
    logger.info('OOBSCAN:DELETE', `Deleted scan file: ${filePath}`);
    return true;
  } catch (err) {
    logger.error('OOBSCAN:DELETE:ERROR', `Failed to delete ${filePath}: ${err.message}`);
    throw err;
  }
}

/**
 * Export all captured RAKP hashes in a scan to a standalone Hashcat -m 7300 crack file
 * @param {string} [filePathOrOutPath=null] - Path to .jsonl file or output destination
 * @param {string} [maybeOutPath=null]
 * @returns {Promise<{ count: number, hashcatFile: string, filePath: string, hashes: Array<string> }>}
 */
export async function exportRakpHashes(filePathOrOutPath = null, maybeOutPath = null) {
  await ensureVigilanteConfig();
  const oobscansDir = getVigilanteOobscansDir();
  let targetScan = null;
  let destination = null;

  if (filePathOrOutPath && maybeOutPath) {
    targetScan = path.isAbsolute(filePathOrOutPath) ? filePathOrOutPath : path.join(oobscansDir, filePathOrOutPath);
    destination = maybeOutPath;
  } else if (filePathOrOutPath && (filePathOrOutPath.endsWith('.jsonl') || filePathOrOutPath.endsWith('.ndjson'))) {
    targetScan = path.isAbsolute(filePathOrOutPath) ? filePathOrOutPath : path.join(oobscansDir, filePathOrOutPath);
    destination = targetScan.replace(/\.(jsonl|ndjson)$/, '.hashcat');
  } else {
    destination = filePathOrOutPath || path.join(oobscansDir, 'hashes_all.txt');
  }

  const hashes = [];

  if (targetScan) {
    const content = await fs.readFile(targetScan, 'utf8');
    const parsed = parseOobReportContent(content, path.basename(targetScan));
    for (const b of parsed.bmcs) {
      for (const r of b.rakp) {
        const line = r.hashcat || r.hash;
        if (line && !hashes.includes(line)) hashes.push(line);
      }
    }
  } else {
    // Aggregate from all saved scans
    try {
      const files = await fs.readdir(oobscansDir);
      const jsonlFiles = files.filter(f => f.endsWith('.jsonl') || f.endsWith('.ndjson'));
      for (const f of jsonlFiles) {
        try {
          const content = await fs.readFile(path.join(oobscansDir, f), 'utf8');
          const parsed = parseOobReportContent(content, f);
          for (const b of parsed.bmcs) {
            for (const r of b.rakp) {
              const line = r.hashcat || r.hash;
              if (line && !hashes.includes(line)) hashes.push(line);
            }
          }
        } catch {}
      }
    } catch {}
  }

  if (hashes.length > 0) {
    await fs.writeFile(destination, hashes.join('\n') + '\n', 'utf8');
    try {
      await autoSignIfConfigured(destination);
    } catch {
      // Ignore
    }
  }

  return {
    count: hashes.length,
    hashcatFile: destination,
    filePath: destination,
    hashes
  };
}
