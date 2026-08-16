import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getVigilanteNmapsDir, ensureVigilanteConfig } from './config.js';
import { logger } from '../utils/logger.js';

export const SCAN_PROFILES = [
  {
    id: 'sweep',
    name: '🗺️  Network Ping Sweep / Host Discovery',
    description: 'Discover all live hosts and active IP addresses across a CIDR network block (-sn -T4)',
    args: ['-sn', '-T4'],
    isSubnetProfile: true
  },
  {
    id: 'net-quick',
    name: '⚡ Network Sweep & Top Ports',
    description: 'Sweep CIDR for active hosts and scan top 100 ports (-T4 -F)',
    args: ['-T4', '-F'],
    isSubnetProfile: true
  },
  {
    id: 'net-service',
    name: '🔍 Network Service & Version Mapping',
    description: 'Scan CIDR hosts for service versions on top 20 ports (-sV -T4 --top-ports 20)',
    args: ['-sV', '-T4', '--top-ports', '20'],
    isSubnetProfile: true
  },
  {
    id: 'quick',
    name: '⚡ Quick Scan (Single Host)',
    description: 'Fast scan of top 100 common ports (-T4 -F)',
    args: ['-T4', '-F']
  },
  {
    id: 'service',
    name: '🔍 Service & Version Detection',
    description: 'Probe open ports for service names and banner versions (-sV -T4)',
    args: ['-sV', '-T4']
  },
  {
    id: 'vuln',
    name: '🛡️  Vulnerability & Threat Audit',
    description: 'Run standard NSE security and CVE vulnerability scripts (-sV --script=vuln)',
    args: ['-sV', '--script=vuln']
  },
  {
    id: 'full',
    name: '🌐 Full Port Scan',
    description: 'Comprehensive scan across all 65,535 TCP ports (-p- -T4)',
    args: ['-p-', '-T4']
  },
  {
    id: 'custom',
    name: '⚙️  Custom Arguments',
    description: 'User-specified nmap flags and parameters',
    args: []
  }
];

/**
 * Check if nmap binary is installed and executable
 * @returns {Promise<{ installed: boolean, version: string, error?: string }>}
 */
export async function checkNmapInstalled() {
  try {
    const { stdout } = await execa('nmap', ['--version']);
    const match = stdout.match(/Nmap version ([^\s]+)/i);
    const version = match ? match[1] : 'installed';
    return { installed: true, version };
  } catch (err) {
    return {
      installed: false,
      version: null,
      error: `nmap not found in PATH (${err.message}). Install via 'brew install nmap' or 'sudo apt install nmap'.`
    };
  }
}

/**
 * Calculate the base network CIDR from an IPv4 address and subnet mask
 * @param {string} ip
 * @param {string} netmask
 * @returns {string|null}
 */
export function calculateSubnetCidr(ip, netmask) {
  if (!ip || !netmask) return null;
  const ipParts = ip.split('.').map(Number);
  const maskParts = netmask.split('.').map(Number);
  if (ipParts.length !== 4 || maskParts.length !== 4) return null;

  const netParts = ipParts.map((part, i) => part & maskParts[i]);
  let bits = 0;
  for (const part of maskParts) {
    bits += (part.toString(2).match(/1/g) || []).length;
  }

  return `${netParts.join('.')}/${bits}`;
}

/**
 * Auto-detect local network subnets and standard cluster CIDR ranges
 * @returns {Array<{ label: string, cidr: string, iface?: string, ip?: string }>}
 */
export function detectNetworkSubnets() {
  const subnets = [];
  try {
    const interfaces = os.networkInterfaces();
    for (const [ifaceName, addrs] of Object.entries(interfaces)) {
      if (!addrs) continue;
      for (const addr of addrs) {
        if (addr.family === 'IPv4' && !addr.internal) {
          const cidr = calculateSubnetCidr(addr.address, addr.netmask);
          if (cidr && !subnets.some(s => s.cidr === cidr)) {
            subnets.push({
              label: `Local Subnet (${ifaceName}: ${addr.address})`,
              cidr,
              iface: ifaceName,
              ip: addr.address
            });
          }
        }
      }
    }
  } catch (err) {
    logger.warn('NMAP:SUBNETS', `Failed to detect network interfaces: ${err.message}`);
  }

  // Pre-configured cluster and network subnets
  const defaults = [
    { label: 'Cluster Pod CIDR (k3s default)', cidr: '10.42.0.0/16' },
    { label: 'Cluster Service CIDR (k3s default)', cidr: '10.43.0.0/16' },
    { label: 'Docker / k3d Bridge Subnet', cidr: '172.17.0.0/16' },
    { label: 'Private Subnet (Example)', cidr: '10.0.1.0/24' }
  ];

  for (const item of defaults) {
    if (!subnets.some(s => s.cidr === item.cidr)) {
      subnets.push(item);
    }
  }

  return subnets;
}

/**
 * Get the XDG directory where nmap scans are stored
 * @returns {string}
 */
export function getNmapsDir() {
  return getVigilanteNmapsDir();
}

/**
 * Parse an Nmap report text into structured host and port metadata
 * @param {string} content
 * @param {string} filename
 * @returns {Object}
 */
export function parseNmapReportContent(content, filename = '') {
  const isCidr = content.includes('IP addresses') || filename.includes('_') || filename.includes('%2F');
  
  // Parse overall summary line: Nmap done: 256 IP addresses (4 hosts up) scanned in 2.15 seconds
  const doneMatch = content.match(/Nmap done:\s+(\d+)\s+IP addresses?\s+\((\d+)\s+hosts?\s+up\)\s+scanned in\s+([\d.]+)\s+seconds/i);
  const totalScanned = doneMatch ? parseInt(doneMatch[1], 10) : 1;
  const hostsUp = doneMatch ? parseInt(doneMatch[2], 10) : 0;
  const durationSec = doneMatch ? parseFloat(doneMatch[3]) : 0;

  // Split report into host sections
  const hostSections = content.split(/Nmap scan report for /g).filter(Boolean);
  const discoveredHosts = [];
  let totalOpenPorts = 0;

  for (const section of hostSections) {
    if (!section.trim() || section.startsWith('Starting Nmap')) continue;

    const lines = section.split('\n');
    const headerLine = lines[0].trim();
    
    // Parse host and IP: e.g. "localhost (127.0.0.1)" or "10.0.1.5"
    let hostName = headerLine;
    let ipAddress = headerLine;
    const ipMatch = headerLine.match(/^([^\s]+)\s+\(([\d.]+)\)/);
    if (ipMatch) {
      hostName = ipMatch[1];
      ipAddress = ipMatch[2];
    } else {
      const bareIpMatch = headerLine.match(/^([\d.]+)/);
      if (bareIpMatch) {
        ipAddress = bareIpMatch[1];
      }
    }

    // Check if host is up
    const isUp = section.includes('Host is up');
    const latencyMatch = section.match(/Host is up \(([\d.]+s) latency\)/);
    const latency = latencyMatch ? latencyMatch[1] : null;

    // Parse open ports in this section
    const openPorts = [];
    for (const line of lines) {
      const portMatch = line.match(/^(\d+\/\w+)\s+(open)\s+([^\s]+)(?:\s+(.*))?/);
      if (portMatch) {
        openPorts.push({
          port: portMatch[1],
          state: portMatch[2],
          service: portMatch[3],
          version: (portMatch[4] || '').trim()
        });
        totalOpenPorts++;
      }
    }

    if (isUp || openPorts.length > 0) {
      discoveredHosts.push({
        host: hostName,
        ip: ipAddress,
        isUp,
        latency,
        openPortsCount: openPorts.length,
        openPorts
      });
    }
  }

  // Extract target from filename or first host
  const targetMatch = content.match(/Nmap scan report for ([^\n\r]+)/i);
  const target = targetMatch ? targetMatch[1].trim() : extractTargetFromFilename(filename);

  // Formulate human summary
  let summary = '';
  if (totalScanned > 1 || isCidr || discoveredHosts.length > 1) {
    summary = `${discoveredHosts.length || hostsUp} live hosts found across network (${totalOpenPorts} open ports total)`;
  } else if (discoveredHosts.length === 1 && discoveredHosts[0].openPortsCount > 0) {
    const ports = discoveredHosts[0].openPorts.map(p => `${p.port} (${p.service})`);
    summary = `${ports.length} open ports: ${ports.slice(0, 4).join(', ')}${ports.length > 4 ? '...' : ''}`;
  } else if (content.includes('0 hosts up')) {
    summary = 'Network / Host down (0 hosts up)';
  } else {
    summary = 'Scan completed (no open ports detected)';
  }

  return {
    target,
    isCidr: totalScanned > 1 || isCidr,
    totalScanned,
    hostsUp: discoveredHosts.length || hostsUp,
    durationSec,
    totalOpenPorts,
    discoveredHosts,
    summary
  };
}

/**
 * List all historical saved nmap scan files in $XDG_CONFIG_HOME/vigilante/nmaps/
 * @returns {Promise<Array<Object>>}
 */
export async function listSavedNmapScans() {
  await ensureVigilanteConfig();
  const nmapsDir = getVigilanteNmapsDir();
  const scans = [];

  try {
    const files = await fs.readdir(nmapsDir);
    const nmapFiles = files.filter(f => f.endsWith('.nmap') || f.endsWith('.txt'));

    for (const file of nmapFiles) {
      const filePath = path.join(nmapsDir, file);
      try {
        const stats = await fs.stat(filePath);
        const content = await fs.readFile(filePath, 'utf8');

        const baseName = file.replace(/\.(nmap|txt)$/, '');
        const xmlPath = path.join(nmapsDir, `${baseName}.xml`);
        const hasXml = fsSync.existsSync(xmlPath);

        const parsed = parseNmapReportContent(content, file);

        scans.push({
          id: baseName,
          filename: file,
          filePath,
          xmlPath: hasXml ? xmlPath : null,
          target: parsed.target,
          isCidr: parsed.isCidr,
          summary: parsed.summary,
          hostsUp: parsed.hostsUp,
          totalScanned: parsed.totalScanned,
          totalOpenPorts: parsed.totalOpenPorts,
          discoveredHosts: parsed.discoveredHosts,
          openPortsCount: parsed.totalOpenPorts,
          sizeBytes: stats.size,
          mtime: stats.mtime,
          createdAt: stats.birthtime || stats.mtime
        });
      } catch (err) {
        logger.warn('NMAP:LIST', `Failed to parse scan file ${file}: ${err.message}`);
      }
    }
  } catch (err) {
    logger.warn('NMAP:LIST', `Failed to read nmaps directory: ${err.message}`);
  }

  // Sort newest first
  return scans.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Helper to extract target from standard filename
 */
function extractTargetFromFilename(filename) {
  const clean = filename.replace(/^nmap-/, '').replace(/-\d+\.(nmap|txt)$/, '');
  return clean ? clean.replace(/_/g, '/') : 'unknown-target';
}

/**
 * Execute an nmap scan against a single IP, hostname, or CIDR network block
 * @param {Object} options
 * @param {string} options.target - IP, CIDR (e.g. 10.0.1.0/24), hostname, or domain to scan
 * @param {string} [options.profile='quick'] - Scan profile id
 * @param {Array<string>} [options.customArgs=[]] - Additional nmap arguments
 * @param {Function} [options.onLog] - Streaming log callback
 * @returns {Promise<Object>}
 */
export async function runNmapScan({
  target = '127.0.0.1',
  profile = 'quick',
  customArgs = [],
  onLog = null
} = {}) {
  await ensureVigilanteConfig();
  const nmapsDir = getVigilanteNmapsDir();
  const check = await checkNmapInstalled();
  if (!check.installed) {
    throw new Error(check.error);
  }

  const cleanTarget = (target || '127.0.0.1').trim();
  // Safe filename replacing / and : with _
  const safeTargetName = cleanTarget.replace(/[/:]/g, '_').replace(/[^a-zA-Z0-9._-]/g, '');
  const timestamp = Date.now();
  const baseName = `nmap-${safeTargetName}-${timestamp}`;
  const nmapFilePath = path.join(nmapsDir, `${baseName}.nmap`);
  const xmlFilePath = path.join(nmapsDir, `${baseName}.xml`);

  const profileDef = SCAN_PROFILES.find(p => p.id === profile) || SCAN_PROFILES[0];
  const profileArgs = profile === 'custom' ? customArgs : profileDef.args;

  const nmapArgs = [
    ...profileArgs,
    '-oN',
    nmapFilePath,
    '-oX',
    xmlFilePath,
    cleanTarget
  ];

  logger.info('NMAP:START', `Running scan: nmap ${nmapArgs.join(' ')}`);
  if (onLog) {
    onLog(`🎯 Starting Nmap [${profileDef.name}] against: ${cleanTarget}`);
    onLog(`⚙️  Command: nmap ${nmapArgs.join(' ')}`);
    onLog(`💾 Destination: ${nmapFilePath}`);
  }

  const startTime = Date.now();
  let fullOutput = '';

  try {
    const subprocess = execa('nmap', nmapArgs);

    if (subprocess.stdout) {
      subprocess.stdout.on('data', (chunk) => {
        const text = chunk.toString();
        fullOutput += text;
        if (onLog) {
          const lines = text.split('\n').filter(Boolean);
          for (const line of lines) {
            onLog(line);
          }
        }
      });
    }

    if (subprocess.stderr) {
      subprocess.stderr.on('data', (chunk) => {
        const text = chunk.toString();
        logger.warn('NMAP:STDERR', text);
      });
    }

    await subprocess;
    const durationMs = Date.now() - startTime;

    if (onLog) {
      onLog(`✔ Nmap scan finished in ${(durationMs / 1000).toFixed(2)}s!`);
      onLog(`📁 Saved results to: ${nmapFilePath}`);
    }

    logger.info('NMAP:SUCCESS', `Scan completed for ${cleanTarget} in ${durationMs}ms`);

    const parsed = parseNmapReportContent(fullOutput, `${baseName}.nmap`);

    return {
      id: baseName,
      target: cleanTarget,
      isCidr: parsed.isCidr,
      profile: profileDef.id,
      profileName: profileDef.name,
      nmapFilePath,
      xmlFilePath,
      durationMs,
      output: fullOutput,
      parsed
    };
  } catch (err) {
    logger.error('NMAP:ERROR', `Scan failed: ${err.message}`, err);
    throw new Error(`Nmap scan failed: ${err.message}`);
  }
}

/**
 * Delete a saved scan and its accompanying XML file
 * @param {string} filePath - Path to .nmap file
 */
export async function deleteSavedScan(filePath) {
  try {
    await fs.unlink(filePath);
    const xmlPath = filePath.replace(/\.(nmap|txt)$/, '.xml');
    try {
      await fs.unlink(xmlPath);
    } catch {
      // Ignore
    }
    logger.info('NMAP:DELETE', `Deleted scan file: ${filePath}`);
    return true;
  } catch (err) {
    logger.error('NMAP:DELETE:ERROR', `Failed to delete ${filePath}: ${err.message}`);
    throw err;
  }
}

/**
 * Read the contents of a saved scan
 * @param {string} filePath
 * @returns {Promise<string>}
 */
export async function readSavedScan(filePath) {
  return await fs.readFile(filePath, 'utf8');
}
