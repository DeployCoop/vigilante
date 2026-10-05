import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import {
  getVigilanteNetexecDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

export const NETEXEC_PROFILES = [
  {
    id: 'smb-signing',
    name: '🛡️  SMB Signing & NTLM Relay Audit',
    description: 'Verify if SMB signing is required or disabled across network targets',
    protocol: 'smb',
    buildArgs: (target) => ['smb', target, '--gen-relay-list', '/dev/stdout']
  },
  {
    id: 'null-sessions',
    name: '🔓 Anonymous / Null Session Check',
    description: 'Probe for guest and anonymous RPC/SMB null session access',
    protocol: 'smb',
    buildArgs: (target) => ['smb', target, '-u', "''", '-p', "''"]
  },
  {
    id: 'pass-policy',
    name: '📋 Domain Password Policy Audit',
    description: 'Query domain password complexity and lockout threshold policies',
    protocol: 'smb',
    buildArgs: (target, opts = {}) => {
      const a = ['smb', target, '--pass-pol'];
      if (opts.user) a.push('-u', opts.user);
      if (opts.password) a.push('-p', opts.password);
      return a;
    }
  },
  {
    id: 'protocol-sweep',
    name: '🌐 Multi-Protocol Service Audit',
    description: 'Enumerate SMB, SSH, LDAP, and WinRM support and OS builds',
    protocol: 'all',
    buildArgs: (target) => ['smb', target]
  }
];

/**
 * Check whether NetExec or CrackMapExec is installed
 * @returns {Promise<{ installed: boolean, bin: string, runner: string }>}
 */
export async function checkNetexecInstalled() {
  for (const bin of ['netexec', 'nxc', 'crackmapexec']) {
    try {
      await execa(bin, ['--version'], { timeout: 3000 });
      return { installed: true, bin, runner: 'host' };
    } catch {
      // try next
    }
  }

  try {
    await execa('docker', ['image', 'inspect', 'netexec/netexec:latest'], { timeout: 3000 });
    return { installed: true, bin: 'docker', runner: 'docker' };
  } catch {
    return { installed: false, bin: 'none', runner: 'native-fallback' };
  }
}

/**
 * Native SMB/LDAP/WinRM port reachability fallback
 * @param {string} target 
 * @returns {Promise<Array<{ protocol: string, port: number, open: boolean }>>}
 */
export async function probeAuthProtocolsNative(target) {
  const ports = [
    { protocol: 'SMB', port: 445 },
    { protocol: 'LDAP', port: 389 },
    { protocol: 'SSH', port: 22 },
    { protocol: 'WinRM', port: 5985 },
    { protocol: 'MSSQL', port: 1433 }
  ];

  const results = [];
  for (const p of ports) {
    const isOpen = await new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(800);
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      socket.on('timeout', () => {
        socket.destroy();
        resolve(false);
      });
      socket.on('error', () => {
        socket.destroy();
        resolve(false);
      });
      socket.connect(p.port, target);
    });

    results.push({ protocol: p.protocol, port: p.port, open: isOpen });
  }

  return results;
}

/**
 * Parse NetExec output lines
 * @param {string} rawOutput 
 * @returns {Array<object>}
 */
export function parseNetexecOutput(rawOutput) {
  if (!rawOutput || typeof rawOutput !== 'string') return [];
  const findings = [];
  const lines = rawOutput.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Pattern: PROTOCOL IP PORT HOSTNAME [status] message
    const match = trimmed.match(/^([A-Z0-9]+)\s+([0-9.]+)\s+(\d+)\s+([^\s]+)?\s*(.*)$/);
    if (match) {
      const protocol = match[1];
      const ip = match[2];
      const port = Number(match[3]);
      const hostname = match[4] || '';
      const detail = match[5] || '';

      const signingMatch = detail.match(/signing:(True|False|required|disabled)/i);
      const smbSigning = signingMatch ? signingMatch[1] : 'unknown';

      findings.push({
        protocol,
        ip,
        port,
        hostname,
        detail,
        smbSigning,
        isVulnerableToRelay: /signing:(False|disabled)/i.test(detail)
      });
    }
  }

  return findings;
}

/**
 * Run a defensive network protocol / credential audit
 * @param {string} target 
 * @param {string} [profileId='smb-signing'] 
 * @param {object} [opts={}]
 * @returns {Promise<object>}
 */
export async function runNetexecAudit(target, profileId = 'smb-signing', opts = {}) {
  await ensureVigilanteConfig();
  const netexecDir = getVigilanteNetexecDir();
  const profile = NETEXEC_PROFILES.find((p) => p.id === profileId) || NETEXEC_PROFILES[0];
  const tool = await checkNetexecInstalled();

  const timestamp = new Date().toISOString();
  const scanId = `netexec_${target.replace(/[^a-zA-Z0-9_.-]/g, '_')}_${Date.now()}`;
  let rawOutput = '';
  let findings = [];

  if (tool.runner === 'host') {
    try {
      const res = await execa(tool.bin, profile.buildArgs(target, opts));
      rawOutput = res.stdout;
      findings = parseNetexecOutput(rawOutput);
    } catch (err) {
      rawOutput = (err.stdout || '') + '\n' + (err.stderr || '');
      findings = parseNetexecOutput(rawOutput);
    }
  } else if (tool.runner === 'docker') {
    try {
      const res = await execa('docker', ['run', '--rm', 'netexec/netexec:latest', ...profile.buildArgs(target, opts)]);
      rawOutput = res.stdout;
      findings = parseNetexecOutput(rawOutput);
    } catch (err) {
      rawOutput = err.stdout || '';
      findings = parseNetexecOutput(rawOutput);
    }
  } else {
    // Native protocol reachability fallback
    const reachable = await probeAuthProtocolsNative(target);
    findings = reachable.filter((r) => r.open).map((r) => ({
      protocol: r.protocol,
      ip: target,
      port: r.port,
      hostname: target,
      detail: `Native probe: ${r.protocol} listening on port ${r.port}`,
      smbSigning: 'unknown',
      isVulnerableToRelay: false
    }));
    rawOutput = JSON.stringify(findings, null, 2);
  }

  const record = {
    id: scanId,
    target,
    profile: profile.id,
    timestamp,
    findings,
    rawOutput
  };

  const filePath = path.join(netexecDir, `${scanId}.json`);
  await fs.writeFile(filePath, JSON.stringify(record, null, 2), 'utf8');

  // GPG sign if configured
  await autoSignIfConfigured(filePath);

  // Evidence file
  try {
    await saveEvidenceFile(target, `${scanId}.json`, JSON.stringify(record, null, 2), {
      source: 'netexec',
      profile: profile.id
    });
  } catch (err) {
    logger.warn('NETEXEC', `Could not save evidence file: ${err.message}`);
  }

  return { ...record, filePath };
}

/**
 * List saved NetExec scans
 * @returns {Promise<Array<object>>}
 */
export async function listSavedNetexecAudits() {
  await ensureVigilanteConfig();
  const netexecDir = getVigilanteNetexecDir();
  try {
    const files = await fs.readdir(netexecDir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json') && !f.endsWith('.sig') && !f.endsWith('.asc')) {
        const fullPath = path.join(netexecDir, f);
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          const parsed = JSON.parse(content);
          results.push({
            id: parsed.id || f.replace('.json', ''),
            target: parsed.target || 'unknown',
            profile: parsed.profile || 'smb-signing',
            timestamp: parsed.timestamp || '',
            findingsCount: (parsed.findings || []).length,
            filePath: fullPath
          });
        } catch {
          // ignore corrupted files
        }
      }
    }
    return results.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
  } catch {
    return [];
  }
}
