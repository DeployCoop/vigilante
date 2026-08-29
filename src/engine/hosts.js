import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execa } from 'execa';

export const HOSTS_FILE_PATH = process.platform === 'win32'
  ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32\\drivers\\etc\\hosts')
  : '/etc/hosts';

export const BLOCK_START = '### BEGIN VIGILANTE MANAGED HOSTS ###';
export const BLOCK_END = '### END VIGILANTE MANAGED HOSTS ###';

/**
 * Generate standard list of domain hostnames for Vigilante
 */
export function getDomainHosts({ domain = 'vigilante.local', subdomains = ['siem', 'vigil', 'vigil-local'] } = {}) {
  const hosts = new Set([domain]);
  for (const sub of subdomains) {
    if (sub) {
      hosts.add(`${sub}.${domain}`);
    }
  }
  return Array.from(hosts);
}

/**
 * Read the current contents of the hosts file
 */
export async function readHostsContent(hostsPath = HOSTS_FILE_PATH) {
  try {
    return await fs.readFile(hostsPath, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      return '';
    }
    throw err;
  }
}

/**
 * Parse host entries into an array of { ip, hostname }
 */
export function parseHostsEntries(content) {
  const entries = [];
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }
    const parts = trimmed.split(/\s+/);
    if (parts.length >= 2) {
      const ip = parts[0];
      for (let i = 1; i < parts.length; i++) {
        entries.push({ ip, hostname: parts[i] });
      }
    }
  }

  return entries;
}

/**
 * Check if the required domain hosts are mapped in /etc/hosts
 */
export async function checkHosts({
  domain = 'vigilante.local',
  hostnames = null,
  ip = '127.0.0.1',
  hostsPath = HOSTS_FILE_PATH
} = {}) {
  const targetHosts = hostnames || getDomainHosts({ domain });
  const content = await readHostsContent(hostsPath);
  const parsed = parseHostsEntries(content);
  const hasManagedBlock = content.includes(BLOCK_START) && content.includes(BLOCK_END);

  const configuredHosts = [];
  const missingHosts = [];

  for (const host of targetHosts) {
    const isMapped = parsed.some(
      entry => entry.hostname.toLowerCase() === host.toLowerCase() && entry.ip === ip
    );
    if (isMapped) {
      configuredHosts.push(host);
    } else {
      missingHosts.push(host);
    }
  }

  return {
    configured: missingHosts.length === 0,
    configuredHosts,
    missingHosts,
    allRequiredHosts: targetHosts,
    hasManagedBlock,
    ip,
    hostsPath
  };
}

/**
 * Generate managed block text for the target hostnames
 */
export function generateManagedBlock(hostnames = [], ip = '127.0.0.1') {
  const lines = [
    BLOCK_START,
    ...hostnames.map(h => `${ip} ${h}`),
    BLOCK_END
  ];
  return lines.join('\n');
}

/**
 * Safely write hosts content directly or via sudo fallback
 */
async function writeHostsFile(newContent, hostsPath = HOSTS_FILE_PATH, { onLog = null } = {}) {
  try {
    // 1. Attempt direct write
    await fs.writeFile(hostsPath, newContent, 'utf8');
    return { method: 'direct' };
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      // 2. Sudo fallback
      if (onLog) {
        onLog(`[hostr] Root permission required to update '${hostsPath}'. Requesting sudo...`);
      }

      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-hosts-'));
      const tmpFile = path.join(tmpDir, 'hosts');
      
      try {
        await fs.writeFile(tmpFile, newContent, 'utf8');
        await execa('sudo', ['cp', tmpFile, hostsPath]);
        return { method: 'sudo' };
      } finally {
        await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => {});
      }
    }
    throw err;
  }
}

/**
 * Synchronize /etc/hosts with the required domain entries (idempotent)
 */
export async function syncHosts({
  domain = 'vigilante.local',
  hostnames = null,
  ip = '127.0.0.1',
  hostsPath = HOSTS_FILE_PATH,
  onLog = null
} = {}) {
  const targetHosts = hostnames || getDomainHosts({ domain });
  const currentContent = await readHostsContent(hostsPath);
  const newBlock = generateManagedBlock(targetHosts, ip);

  let newContent = '';
  const startIndex = currentContent.indexOf(BLOCK_START);
  const endIndex = currentContent.indexOf(BLOCK_END);

  if (startIndex !== -1 && endIndex !== -1 && endIndex > startIndex) {
    // Replace existing managed block
    const before = currentContent.substring(0, startIndex);
    const after = currentContent.substring(endIndex + BLOCK_END.length);
    newContent = `${before.trimEnd()}\n${newBlock}\n${after.trimStart()}`.trimEnd() + '\n';
  } else {
    // Append managed block
    const separator = currentContent.length > 0 && !currentContent.endsWith('\n') ? '\n\n' : '\n';
    newContent = `${currentContent.trimEnd()}${separator}${newBlock}\n`;
  }

  if (currentContent.trim() === newContent.trim()) {
    if (onLog) onLog(`[hostr] Domain entries for *.${domain} are already up to date in '${hostsPath}'.`);
    return {
      updated: false,
      alreadySynced: true,
      hosts: targetHosts,
      hostsPath
    };
  }

  if (onLog) {
    onLog(`[hostr] Writing domain mappings (${targetHosts.join(', ')}) to '${hostsPath}'...`);
  }

  const result = await writeHostsFile(newContent, hostsPath, { onLog });

  if (onLog) {
    onLog(`[hostr] Successfully synchronized '${hostsPath}' via ${result.method}!`);
  }

  return {
    updated: true,
    alreadySynced: false,
    hosts: targetHosts,
    hostsPath,
    method: result.method
  };
}

/**
 * Remove Vigilante managed block from /etc/hosts
 */
export async function removeHosts({
  hostsPath = HOSTS_FILE_PATH,
  onLog = null
} = {}) {
  const currentContent = await readHostsContent(hostsPath);
  const startIndex = currentContent.indexOf(BLOCK_START);
  const endIndex = currentContent.indexOf(BLOCK_END);

  if (startIndex === -1 || endIndex === -1 || endIndex <= startIndex) {
    if (onLog) onLog(`[hostr] No managed Vigilante block found in '${hostsPath}'.`);
    return {
      removed: false,
      reason: 'No managed block found'
    };
  }

  const before = currentContent.substring(0, startIndex).trimEnd();
  const after = currentContent.substring(endIndex + BLOCK_END.length).trimStart();
  const newContent = (before + (after ? '\n' + after : '')).trimEnd() + '\n';

  if (onLog) {
    onLog(`[hostr] Removing Vigilante managed block from '${hostsPath}'...`);
  }

  const result = await writeHostsFile(newContent, hostsPath, { onLog });

  if (onLog) {
    onLog(`[hostr] Successfully removed managed block from '${hostsPath}' via ${result.method}!`);
  }

  return {
    removed: true,
    method: result.method
  };
}
