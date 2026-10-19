import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import net from 'node:net';
import { execa } from 'execa';
import { shQuote, isValidHostname } from './config.js';

export const HOSTS_FILE_PATH = process.platform === 'win32'
  ? path.join(process.env.SystemRoot || 'C:\\Windows', 'System32\\drivers\\etc\\hosts')
  : '/etc/hosts';

export const BLOCK_START = '### BEGIN VIGILANTE MANAGED HOSTS ###';
export const BLOCK_END = '### END VIGILANTE MANAGED HOSTS ###';

/**
 * Generate standard list of domain hostnames for Vigilante
 */
export function getDomainHosts({ domain = 'vigilante.local', subdomains = ['siem', 'vigil', 'vigil-local', 'kctf', 'ctf', 'openvas', 'gvm', 'wazuh', 'flamingo', 'falco', 'suricata', 'zeek', 'zap', 'bloodhound'] } = {}) {
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
  // Block lines are written verbatim into the hosts file (as root on the
  // sudo path): an unvalidated hostname containing a newline would inject
  // arbitrary additional hosts entries. Validate, never sanitize silently.
  if (!net.isIP(ip)) {
    throw new Error(`Invalid IP address '${ip}' for hosts block`);
  }
  for (const h of hostnames) {
    if (!isValidHostname(h)) {
      throw new Error(`Invalid hostname '${h}': expected a dotted hostname without whitespace`);
    }
  }
  const lines = [
    BLOCK_START,
    ...hostnames.map(h => `${ip} ${h}`),
    BLOCK_END
  ];
  return lines.join('\n');
}

/**
 * Remove complete Vigilante blocks and malformed marker lines without ever
 * discarding ordinary hosts entries. A BEGIN marker with no matching END
 * does not establish where a managed block ends, so the lines after it are
 * preserved rather than being swallowed by a later block's END marker.
 */
function stripManagedHostsBlocks(content) {
  const lines = [];
  let pendingBlockLines = null;
  let firstBlockIndex = null;
  let removedBlocks = 0;
  let malformedMarkers = 0;

  for (const line of String(content).split('\n')) {
    const trimmed = line.trim();

    if (pendingBlockLines !== null) {
      if (trimmed === BLOCK_END) {
        removedBlocks++;
        pendingBlockLines = null;
      } else if (trimmed === BLOCK_START) {
        // A second BEGIN before an END means the previous block was never
        // terminated. Preserve its would-be contents as ordinary lines and
        // start a new candidate block at this marker.
        lines.push(...pendingBlockLines);
        malformedMarkers++;
        pendingBlockLines = [];
      } else {
        pendingBlockLines.push(line);
      }
      continue;
    }

    if (trimmed === BLOCK_START) {
      if (firstBlockIndex === null) firstBlockIndex = lines.length;
      pendingBlockLines = [];
    } else if (trimmed === BLOCK_END) {
      malformedMarkers++;
    } else {
      lines.push(line);
    }
  }

  if (pendingBlockLines !== null) {
    // Unterminated block: remove only the marker, never the following lines.
    lines.push(...pendingBlockLines);
    malformedMarkers++;
  }

  return { lines, firstBlockIndex, removedBlocks, malformedMarkers };
}

/**
 * Parse the entries of all well-formed managed blocks into
 * [{ ip, hostname }]. Used to preserve other instances' mappings when
 * one domain is synced or removed: the block is shared, so a sync must
 * merge rather than replace, and a removal must be domain-scoped.
 */
export function extractManagedEntries(content) {
  const entries = [];
  // Only WELL-FORMED blocks contribute entries (same rule as
  // stripManagedHostsBlocks): lines after an unterminated BEGIN marker
  // are user content, not managed entries — treating them as managed
  // would absorb them into the block on the next sync.
  let pending = null;
  const commitPending = () => {
    for (const l of pending) {
      const m = l.trim().match(/^(\S+)\s+(\S+)$/);
      if (m) entries.push({ ip: m[1], hostname: m[2] });
    }
    pending = null;
  };
  for (const line of String(content).split('\n')) {
    const trimmed = line.trim();
    if (pending !== null) {
      if (trimmed === BLOCK_END) commitPending();
      else if (trimmed === BLOCK_START) pending = []; // previous block never terminated
      else pending.push(line);
      continue;
    }
    if (trimmed === BLOCK_START) pending = [];
  }
  return entries;
}

function hostnameBelongsToDomain(hostname, domain) {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function renderHostsLines(lines) {
  const rendered = lines.join('\n').trimEnd();
  return rendered ? `${rendered}\n` : '\n';
}

async function writeHostsFile(newContent, hostsPath = HOSTS_FILE_PATH, { onLog = null } = {}) {
  try {
    await fs.writeFile(hostsPath, newContent, 'utf8');
    return { method: 'direct' };
  } catch (err) {
    if (err.code === 'EACCES' || err.code === 'EPERM') {
      if (onLog) {
        onLog(`[hostr] Root permission required to update '${hostsPath}'. Requesting sudo...`);
      }

      const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-hosts-'));
      const tmpFile = path.join(tmpDir, 'hosts');
      
      try {
        await fs.writeFile(tmpFile, newContent, 'utf8');
        
        let hasPasswordlessSudo = false;
        try {
          await execa('sudo', ['-n', 'true'], { timeout: 3000 });
          hasPasswordlessSudo = true;
        } catch {}

        if (hasPasswordlessSudo) {
          await execa('sudo', ['-n', 'cp', tmpFile, hostsPath], { timeout: 5000 });
        } else {
          // sudo-prompt runs its command through a shell (as root), so the
          // paths are single-quote escaped: a quote or $(...) in a
          // caller-supplied hostsPath must stay inert data.
          const sudo = await import('sudo-prompt');
          await new Promise((resolve, reject) => {
            sudo.exec(`cp ${shQuote(tmpFile)} ${shQuote(hostsPath)}`, { name: 'Vigilante CLI' }, (error, stdout, stderr) => {
              if (error) reject(error);
              else resolve(stdout);
            });
          });
        }
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
  // The managed block is shared by every instance: keep entries that
  // belong to OTHER domains (with their recorded IPs) and replace only
  // this domain's slice. Previously a sync rebuilt the block from the
  // current domain alone, evicting every other instance's mappings.
  const preserved = extractManagedEntries(currentContent)
    .filter(e => !hostnameBelongsToDomain(e.hostname, domain) && !targetHosts.includes(e.hostname));
  const newBlock = [
    BLOCK_START,
    ...targetHosts.map(h => `${ip} ${h}`),
    ...preserved.map(e => `${e.ip} ${e.hostname}`),
    BLOCK_END
  ].join('\n');

  // Replace every well-formed managed block with one fresh block at the
  // first block's location. Malformed markers are repaired without deleting
  // the ordinary entries that followed an unterminated BEGIN marker.
  const stripped = stripManagedHostsBlocks(currentContent);
  const baseLines = [...stripped.lines];
  while (baseLines.length > 0 && baseLines[baseLines.length - 1].trim() === '') {
    baseLines.pop();
  }
  const insertIndex = stripped.firstBlockIndex === null
    ? baseLines.length
    : Math.min(stripped.firstBlockIndex, baseLines.length);
  baseLines.splice(insertIndex, 0, ...newBlock.split('\n'));
  const newContent = renderHostsLines(baseLines);

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
  domain = null,
  hostsPath = HOSTS_FILE_PATH,
  onLog = null
} = {}) {
  const currentContent = await readHostsContent(hostsPath);

  if (domain) {
    // Domain-scoped removal: drop only this domain's entries and keep
    // the block (with the other instances' mappings) intact. Without a
    // domain the whole managed block is removed, as before.
    const allEntries = extractManagedEntries(currentContent);
    const removedEntries = allEntries.filter(e => hostnameBelongsToDomain(e.hostname, domain));
    if (removedEntries.length === 0) {
      if (onLog) onLog(`[hostr] No managed entries for *.${domain} found in '${hostsPath}'.`);
      return { removed: false, reason: `No managed entries for domain '${domain}'`, domain };
    }
    const remaining = allEntries.filter(e => !hostnameBelongsToDomain(e.hostname, domain));
    const strippedScoped = stripManagedHostsBlocks(currentContent);
    const baseLines = [...strippedScoped.lines];
    while (baseLines.length > 0 && baseLines[baseLines.length - 1].trim() === '') {
      baseLines.pop();
    }
    if (remaining.length > 0) {
      const insertIndex = strippedScoped.firstBlockIndex === null
        ? baseLines.length
        : Math.min(strippedScoped.firstBlockIndex, baseLines.length);
      const block = [BLOCK_START, ...remaining.map(e => `${e.ip} ${e.hostname}`), BLOCK_END];
      baseLines.splice(insertIndex, 0, ...block);
    }
    const result = await writeHostsFile(renderHostsLines(baseLines), hostsPath, { onLog });
    if (onLog) onLog(`[hostr] Removed ${removedEntries.length} managed entr${removedEntries.length === 1 ? 'y' : 'ies'} for *.${domain} from '${hostsPath}' via ${result.method}.`);
    return {
      removed: true,
      method: result.method,
      domain,
      removedEntries: removedEntries.length,
      remainingEntries: remaining.length
    };
  }

  const stripped = stripManagedHostsBlocks(currentContent);

  if (stripped.removedBlocks === 0 && stripped.malformedMarkers === 0) {
    if (onLog) onLog(`[hostr] No managed Vigilante block found in '${hostsPath}'.`);
    return {
      removed: false,
      reason: 'No managed block found'
    };
  }

  const newContent = renderHostsLines(stripped.lines);

  if (onLog) {
    onLog(`[hostr] Removing Vigilante managed block from '${hostsPath}'...`);
  }

  const result = await writeHostsFile(newContent, hostsPath, { onLog });

  if (onLog) {
    onLog(`[hostr] Successfully removed managed block from '${hostsPath}' via ${result.method}!`);
  }

  return {
    removed: true,
    method: result.method,
    removedBlocks: stripped.removedBlocks,
    repairedMarkers: stripped.malformedMarkers
  };
}
