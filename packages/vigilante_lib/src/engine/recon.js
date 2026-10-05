import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import net from 'node:net';
import {
  getVigilanteReconDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { detectNetworkSubnets } from './nmap.js';
import { logger } from '../utils/logger.js';

export const RECON_PROFILES = [
  {
    id: 'fast-ports',
    name: '⚡ Fast Port Discovery (Naabu)',
    description: 'High-speed asynchronous port discovery across top 100 common ports',
    tool: 'naabu',
    args: ['-top-ports', '100', '-json'],
    buildArgs: (target, opts = {}) => {
      const a = ['-host', target, '-top-ports', opts.topPorts ? String(opts.topPorts) : '100', '-json'];
      if (opts.rate) a.push('-rate', String(opts.rate));
      if (opts.timeout) a.push('-timeout', String(opts.timeout));
      return a;
    }
  },
  {
    id: 'full-ports',
    name: '🌐 Full Range Port Sweep (Naabu)',
    description: 'High-performance scan across full 1-65535 port range',
    tool: 'naabu',
    args: ['-p', '-', '-json'],
    buildArgs: (target, opts = {}) => {
      const a = ['-host', target, '-p', '-', '-json'];
      if (opts.rate) a.push('-rate', String(opts.rate));
      return a;
    }
  },
  {
    id: 'web-probe',
    name: '🌐 Web Service & Tech Stack Probe (Httpx)',
    description: 'Identify live HTTP/HTTPS services, TLS certs, status codes, and tech stacks',
    tool: 'httpx',
    args: ['-title', '-tech-detect', '-status-code', '-json'],
    buildArgs: (target, opts = {}) => {
      const a = ['-u', target, '-title', '-tech-detect', '-status-code', '-tls-grab', '-json'];
      if (opts.ports) a.push('-ports', String(opts.ports));
      if (opts.threads) a.push('-threads', String(opts.threads));
      return a;
    }
  },
  {
    id: 'deep-recon',
    name: '🔬 Combined Port Scan + Web Tech Fingerprint',
    description: 'Pipeline Naabu port discovery directly into Httpx for deep service fingerprinting',
    tool: 'combined',
    args: []
  }
];

/**
 * Check whether Naabu and Httpx binaries or containers are available
 * @returns {Promise<{ naabu: { installed: boolean, version: string, runner: string }, httpx: { installed: boolean, version: string, runner: string } }>}
 */
export async function checkReconToolsInstalled() {
  const result = {
    naabu: { installed: false, version: '', runner: 'none' },
    httpx: { installed: false, version: '', runner: 'none' }
  };

  // Check Naabu host binary
  try {
    const res = await execa('naabu', ['-version'], { timeout: 3000 });
    result.naabu = {
      installed: true,
      version: res.stdout.split('\n')[0] || 'installed',
      runner: 'host'
    };
  } catch {
    // Check container runner fallback
    try {
      await execa('docker', ['image', 'inspect', 'projectdiscovery/naabu:latest'], { timeout: 3000 });
      result.naabu = { installed: true, version: 'docker (projectdiscovery/naabu)', runner: 'docker' };
    } catch {
      result.naabu = { installed: false, version: 'Node.js Socket Fallback', runner: 'native-fallback' };
    }
  }

  // Check Httpx host binary
  try {
    const res = await execa('httpx', ['-version'], { timeout: 3000 });
    result.httpx = {
      installed: true,
      version: res.stdout.split('\n')[0] || 'installed',
      runner: 'host'
    };
  } catch {
    try {
      await execa('docker', ['image', 'inspect', 'projectdiscovery/httpx:latest'], { timeout: 3000 });
      result.httpx = { installed: true, version: 'docker (projectdiscovery/httpx)', runner: 'docker' };
    } catch {
      result.httpx = { installed: false, version: 'Node.js Fetch Fallback', runner: 'native-fallback' };
    }
  }

  return result;
}

/**
 * Native Node.js TCP port probe fallback (when external Naabu binary is missing)
 * @param {string} host 
 * @param {number[]} ports 
 * @param {number} [timeoutMs=800]
 * @returns {Promise<Array<{ host: string, ip: string, port: number }>>}
 */
export async function probePortsNative(host, ports = [80, 443, 22, 53, 8080, 8443, 3000], timeoutMs = 800) {
  const open = [];
  const promises = ports.map((port) => {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      socket.setTimeout(timeoutMs);

      socket.on('connect', () => {
        open.push({ host, ip: socket.remoteAddress || host, port });
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

      socket.connect(port, host);
    });
  });

  await Promise.all(promises);
  return open.sort((a, b) => a.port - b.port);
}

/**
 * Native Node.js HTTP/HTTPS service probe fallback (when Httpx is missing)
 * @param {string} targetUrl 
 * @returns {Promise<object>}
 */
export async function probeHttpNative(targetUrl) {
  const normUrl = targetUrl.startsWith('http://') || targetUrl.startsWith('https://')
    ? targetUrl
    : `http://${targetUrl}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3500);
    const res = await fetch(normUrl, {
      method: 'GET',
      signal: controller.signal,
      headers: { 'User-Agent': 'Vigilante-Recon/1.0' }
    });
    clearTimeout(timeout);

    const bodyText = await res.text();
    const titleMatch = bodyText.match(/<title[^>]*>([^<]+)<\/title>/i);
    const title = titleMatch ? titleMatch[1].trim() : '';
    const server = res.headers.get('server') || 'unknown';

    return {
      url: normUrl,
      host: new URL(normUrl).hostname,
      port: Number(new URL(normUrl).port || (normUrl.startsWith('https') ? 443 : 80)),
      title,
      webserver: server,
      status_code: res.status,
      tech: server !== 'unknown' ? [server] : [],
      failed: false
    };
  } catch (err) {
    return {
      url: normUrl,
      host: targetUrl,
      status_code: 0,
      failed: true,
      error: err.message
    };
  }
}

/**
 * Parse Naabu NDJSON output stream
 * @param {string} rawOutput 
 * @returns {Array<{ host: string, ip: string, port: number }>>}
 */
export function parseNaabuOutput(rawOutput) {
  if (!rawOutput || typeof rawOutput !== 'string') return [];
  const results = [];
  const lines = rawOutput.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // Check if JSON
    if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
      try {
        const parsed = JSON.parse(trimmed);
        results.push({
          host: parsed.host || parsed.ip,
          ip: parsed.ip || parsed.host,
          port: Number(parsed.port)
        });
        continue;
      } catch {
        // Fall back to plain text host:port
      }
    }

    // host:port format
    const match = trimmed.match(/^([^:]+):(\d+)$/);
    if (match) {
      results.push({
        host: match[1],
        ip: match[1],
        port: Number(match[2])
      });
    }
  }

  return results;
}

/**
 * Parse Httpx NDJSON output stream
 * @param {string} rawOutput 
 * @returns {Array<object>}
 */
export function parseHttpxOutput(rawOutput) {
  if (!rawOutput || typeof rawOutput !== 'string') return [];
  const results = [];
  const lines = rawOutput.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.startsWith('{')) continue;

    try {
      const parsed = JSON.parse(trimmed);
      results.push({
        url: parsed.url,
        host: parsed.input || parsed.host,
        port: parsed.port,
        title: parsed.title || '',
        webserver: parsed.webserver || '',
        status_code: parsed.status_code || 0,
        content_length: parsed.content_length,
        tech: parsed.tech || [],
        tls: parsed.tls || null,
        cname: parsed.cname || [],
        cdn: parsed.cdn || false
      });
    } catch {
      // Skip malformed lines
    }
  }

  return results;
}

/**
 * Execute a fast recon scan (Naabu, Httpx, or Native Fallback)
 * @param {string} target 
 * @param {string} profileId 
 * @param {object} [opts={}]
 * @returns {Promise<{ id: string, target: string, profile: string, timestamp: string, openPorts: Array, webServices: Array, rawOutput: string, filePath: string }>}
 */
export async function runReconScan(target, profileId = 'fast-ports', opts = {}) {
  await ensureVigilanteConfig();
  const reconDir = getVigilanteReconDir();
  const profile = RECON_PROFILES.find((p) => p.id === profileId) || RECON_PROFILES[0];
  const tools = await checkReconToolsInstalled();

  const timestamp = new Date().toISOString();
  const scanId = `recon_${target.replace(/[^a-zA-Z0-9_.-]/g, '_')}_${Date.now()}`;
  let rawOutput = '';
  let openPorts = [];
  let webServices = [];

  if (profile.tool === 'naabu') {
    if (tools.naabu.runner === 'host') {
      const args = profile.buildArgs(target, opts);
      const res = await execa('naabu', args);
      rawOutput = res.stdout;
      openPorts = parseNaabuOutput(rawOutput);
    } else {
      // Native socket probe fallback
      const ports = opts.topPorts ? [80, 443, 22, 21, 53, 161, 389, 8080, 8443, 9000] : [80, 443, 22, 8080];
      openPorts = await probePortsNative(target, ports);
      rawOutput = JSON.stringify(openPorts, null, 2);
    }
  } else if (profile.tool === 'httpx') {
    if (tools.httpx.runner === 'host') {
      const args = profile.buildArgs(target, opts);
      const res = await execa('httpx', args);
      rawOutput = res.stdout;
      webServices = parseHttpxOutput(rawOutput);
    } else {
      // Native fetch fallback
      const webResult = await probeHttpNative(target);
      if (!webResult.failed) webServices.push(webResult);
      rawOutput = JSON.stringify(webServices, null, 2);
    }
  } else if (profile.tool === 'combined') {
    // Pipeline ports into web services
    const ports = [80, 443, 8080, 8443, 3000];
    openPorts = await probePortsNative(target, ports);
    for (const p of openPorts) {
      const scheme = p.port === 443 || p.port === 8443 ? 'https' : 'http';
      const webResult = await probeHttpNative(`${scheme}://${target}:${p.port}`);
      if (!webResult.failed) webServices.push(webResult);
    }
    rawOutput = JSON.stringify({ openPorts, webServices }, null, 2);
  }

  const record = {
    id: scanId,
    target,
    profile: profile.id,
    timestamp,
    openPorts,
    webServices,
    rawOutput
  };

  const filePath = path.join(reconDir, `${scanId}.json`);
  await fs.writeFile(filePath, JSON.stringify(record, null, 2), 'utf8');

  // GPG sign if configured
  await autoSignIfConfigured(filePath);

  // Also save as formal evidence artifact
  try {
    await saveEvidenceFile(target, `${scanId}.json`, JSON.stringify(record, null, 2), {
      source: 'recon',
      profile: profile.id
    });
  } catch (err) {
    logger.warn('RECON', `Could not save evidence file: ${err.message}`);
  }

  return { ...record, filePath };
}

/**
 * List saved recon scans
 * @returns {Promise<Array<object>>}
 */
export async function listSavedReconScans() {
  await ensureVigilanteConfig();
  const reconDir = getVigilanteReconDir();
  try {
    const files = await fs.readdir(reconDir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json') && !f.endsWith('.sig') && !f.endsWith('.asc')) {
        const fullPath = path.join(reconDir, f);
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          const parsed = JSON.parse(content);
          results.push({
            id: parsed.id || f.replace('.json', ''),
            target: parsed.target || 'unknown',
            profile: parsed.profile || 'unknown',
            timestamp: parsed.timestamp || '',
            portsCount: (parsed.openPorts || []).length,
            webCount: (parsed.webServices || []).length,
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

/**
 * Convert recon findings to NastyMap nodes and links
 * @param {object} reconRecord 
 * @returns {{ nodes: Array, links: Array }}
 */
export function reconToTopology(reconRecord) {
  const nodes = [];
  const links = [];
  if (!reconRecord || !reconRecord.target) return { nodes, links };

  const targetNode = {
    id: reconRecord.target,
    label: reconRecord.target,
    type: 'host',
    ports: (reconRecord.openPorts || []).map((p) => p.port)
  };
  nodes.push(targetNode);

  for (const ws of reconRecord.webServices || []) {
    const serviceId = `${reconRecord.target}:${ws.port || (ws.url && ws.url.startsWith('https') ? 443 : 80)}`;
    nodes.push({
      id: serviceId,
      label: ws.title ? `${ws.title} (${ws.webserver || 'HTTP'})` : serviceId,
      type: 'service',
      statusCode: ws.status_code,
      tech: ws.tech
    });
    links.push({
      source: reconRecord.target,
      target: serviceId,
      label: `port ${ws.port}`
    });
  }

  return { nodes, links };
}
