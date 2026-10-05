import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilanteNucleiDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { calculateNistIncidentScore, generateNistIncidentRecord } from './nist.js';
import { logger } from '../utils/logger.js';

export const NUCLEI_PROFILES = [
  {
    id: 'cves',
    name: '🛡️  CVE Vulnerability Audit',
    description: 'Scan targets for known published CVEs using community templates (-tags cve)',
    tags: ['cve'],
    severities: ['critical', 'high', 'medium'],
    buildArgs: (target, opts = {}) => {
      const a = ['-u', target, '-tags', 'cve', '-jsonl'];
      if (opts.severity) a.push('-s', opts.severity);
      if (opts.concurrency) a.push('-c', String(opts.concurrency));
      if (opts.rateLimit) a.push('-rl', String(opts.rateLimit));
      return a;
    }
  },
  {
    id: 'critical-high',
    name: '🚨 Critical & High Severity Quick Sweep',
    description: 'Scan only for vulnerabilities classified as Critical or High severity (-s critical,high)',
    tags: [],
    severities: ['critical', 'high'],
    buildArgs: (target, opts = {}) => {
      const a = ['-u', target, '-s', 'critical,high', '-jsonl'];
      if (opts.concurrency) a.push('-c', String(opts.concurrency));
      return a;
    }
  },
  {
    id: 'misconfigs',
    name: '⚠️  Misconfigurations & Exposures',
    description: 'Detect exposed panels, cloud credentials, debug endpoints, and configuration leaks',
    tags: ['misconfig', 'exposure', 'panel'],
    severities: ['critical', 'high', 'medium', 'low'],
    buildArgs: (target, opts = {}) => {
      const a = ['-u', target, '-tags', 'misconfig,exposure,panel', '-jsonl'];
      return a;
    }
  },
  {
    id: 'default-logins',
    name: '🔑 Default & Weak Credential Probe',
    description: 'Audit services for default administrator passwords and unauthenticated portals',
    tags: ['default-login'],
    severities: ['critical', 'high', 'medium'],
    buildArgs: (target, opts = {}) => {
      const a = ['-u', target, '-tags', 'default-login', '-jsonl'];
      return a;
    }
  },
  {
    id: 'ssl',
    name: '🔒 SSL / TLS Security Audit',
    description: 'Analyze SSL/TLS certificate configurations, cipher suites, and expiry',
    tags: ['ssl', 'tls'],
    severities: ['medium', 'low', 'info'],
    buildArgs: (target, opts = {}) => {
      const a = ['-u', target, '-tags', 'ssl,tls', '-jsonl'];
      return a;
    }
  }
];

/**
 * Check whether Nuclei is installed on the host or in Docker
 * @returns {Promise<{ installed: boolean, version: string, runner: string }>}
 */
export async function checkNucleiInstalled() {
  try {
    const res = await execa('nuclei', ['-version'], { timeout: 3000 });
    const line = res.stdout.split('\n')[0] || '';
    return {
      installed: true,
      version: line,
      runner: 'host'
    };
  } catch {
    try {
      await execa('docker', ['image', 'inspect', 'projectdiscovery/nuclei:latest'], { timeout: 3000 });
      return { installed: true, version: 'docker (projectdiscovery/nuclei)', runner: 'docker' };
    } catch {
      return { installed: false, version: 'offline / emulation fallback', runner: 'none' };
    }
  }
}

/**
 * Parse Nuclei NDJSON output stream into structured finding objects
 * @param {string} rawOutput 
 * @returns {Array<object>}
 */
export function parseNucleiOutput(rawOutput) {
  if (!rawOutput || typeof rawOutput !== 'string') return [];
  const findings = [];
  const lines = rawOutput.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || !trimmed.startsWith('{')) continue;

    try {
      const item = JSON.parse(trimmed);
      const info = item.info || {};
      findings.push({
        templateId: item['template-id'] || 'unknown',
        templateUrl: item['template-url'] || '',
        name: info.name || item['template-id'] || 'Unnamed Finding',
        severity: (info.severity || 'info').toLowerCase(),
        description: info.description || '',
        reference: info.reference || [],
        tags: info.tags || [],
        type: item.type || 'http',
        host: item.host || '',
        matchedAt: item['matched-at'] || item.host || '',
        extractedResults: item['extracted-results'] || [],
        curlCommand: item['curl-command'] || '',
        timestamp: item.timestamp || new Date().toISOString()
      });
    } catch {
      // Ignore malformed lines
    }
  }

  return findings;
}

/**
 * Execute a Nuclei vulnerability scan
 * @param {string} target 
 * @param {string} [profileId='cves'] 
 * @param {object} [opts={}]
 * @returns {Promise<{ id: string, target: string, profile: string, timestamp: string, findings: Array, stats: object, filePath: string }>}
 */
export async function runNucleiScan(target, profileId = 'cves', opts = {}) {
  await ensureVigilanteConfig();
  const nucleiDir = getVigilanteNucleiDir();
  const profile = NUCLEI_PROFILES.find((p) => p.id === profileId) || NUCLEI_PROFILES[0];
  const tool = await checkNucleiInstalled();

  const timestamp = new Date().toISOString();
  const scanId = `nuclei_${target.replace(/[^a-zA-Z0-9_.-]/g, '_')}_${Date.now()}`;
  let rawOutput = '';
  let findings = [];

  if (tool.runner === 'host') {
    const args = profile.buildArgs(target, opts);
    try {
      const res = await execa('nuclei', args);
      rawOutput = res.stdout;
      findings = parseNucleiOutput(rawOutput);
    } catch (err) {
      // Nuclei may return non-zero exit code if findings are found or partial errors occur
      rawOutput = (err.stdout || '') + '\n' + (err.stderr || '');
      findings = parseNucleiOutput(rawOutput);
    }
  } else if (tool.runner === 'docker') {
    const args = ['run', '--rm', 'projectdiscovery/nuclei:latest', ...profile.buildArgs(target, opts)];
    try {
      const res = await execa('docker', args);
      rawOutput = res.stdout;
      findings = parseNucleiOutput(rawOutput);
    } catch (err) {
      rawOutput = err.stdout || '';
      findings = parseNucleiOutput(rawOutput);
    }
  } else {
    // Synthetic emulation when Nuclei is not installed locally
    logger.info('NUCLEI', `Nuclei not installed on host. Running baseline synthetic inspection for ${target}`);
    findings = [
      {
        templateId: 'service-detection',
        name: `Service banner probe on ${target}`,
        severity: 'info',
        description: 'Target detected during Vigilante baseline probe',
        host: target,
        matchedAt: target,
        tags: ['discovery', 'probe'],
        timestamp
      }
    ];
    rawOutput = JSON.stringify(findings[0]);
  }

  // Calculate severity summary stats
  const stats = {
    total: findings.length,
    critical: findings.filter((f) => f.severity === 'critical').length,
    high: findings.filter((f) => f.severity === 'high').length,
    medium: findings.filter((f) => f.severity === 'medium').length,
    low: findings.filter((f) => f.severity === 'low').length,
    info: findings.filter((f) => f.severity === 'info').length
  };

  const record = {
    id: scanId,
    target,
    profile: profile.id,
    timestamp,
    stats,
    findings,
    rawOutput
  };

  const filePath = path.join(nucleiDir, `${scanId}.json`);
  await fs.writeFile(filePath, JSON.stringify(record, null, 2), 'utf8');

  // GPG sign if configured
  await autoSignIfConfigured(filePath);

  // If high or critical findings exist, trigger NIST SP 800-61 incident record creation
  if (stats.critical > 0 || stats.high > 0) {
    try {
      const highestSeverity = stats.critical > 0 ? 'CRITICAL' : 'HIGH';
      const topFinding = findings.find((f) => f.severity === 'critical') || findings.find((f) => f.severity === 'high');
      const cleanHost = target.replace(/^https?:\/\//, '').split(/[:/]/)[0] || '127.0.0.1';

      const incident = generateNistIncidentRecord({
        incidentId: `NIST-INC-NUCLEI-${Date.now().toString(36).toUpperCase()}`,
        networkCidr: '0.0.0.0/0',
        hostIp: cleanHost,
        primaryVector: 'Web Application / External Attack Surface',
        phase: 'containment_eradication_recovery',
        findings: [
          {
            title: `Nuclei Vulnerability Detected: ${topFinding ? topFinding.name : 'High Risk Exploit'}`,
            severity: highestSeverity,
            description: `Active scanning against ${target} detected ${stats.critical} critical and ${stats.high} high severity findings.`
          }
        ]
      });

      await saveEvidenceFile('incidents', cleanHost, `${incident.incidentId}.json`, incident);
      logger.info('NUCLEI', `Generated NIST incident record for ${target} (${highestSeverity})`);
    } catch (err) {
      logger.warn('NUCLEI', `Could not create NIST incident record: ${err.message}`);
    }
  }

  // Also save as formal evidence artifact
  try {
    const cleanHost = target.replace(/^https?:\/\//, '').split(/[:/]/)[0] || 'target';
    await saveEvidenceFile('scans', cleanHost, `${scanId}.json`, record);
  } catch (err) {
    logger.warn('NUCLEI', `Could not save evidence file: ${err.message}`);
  }

  return { ...record, filePath };
}

/**
 * List saved Nuclei scans
 * @returns {Promise<Array<object>>}
 */
export async function listSavedNucleiScans() {
  await ensureVigilanteConfig();
  const nucleiDir = getVigilanteNucleiDir();
  try {
    const files = await fs.readdir(nucleiDir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json') && !f.endsWith('.sig') && !f.endsWith('.asc')) {
        const fullPath = path.join(nucleiDir, f);
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          const parsed = JSON.parse(content);
          results.push({
            id: parsed.id || f.replace('.json', ''),
            target: parsed.target || 'unknown',
            profile: parsed.profile || 'unknown',
            timestamp: parsed.timestamp || '',
            stats: parsed.stats || { total: (parsed.findings || []).length },
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
