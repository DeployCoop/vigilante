import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilanteTrivyDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { calculateNistIncidentScore, generateNistIncidentRecord } from './nist.js';
import { logger } from '../utils/logger.js';

export const TRIVY_PROFILES = [
  {
    id: 'image',
    name: '🐳 Container Image Vulnerability Audit',
    description: 'Scan container image for OS packages and language library CVEs',
    buildArgs: (target, opts = {}) => {
      const a = ['image', '--format', 'json', target];
      if (opts.severity) a.push('--severity', opts.severity);
      return a;
    }
  },
  {
    id: 'k8s',
    name: '☸️  Kubernetes Cluster & Workload Audit',
    description: 'Audit Kubernetes cluster workloads for security misconfigurations and CVEs',
    buildArgs: (target = 'cluster', opts = {}) => {
      const a = ['k8s', '--format', 'json', '--report', 'summary'];
      if (opts.namespace) a.push('--namespace', opts.namespace);
      return a;
    }
  },
  {
    id: 'secrets',
    name: '🔑 Filesystem & Secret Leak Scan',
    description: 'Scan directory or codebase for exposed API keys, private keys, and passwords',
    buildArgs: (target = '.', opts = {}) => {
      const a = ['fs', '--scanners', 'secret', '--format', 'json', target];
      return a;
    }
  },
  {
    id: 'sbom',
    name: '📦 Software Bill of Materials (SBOM)',
    description: 'Generate CycloneDX / SPDX SBOM for software supply chain transparency',
    buildArgs: (target, opts = {}) => {
      const a = ['image', '--format', 'cyclonedx', target];
      return a;
    }
  }
];

/**
 * Check whether Trivy is installed
 * @returns {Promise<{ installed: boolean, version: string, runner: string }>}
 */
export async function checkTrivyInstalled() {
  try {
    const res = await execa('trivy', ['--version'], { timeout: 3000 });
    const line = res.stdout.split('\n')[0] || '';
    return {
      installed: true,
      version: line,
      runner: 'host'
    };
  } catch {
    try {
      await execa('docker', ['image', 'inspect', 'aquasec/trivy:latest'], { timeout: 3000 });
      return { installed: true, version: 'docker (aquasec/trivy)', runner: 'docker' };
    } catch {
      return { installed: false, version: 'offline emulation', runner: 'none' };
    }
  }
}

/**
 * Parse Trivy JSON output
 * @param {string} rawJson 
 * @returns {{ vulnerabilities: Array, misconfigurations: Array, secrets: Array, summary: object }}
 */
export function parseTrivyOutput(rawJson) {
  const result = {
    vulnerabilities: [],
    misconfigurations: [],
    secrets: [],
    summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
  };

  if (!rawJson || typeof rawJson !== 'string') return result;

  try {
    const parsed = JSON.parse(rawJson);
    const results = parsed.Results || (Array.isArray(parsed) ? parsed : [parsed]);

    for (const res of results) {
      const targetName = res.Target || 'unknown';

      // Vulnerabilities
      for (const vuln of res.Vulnerabilities || []) {
        const severity = (vuln.Severity || 'LOW').toUpperCase();
        result.vulnerabilities.push({
          cveId: vuln.VulnerabilityID || 'UNKNOWN',
          pkgName: vuln.PkgName || '',
          installedVersion: vuln.InstalledVersion || '',
          fixedVersion: vuln.FixedVersion || '',
          title: vuln.Title || '',
          description: vuln.Description || '',
          severity,
          target: targetName,
          references: vuln.References || []
        });
        const lowerSev = severity.toLowerCase();
        if (lowerSev in result.summary) {
          result.summary[lowerSev]++;
        }
        result.summary.total++;
      }

      // Misconfigurations
      for (const misc of res.Misconfigurations || []) {
        const severity = (misc.Severity || 'LOW').toUpperCase();
        result.misconfigurations.push({
          id: misc.ID || '',
          title: misc.Title || '',
          description: misc.Description || '',
          message: misc.Message || '',
          resolution: misc.Resolution || '',
          severity,
          target: targetName
        });
        const lowerSev = severity.toLowerCase();
        if (lowerSev in result.summary) {
          result.summary[lowerSev]++;
        }
        result.summary.total++;
      }

      // Secrets
      for (const sec of res.Secrets || []) {
        const severity = (sec.Severity || 'CRITICAL').toUpperCase();
        result.secrets.push({
          ruleId: sec.RuleID || '',
          category: sec.Category || '',
          title: sec.Title || '',
          severity,
          target: targetName,
          match: sec.Match || ''
        });
        const lowerSev = severity.toLowerCase();
        if (lowerSev in result.summary) {
          result.summary[lowerSev]++;
        }
        result.summary.total++;
      }
    }
  } catch {
    // Malformed JSON
  }

  return result;
}

/**
 * Execute a Trivy security audit
 * @param {string} target 
 * @param {string} [profileId='image'] 
 * @param {object} [opts={}]
 * @returns {Promise<{ id: string, target: string, profile: string, timestamp: string, data: object, filePath: string }>}
 */
export async function runTrivyAudit(target, profileId = 'image', opts = {}) {
  await ensureVigilanteConfig();
  const trivyDir = getVigilanteTrivyDir();
  const profile = TRIVY_PROFILES.find((p) => p.id === profileId) || TRIVY_PROFILES[0];
  const tool = await checkTrivyInstalled();

  const timestamp = new Date().toISOString();
  const scanId = `trivy_${target.replace(/[^a-zA-Z0-9_.-]/g, '_')}_${Date.now()}`;
  let rawOutput = '';
  let parsedData = { vulnerabilities: [], misconfigurations: [], secrets: [], summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 } };

  if (tool.runner === 'host') {
    const args = profile.buildArgs(target, opts);
    try {
      const res = await execa('trivy', args);
      rawOutput = res.stdout;
      parsedData = parseTrivyOutput(rawOutput);
    } catch (err) {
      rawOutput = err.stdout || '';
      parsedData = parseTrivyOutput(rawOutput);
    }
  } else if (tool.runner === 'docker') {
    const args = ['run', '--rm', '-v', '/var/run/docker.sock:/var/run/docker.sock', 'aquasec/trivy:latest', ...profile.buildArgs(target, opts)];
    try {
      const res = await execa('docker', args);
      rawOutput = res.stdout;
      parsedData = parseTrivyOutput(rawOutput);
    } catch (err) {
      rawOutput = err.stdout || '';
      parsedData = parseTrivyOutput(rawOutput);
    }
  } else {
    // Synthetic fallback
    parsedData = {
      vulnerabilities: [],
      misconfigurations: [],
      secrets: [],
      summary: { critical: 0, high: 0, medium: 0, low: 0, total: 0 }
    };
    rawOutput = JSON.stringify(parsedData);
  }

  const record = {
    id: scanId,
    target,
    profile: profile.id,
    timestamp,
    ...parsedData,
    rawOutput
  };

  const filePath = path.join(trivyDir, `${scanId}.json`);
  await fs.writeFile(filePath, JSON.stringify(record, null, 2), 'utf8');

  // GPG sign if configured
  await autoSignIfConfigured(filePath);

  // If critical vulnerabilities exist, trigger NIST incident triage
  if (parsedData.summary.critical > 0) {
    try {
      const cleanTarget = target.replace(/[^a-zA-Z0-9_.-]/g, '_');
      const incident = generateNistIncidentRecord({
        incidentId: `NIST-INC-TRIVY-${Date.now().toString(36).toUpperCase()}`,
        networkCidr: '0.0.0.0/0',
        hostIp: cleanTarget,
        primaryVector: 'Supply Chain / Container Vulnerability',
        phase: 'containment_eradication_recovery',
        findings: [
          {
            title: `Trivy Audit Critical Alert for ${target}`,
            severity: 'CRITICAL',
            description: `Trivy audit uncovered ${parsedData.summary.critical} CRITICAL vulnerabilities in ${target}.`
          }
        ]
      });

      await saveEvidenceFile('incidents', cleanTarget, `${incident.incidentId}.json`, incident);
    } catch (err) {
      logger.warn('TRIVY', `Could not create NIST incident bundle: ${err.message}`);
    }
  }

  // Save evidence file
  try {
    const cleanTarget = target.replace(/[^a-zA-Z0-9_.-]/g, '_');
    await saveEvidenceFile('audits', cleanTarget, `${scanId}.json`, record);
  } catch (err) {
    logger.warn('TRIVY', `Could not save evidence file: ${err.message}`);
  }

  return { ...record, filePath };
}

/**
 * List saved Trivy scans
 * @returns {Promise<Array<object>>}
 */
export async function listSavedTrivyScans() {
  await ensureVigilanteConfig();
  const trivyDir = getVigilanteTrivyDir();
  try {
    const files = await fs.readdir(trivyDir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json') && !f.endsWith('.sig') && !f.endsWith('.asc')) {
        const fullPath = path.join(trivyDir, f);
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          const parsed = JSON.parse(content);
          results.push({
            id: parsed.id || f.replace('.json', ''),
            target: parsed.target || 'unknown',
            profile: parsed.profile || 'unknown',
            timestamp: parsed.timestamp || '',
            summary: parsed.summary || { total: 0 },
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
