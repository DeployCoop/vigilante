import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { logger } from '../utils/logger.js';

const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1
};

/**
 * Scan a single Kubernetes or Dockerfile content for security misconfigurations
 * Supports both (content, filePath) and (filePath, content)
 * @param {string} arg1
 * @param {string} arg2
 * @returns {Array<Object>} Findings
 */
export function auditFileContent(arg1, arg2) {
  let content;
  let filePath;

  if (typeof arg1 === 'string' && (arg1.endsWith('.yaml') || arg1.endsWith('.yml') || arg1.toLowerCase().includes('dockerfile')) && typeof arg2 === 'string') {
    filePath = arg1;
    content = arg2;
  } else {
    content = String(arg1 || '');
    filePath = String(arg2 || 'manifest.yaml');
  }

  const findings = [];
  const fileName = path.basename(filePath).toLowerCase();

  // Helper to add finding with both id and ruleId
  const addFinding = (ruleId, title, severity, description, remediation, line = null) => {
    findings.push({
      id: ruleId,
      ruleId,
      title,
      severity,
      file: filePath,
      line,
      description,
      remediation
    });
  };

  // 1. Dockerfile checks
  if (fileName.includes('dockerfile')) {
    if (!content.includes('USER ') || content.includes('USER root') || content.includes('USER 0')) {
      addFinding(
        'VIGIL-DOCKER-001',
        'Container Runs as Root User',
        'HIGH',
        'Dockerfile runs with root privileges or lacks a non-root USER instruction.',
        'Add a dedicated non-root user via `USER 10001` or create user with adduser.'
      );
    }
    if (/ENV\s+.*(PASSWORD|SECRET|KEY|TOKEN)\s*=/i.test(content)) {
      addFinding(
        'VIGIL-DOCKER-002',
        'Hardcoded Secret in Environment Variable',
        'CRITICAL',
        'Plaintext secret or credential hardcoded into Dockerfile ENV instruction.',
        'Inject secrets at runtime using Kubernetes Secrets or volume mounts.'
      );
    }
    if (/FROM\s+[^\s:]+:latest/i.test(content) || (/FROM\s+[^\s:]+$/m.test(content) && !content.includes(':'))) {
      addFinding(
        'VIGIL-DOCKER-003',
        'Image Uses Latest or Untagged Version',
        'MEDIUM',
        'Base image relies on mutable :latest tag rather than an immutable SHA256 digest or semver tag.',
        'Pin specific image digests or version tags (e.g. node:20-alpine).'
      );
    }
    if (content.includes('sudo ') || content.includes('chmod 777')) {
      addFinding(
        'VIGIL-DOCKER-004',
        'Dangerous Privileges or Sudo in RUN Command',
        'HIGH',
        'Dockerfile grants world-writable permissions or installs/invokes sudo.',
        'Avoid sudo in containers and restrict permissions to 0755 or 0700.'
      );
    }
    if (/ADD\s+https?:\/\//i.test(content)) {
      addFinding(
        'VIGIL-DOCKER-005',
        'Insecure Remote ADD Instruction',
        'MEDIUM',
        'ADD instruction downloads from remote URL without checksum verification.',
        'Use curl with hash verification or COPY pre-downloaded assets instead.'
      );
    }
  }

  // 2. Kubernetes YAML Manifest checks
  if (fileName.endsWith('.yaml') || fileName.endsWith('.yml')) {
    if (content.includes('privileged: true')) {
      addFinding(
        'VIGIL-K8S-001',
        'Privileged Container Execution Enabled',
        'CRITICAL',
        'Container securityContext has privileged: true, allowing complete host takeover and kernel escapes.',
        'Disable privileged mode: set `securityContext.privileged: false`.'
      );
    }
    if (content.includes('runAsUser: 0') || (/runAsNonRoot:\s*false/i.test(content))) {
      addFinding(
        'VIGIL-K8S-002',
        'Workload Configured to Run as Root User',
        'HIGH',
        'Pod or container specifies runAsUser: 0 or explicit root privileges.',
        'Configure `securityContext.runAsNonRoot: true` and specify a non-zero UID.'
      );
    }
    if (content.includes('hostNetwork: true') || content.includes('hostPID: true') || content.includes('hostIPC: true')) {
      addFinding(
        'VIGIL-K8S-003',
        'Host Namespace Sharing Enabled (hostNetwork/hostPID)',
        'HIGH',
        'Pod shares node host namespaces, allowing inspection of node processes and traffic.',
        'Remove hostNetwork, hostPID, and hostIPC directives.'
      );
    }
    if (content.includes('allowPrivilegeEscalation: true')) {
      addFinding(
        'VIGIL-K8S-004',
        'Privilege Escalation Allowed in Container',
        'HIGH',
        'Container process can gain more privileges than its parent via setuid binaries.',
        'Set `securityContext.allowPrivilegeEscalation: false`.'
      );
    }
    if (!content.includes('limits:') || !content.includes('requests:')) {
      addFinding(
        'VIGIL-K8S-005',
        'Missing CPU/Memory Resource Limits',
        'LOW',
        'Workload does not define resource limits, making the node vulnerable to noisy neighbors and DoS.',
        'Specify explicit `resources.limits` and `resources.requests` for cpu and memory.'
      );
    }
  }

  return findings;
}

/**
 * Format findings into SARIF v2.1.0 format for GitHub Code Scanning
 * @param {Array<Object>} findings
 * @returns {Object} SARIF JSON
 */
export function generateSarifReport(findings = []) {
  // Deduplicate rules
  const ruleMap = new Map();
  for (const f of findings) {
    if (!ruleMap.has(f.ruleId || f.id)) {
      ruleMap.set(f.ruleId || f.id, {
        id: f.ruleId || f.id,
        name: f.title,
        shortDescription: { text: f.title },
        fullDescription: { text: f.description },
        defaultConfiguration: {
          level: (f.severity === 'CRITICAL' || f.severity === 'HIGH') ? 'error' : 'warning'
        }
      });
    }
  }

  return {
    version: '2.1.0',
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'vigilante-audit',
            version: '0.1.0',
            rules: Array.from(ruleMap.values())
          }
        },
        results: findings.map(f => ({
          ruleId: f.ruleId || f.id,
          level: (f.severity === 'CRITICAL' || f.severity === 'HIGH') ? 'error' : 'warning',
          message: { text: `${f.title}: ${f.remediation}` },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: f.file || 'manifest.yaml' },
                region: f.line ? { startLine: f.line } : undefined
              }
            }
          ]
        }))
      }
    ]
  };
}

/**
 * Run a shift-left security audit across a target directory or file
 * @param {string} targetPath - Directory or file path to audit
 * @param {Object} [options]
 * @param {string} [options.failOn='HIGH'] - Severity threshold to fail gate
 * @returns {Promise<Object>}
 */
export async function runPipelineAudit(targetPath = '.', options = {}) {
  const failOn = (options.failOn || 'HIGH').toUpperCase();
  const failThreshold = SEVERITY_RANK[failOn.toLowerCase()] || 3;
  const absPath = path.resolve(process.cwd(), targetPath);

  if (!fsSync.existsSync(absPath)) {
    throw new Error(`Target audit path not found: ${targetPath}`);
  }

  const allFindings = [];
  let filesScanned = 0;

  async function walk(current) {
    const stat = await fs.stat(current);
    if (stat.isFile()) {
      const base = path.basename(current).toLowerCase();
      if (base.endsWith('.yaml') || base.endsWith('.yml') || base.includes('dockerfile')) {
        filesScanned++;
        const raw = await fs.readFile(current, 'utf8');
        const f = auditFileContent(current, raw);
        allFindings.push(...f);
      }
    } else if (stat.isDirectory()) {
      const entries = await fs.readdir(current);
      for (const e of entries) {
        if (e === 'node_modules' || e === '.git' || e === '.gitnexus') continue;
        await walk(path.join(current, e));
      }
    }
  }

  await walk(absPath);

  // Calculate summary counts
  const summary = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0
  };

  let failed = false;

  for (const f of allFindings) {
    const sev = (f.severity || 'LOW').toUpperCase();
    if (summary[sev] !== undefined) {
      summary[sev]++;
    }
    const rank = SEVERITY_RANK[sev.toLowerCase()] || 1;
    if (rank >= failThreshold) {
      failed = true;
    }
  }

  const sarif = generateSarifReport(allFindings);

  return {
    targetPath: absPath,
    scannedAt: new Date().toISOString(),
    filesScanned,
    failed,
    passed: !failed,
    failThreshold: failOn,
    findingsCount: allFindings.length,
    summary,
    severityCounts: summary,
    findings: allFindings,
    sarif
  };
}
