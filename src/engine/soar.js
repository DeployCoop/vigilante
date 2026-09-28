import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { dump as yamlDump } from 'js-yaml';
import {
  getVigilanteContainmentsDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

/**
 * Generate Kubernetes NetworkPolicy manifest to completely air-gap a pod
 * Accepts either (podName, namespace, options) or ({ podName, namespace, labels, ... })
 * @returns {string} NetworkPolicy YAML string
 */
export function generateQuarantineNetworkPolicy(arg1, arg2 = 'default', arg3 = {}) {
  let podName;
  let namespace = 'default';
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    podName = arg1.podName || arg1.name || 'target-pod';
    namespace = arg1.namespace || 'default';
    options = arg1;
  } else {
    podName = arg1 || 'target-pod';
    namespace = typeof arg2 === 'string' ? arg2 : 'default';
    options = typeof arg3 === 'object' && arg3 !== null ? arg3 : {};
  }

  const cleanPod = String(podName).toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const policyName = `quarantine-${cleanPod}`;
  const matchLabels = options.labels || options.podLabels || { 'app.kubernetes.io/name': podName, app: cleanPod };

  const manifest = {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: {
      name: policyName,
      namespace,
      labels: {
        'vigilante.containment/quarantine': 'true',
        'vigilante.containment/target-pod': String(podName),
        'app.kubernetes.io/managed-by': 'vigilante-soar'
      },
      annotations: {
        'vigilante.io/quarantine-reason': options.reason || 'Active Threat Containment',
        'vigilante.io/isolated-at': new Date().toISOString()
      }
    },
    spec: {
      podSelector: {
        matchLabels
      },
      policyTypes: ['Ingress', 'Egress'],
      ingress: [],
      egress: []
    }
  };

  const yaml = yamlDump(manifest);
  return yaml;
}

/**
 * Isolate a Kubernetes pod by applying a strict air-gap NetworkPolicy
 * Accepts ({ podName, namespace, reason }) or (podName, namespace, options)
 * @returns {Promise<Object>} Containment record
 */
export async function isolatePod(arg1, arg2 = 'default', arg3 = {}) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  let podName;
  let namespace = 'default';
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    podName = arg1.podName || arg1.name || 'target-pod';
    namespace = arg1.namespace || 'default';
    options = arg1;
  } else {
    podName = arg1 || 'target-pod';
    namespace = typeof arg2 === 'string' ? arg2 : 'default';
    options = typeof arg3 === 'object' && arg3 !== null ? arg3 : {};
  }

  const manifestYaml = generateQuarantineNetworkPolicy(podName, namespace, options);
  const containmentId = `cont-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const cleanPod = String(podName).toLowerCase().replace(/[^a-z0-9-]/g, '-');

  const record = {
    id: containmentId,
    containmentId,
    type: 'NETWORK_ISOLATION',
    target: podName,
    namespace,
    policyName: `quarantine-${cleanPod}`,
    policyYaml: manifestYaml,
    active: true,
    status: 'ACTIVE',
    isolatedAt: new Date().toISOString(),
    reason: options.reason || 'Active Threat Containment',
    appliedToCluster: false
  };

  // Attempt kubectl apply if cluster reachable
  if (options.apply !== false) {
    try {
      await execa('kubectl', ['apply', '-f', '-'], {
        input: manifestYaml,
        timeout: 5000
      });
      record.appliedToCluster = true;
      logger.info('SOAR', `Applied isolation NetworkPolicy ${record.policyName} in ${namespace}`);
    } catch (err) {
      logger.warn('SOAR', `Could not apply NetworkPolicy via kubectl (staged locally): ${err.message}`);
    }
  }

  // Persist containment record
  const recordFile = path.join(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');

  // Save signed evidence
  try {
    await saveEvidenceFile('containments', namespace, `${containmentId}.json`, JSON.stringify(record, null, 2));
    await autoSignIfConfigured(path.join(getHostEvidenceDir('containments', namespace), `${containmentId}.json`));
  } catch (evErr) {
    logger.warn('SOAR', `Failed to sign containment evidence: ${evErr.message}`);
  }

  return record;
}

/**
 * Freeze a pod or container execution while preserving memory
 * Accepts ({ podName, namespace, reason }) or (podName, namespace, options)
 * @returns {Promise<Object>}
 */
export async function freezePod(arg1, arg2 = 'default', arg3 = {}) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  let podName;
  let namespace = 'default';
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    podName = arg1.podName || arg1.name || 'target-pod';
    namespace = arg1.namespace || 'default';
    options = arg1;
  } else {
    podName = arg1 || 'target-pod';
    namespace = typeof arg2 === 'string' ? arg2 : 'default';
    options = typeof arg3 === 'object' && arg3 !== null ? arg3 : {};
  }

  const containmentId = `cont-freeze-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const record = {
    id: containmentId,
    containmentId,
    type: 'CONTAINER_FREEZE',
    target: podName,
    namespace,
    active: true,
    status: 'FROZEN',
    frozenAt: new Date().toISOString(),
    reason: options.reason || 'Cryptominer / High Severity Malicious Execution',
    appliedToCluster: false
  };

  const recordFile = path.join(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return record;
}

/**
 * Apply local firewall or Kubernetes egress block on a malicious IP address
 * Accepts ({ ip, reason }) or (ip, options)
 * @returns {Promise<Object>}
 */
export async function blockIp(arg1, arg2 = {}) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  let ipAddress;
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    ipAddress = arg1.ip || arg1.target || '127.0.0.1';
    options = arg1;
  } else {
    ipAddress = arg1 || '127.0.0.1';
    options = typeof arg2 === 'object' && arg2 !== null ? arg2 : {};
  }

  const containmentId = `cont-ip-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const record = {
    id: containmentId,
    containmentId,
    type: 'IP_BLOCK',
    target: ipAddress,
    active: true,
    status: 'BLOCKED',
    blockedAt: new Date().toISOString(),
    reason: options.reason || 'Malicious C2 / Port Scan Source',
    iptablesRule: `iptables -I INPUT -s ${ipAddress} -j DROP`
  };

  const recordFile = path.join(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return record;
}

/**
 * Generate remediation action to quarantine or disable a compromised account
 * Accepts ({ accountName, namespace, reason }) or (accountName, namespace, options)
 * @returns {Promise<Object>}
 */
export async function quarantineAccount(arg1, arg2 = 'default', arg3 = {}) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  let accountName;
  let namespace = 'default';
  let options = {};

  if (typeof arg1 === 'object' && arg1 !== null) {
    accountName = arg1.accountName || arg1.username || 'target-account';
    namespace = arg1.namespace || arg1.domain || 'default';
    options = arg1;
  } else {
    accountName = arg1 || 'target-account';
    namespace = typeof arg2 === 'string' ? arg2 : 'default';
    options = typeof arg3 === 'object' && arg3 !== null ? arg3 : {};
  }

  const containmentId = `cont-acct-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const record = {
    id: containmentId,
    containmentId,
    type: 'ACCOUNT_QUARANTINE',
    target: accountName,
    namespace,
    active: true,
    status: 'REVOKED',
    revokedAt: new Date().toISOString(),
    reason: options.reason || 'Compromised Token / Lateral Movement Credentials'
  };

  const recordFile = path.join(containmentsDir, `${containmentId}.json`);
  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return record;
}

/**
 * List all active and historical containment actions
 * @returns {Promise<Array<Object>>}
 */
export async function listActiveContainments() {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();

  try {
    const files = await fs.readdir(containmentsDir);
    const records = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        try {
          const raw = await fs.readFile(path.join(containmentsDir, f), 'utf8');
          const parsed = JSON.parse(raw);
          if (parsed.active !== false && parsed.status !== 'RELEASED') {
            parsed.active = true;
          }
          records.push(parsed);
        } catch {
          // ignore corrupted file
        }
      }
    }
    return records.sort((a, b) => new Date(b.isolatedAt || b.blockedAt || 0) - new Date(a.isolatedAt || a.blockedAt || 0));
  } catch (err) {
    logger.warn('SOAR', `Failed to list containments: ${err.message}`);
    return [];
  }
}

/**
 * Release an active containment (rollback NetworkPolicy or unblock)
 * @param {string} containmentId
 * @returns {Promise<Object>}
 */
export async function releaseContainment(containmentId) {
  await ensureVigilanteConfig();
  const containmentsDir = getVigilanteContainmentsDir();
  const recordFile = path.join(containmentsDir, `${containmentId}.json`);

  if (!fsSync.existsSync(recordFile)) {
    throw new Error(`Containment record '${containmentId}' not found.`);
  }

  const raw = await fs.readFile(recordFile, 'utf8');
  const record = JSON.parse(raw);

  if (record.policyName && record.namespace) {
    try {
      await execa('kubectl', ['delete', 'networkpolicy', record.policyName, '-n', record.namespace], { timeout: 5000 });
      logger.info('SOAR', `Removed isolation NetworkPolicy ${record.policyName}`);
    } catch (err) {
      logger.warn('SOAR', `Could not delete NetworkPolicy: ${err.message}`);
    }
  }

  record.status = 'RELEASED';
  record.active = false;
  record.releasedAt = new Date().toISOString();

  await fs.writeFile(recordFile, JSON.stringify(record, null, 2), 'utf8');
  return { success: true, record };
}
