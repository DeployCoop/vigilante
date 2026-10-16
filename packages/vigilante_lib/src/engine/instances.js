import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  ensureVigilanteConfig,
  getVigilanteInstancesDir,
  getInstanceDir,
  getInstanceCertsDir,
  getInstanceValuesDir,
  getInstanceLogsDir,
  sanitizePathComponent,
  assertPathStrictlyInside
} from './config.js';
import { listK3dClusters, deleteK3dCluster } from './cluster.js';
import { logger } from '../utils/logger.js';

/**
 * Ensure all subdirectories for a specific k3d instance exist
 * @param {string} [instanceName='vigilante-dev']
 * @returns {Promise<{ instanceDir: string, certsDir: string, valuesDir: string, logsDir: string }>}
 */
export async function ensureInstanceDirs(instanceName = 'vigilante-dev') {
  await ensureVigilanteConfig();
  const safeName = sanitizePathComponent(instanceName || 'vigilante-dev');
  const instanceDir = getInstanceDir(safeName);
  const certsDir = getInstanceCertsDir(safeName);
  const valuesDir = getInstanceValuesDir(safeName);
  const logsDir = getInstanceLogsDir(safeName);

  await fs.mkdir(instanceDir, { recursive: true });
  await fs.mkdir(certsDir, { recursive: true });
  await fs.mkdir(valuesDir, { recursive: true });
  await fs.mkdir(logsDir, { recursive: true });

  return { instanceDir, certsDir, valuesDir, logsDir };
}

/**
 * Synchronously ensure instance directories exist
 * @param {string} [instanceName='vigilante-dev']
 * @returns {{ instanceDir: string, certsDir: string, valuesDir: string, logsDir: string }}
 */
export function ensureInstanceDirsSync(instanceName = 'vigilante-dev') {
  const safeName = sanitizePathComponent(instanceName || 'vigilante-dev');
  const instanceDir = getInstanceDir(safeName);
  const certsDir = getInstanceCertsDir(safeName);
  const valuesDir = getInstanceValuesDir(safeName);
  const logsDir = getInstanceLogsDir(safeName);

  try {
    if (!fsSync.existsSync(instanceDir)) fsSync.mkdirSync(instanceDir, { recursive: true });
    if (!fsSync.existsSync(certsDir)) fsSync.mkdirSync(certsDir, { recursive: true });
    if (!fsSync.existsSync(valuesDir)) fsSync.mkdirSync(valuesDir, { recursive: true });
    if (!fsSync.existsSync(logsDir)) fsSync.mkdirSync(logsDir, { recursive: true });
  } catch (err) {
    // Ignore sync fallback error
  }

  return { instanceDir, certsDir, valuesDir, logsDir };
}

/**
 * Save or update instance metadata in instance.json
 * @param {string} instanceName
 * @param {Object} metadata
 * @returns {Promise<string>} Path to instance.json
 */
// instance.json updates are read-modify-write. Without serialization,
// concurrent writers all read the same starting state and the last write
// wins wholesale (8 concurrent namespace records left exactly 1
// survivor). A per-instance promise chain serializes the writers in
// this process; the *Unlocked core is what nested callers use while
// already holding the chain.
const instanceWriteChains = new Map();

function withInstanceWriteLock(instanceName, fn) {
  const key = sanitizePathComponent(instanceName || 'vigilante-dev');
  const prev = instanceWriteChains.get(key) || Promise.resolve();
  const run = prev.then(fn, fn);
  instanceWriteChains.set(key, run.catch(() => {}));
  return run;
}

export async function saveInstanceMetadata(instanceName = 'vigilante-dev', metadata = {}) {
  return withInstanceWriteLock(instanceName, () => saveInstanceMetadataUnlocked(instanceName, metadata));
}

async function saveInstanceMetadataUnlocked(instanceName = 'vigilante-dev', metadata = {}) {
  const { instanceDir } = await ensureInstanceDirs(instanceName);
  const metadataPath = path.join(instanceDir, 'instance.json');

  let existing = {};
  try {
    const raw = await fs.readFile(metadataPath, 'utf8');
    existing = JSON.parse(raw);
  } catch {
    existing = { createdAt: new Date().toISOString() };
  }

  const merged = {
    ...existing,
    ...metadata,
    instanceName: sanitizePathComponent(instanceName || 'vigilante-dev'),
    clusterName: metadata.clusterName || instanceName || 'vigilante-dev',
    updatedAt: new Date().toISOString()
  };

  await fs.writeFile(metadataPath, JSON.stringify(merged, null, 2), 'utf8');
  logger.info('INSTANCES:SAVE_META', `Saved metadata for instance '${instanceName}' at ${metadataPath}`);
  return metadataPath;
}

/**
 * Load instance metadata from instance.json
 * @param {string} instanceName
 * @returns {Promise<Object|null>}
 */
export async function loadInstanceMetadata(instanceName = 'vigilante-dev') {
  const safeName = sanitizePathComponent(instanceName || 'vigilante-dev');
  const metadataPath = path.join(getInstanceDir(safeName), 'instance.json');

  try {
    const raw = await fs.readFile(metadataPath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Record a deployment of modules to a specific namespace
 * @param {string} [instanceName='vigilante-dev']
 * @param {string} [namespace='default']
 * @param {string[]} [modules=[]]
 * @param {Object} [extra={}]
 */
export async function recordNamespaceDeployment(instanceName = 'vigilante-dev', namespace = 'default', modules = [], extra = {}) {
  return withInstanceWriteLock(instanceName, async () => {
    const meta = (await loadInstanceMetadata(instanceName)) || {};
    const currentNamespaces = meta.namespaces || {};

    currentNamespaces[namespace] = {
      modules,
      ...extra,
      updatedAt: new Date().toISOString()
    };

    await saveInstanceMetadataUnlocked(instanceName, {
      ...meta,
      namespaces: currentNamespaces
    });

    logger.info('INSTANCES:NAMESPACE_DEPLOY', `Recorded deployment of [${modules.join(', ')}] in namespace '${namespace}' on instance '${instanceName}'`);
  });
}

/**
 * Get all namespaces and their installed modules on an instance
 * @param {string} [instanceName='vigilante-dev']
 * @returns {Promise<Record<string, { modules: string[], updatedAt?: string }>>}
 */
export async function getDeployedNamespaces(instanceName = 'vigilante-dev') {
  const meta = await loadInstanceMetadata(instanceName);
  return meta?.namespaces || {};
}

/**
 * Remove a namespace record from instance metadata
 * @param {string} [instanceName='vigilante-dev']
 * @param {string} [namespace='default']
 */
export async function removeNamespaceDeployment(instanceName = 'vigilante-dev', namespace = 'default') {
  return withInstanceWriteLock(instanceName, async () => {
    const meta = (await loadInstanceMetadata(instanceName)) || {};
    if (meta.namespaces && meta.namespaces[namespace]) {
      delete meta.namespaces[namespace];
      await saveInstanceMetadataUnlocked(instanceName, meta);
      logger.info('INSTANCES:NAMESPACE_REMOVE', `Removed namespace '${namespace}' metadata from instance '${instanceName}'`);
    }
  });
}

/**
 * List all Vigilante k3d instances and cross-reference with live clusters
 * @returns {Promise<Array<Object>>}
 */
export async function listInstances() {
  await ensureVigilanteConfig();
  const instancesDir = getVigilanteInstancesDir();
  const instances = [];

  let liveClusters = [];
  try {
    liveClusters = await listK3dClusters();
  } catch {
    liveClusters = [];
  }

  try {
    const entries = await fs.readdir(instancesDir, { withFileTypes: true });

    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      const instanceName = entry.name;
      const instancePath = path.join(instancesDir, instanceName);
      const certsDir = path.join(instancePath, 'certs');
      const valuesDir = path.join(instancePath, 'values');

      // Check metadata
      let meta = null;
      try {
        const raw = await fs.readFile(path.join(instancePath, 'instance.json'), 'utf8');
        meta = JSON.parse(raw);
      } catch {
        meta = { instanceName, clusterName: instanceName };
      }

      const clusterName = meta.clusterName || instanceName;
      const matchingCluster = liveClusters.find(c => c.name === clusterName);

      // Check certs
      let hasCerts = false;
      try {
        const certFiles = await fs.readdir(certsDir);
        hasCerts = certFiles.some(f => f.endsWith('.pem'));
      } catch {
        hasCerts = false;
      }

      let k3dStatus = 'not_created';
      let serversRunning = 0;
      let serversCount = 0;
      let agentsCount = 0;

      if (matchingCluster) {
        serversRunning = matchingCluster.serversRunning || 0;
        serversCount = matchingCluster.serversCount || 0;
        agentsCount = matchingCluster.agentsCount || 0;
        k3dStatus = serversRunning > 0 ? 'running' : 'stopped';
      }

      instances.push({
        instanceName,
        clusterName,
        instanceDir: instancePath,
        certsDir,
        valuesDir,
        hasCerts,
        k3dStatus,
        serversRunning,
        serversCount,
        agentsCount,
        domain: meta.domain || `${instanceName}.local`,
        ip: meta.ip || '127.0.0.1',
        httpPort: meta.httpPort || 80,
        httpsPort: meta.httpsPort || 443,
        modules: meta.modules || [],
        createdAt: meta.createdAt || null,
        updatedAt: meta.updatedAt || null
      });
    }
  } catch (err) {
    logger.warn('INSTANCES:LIST', `Failed to read instances directory: ${err.message}`);
  }

  return instances;
}

/**
 * Delete a Vigilante instance and its associated files and k3d cluster
 * @param {string} instanceName
 * @param {Object} [options]
 * @param {boolean} [options.deleteCluster=true]
 * @param {Function} [options.onLog]
 * @returns {Promise<{ success: boolean, instanceName: string, deletedCluster: boolean, clusterStatus: string, removedInstanceDir: boolean, error?: string }>}
 */
export async function deleteInstance(instanceName = 'vigilante-dev', {
  deleteCluster = true,
  onLog = null
} = {}) {
  const safeName = sanitizePathComponent(instanceName || 'vigilante-dev');
  const instancePath = getInstanceDir(safeName);
  // Defense in depth: never recursively delete the instances root itself or
  // anything outside it, regardless of how instancePath was derived.
  assertPathStrictlyInside(getVigilanteInstancesDir(), instancePath);

  let deletedCluster = false;
  let clusterStatus = 'skipped';
  let removedInstanceDir = false;
  const errors = [];

  if (deleteCluster) {
    try {
      if (onLog) onLog(`Tearing down k3d cluster '${safeName}'...`);
      const clusterResult = await deleteK3dCluster(safeName, { onLog });
      clusterStatus = clusterResult.status;
      // deleteK3dCluster reports a missing cluster as a result, not an
      // exception. Only an actual deletion may be reported as one.
      deletedCluster = clusterResult.status === 'deleted';
    } catch (err) {
      clusterStatus = 'error';
      errors.push(`cluster deletion failed: ${err.message}`);
      logger.warn('INSTANCES:DELETE_CLUSTER', `Could not delete cluster '${safeName}': ${err.message}`);
    }
  }

  try {
    if (onLog) onLog(`Removing instance directory at ${instancePath}...`);
    await fs.rm(instancePath, { recursive: true, force: true });
    removedInstanceDir = true;
    logger.info('INSTANCES:DELETE', `Deleted instance files at ${instancePath}`);
  } catch (err) {
    errors.push(`instance directory removal failed: ${err.message}`);
    logger.warn('INSTANCES:DELETE_DIR', `Could not remove instance directory: ${err.message}`);
  }

  const result = {
    success: errors.length === 0,
    instanceName: safeName,
    deletedCluster,
    clusterStatus,
    removedInstanceDir
  };
  if (errors.length > 0) result.error = errors.join('; ');
  return result;
}
