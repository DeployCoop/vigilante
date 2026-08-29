import { execa } from 'execa';
import { logger } from '../utils/logger.js';

/**
 * Apply Kubernetes manifest YAML with validation fallback and transient error retries
 * @param {string} yamlContent - YAML string to apply via stdin
 * @param {Object} [options] - Options
 * @param {number} [options.maxRetries=6] - Maximum retry attempts
 * @param {number} [options.retryDelayMs=1000] - Base delay between retries
 * @param {Function} [options.onLog] - Log callback
 * @returns {Promise<string>} - kubectl stdout
 */
export async function safeKubectlApply(yamlContent, options = {}) {
  const { maxRetries = 6, retryDelayMs = 1000, onLog = null } = options;

  let lastError;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const { stdout } = await execa('kubectl', [
        'apply',
        '--validate=false',
        '-f', '-'
      ], {
        input: yamlContent
      });
      return stdout;
    } catch (err) {
      lastError = err;
      const msg = err.message || '';
      const isTransient = msg.includes('failed to download openapi') ||
                          msg.includes('unable to handle the request') ||
                          msg.includes('connection refused') ||
                          msg.includes('i/o timeout') ||
                          msg.includes('EOF') ||
                          msg.includes('503 Service Unavailable');

      if (isTransient && attempt < maxRetries) {
        const waitMs = retryDelayMs * attempt;
        logger.warn('K8S:APPLY_RETRY', `Kubernetes API server transient error (attempt ${attempt}/${maxRetries}): ${msg}. Retrying in ${waitMs}ms...`);
        if (onLog) {
          onLog(`Kubernetes API server warming up (attempt ${attempt}/${maxRetries}). Retrying apply in ${(waitMs / 1000).toFixed(1)}s...`);
        }
        await new Promise((r) => setTimeout(r, waitMs));
      } else {
        throw err;
      }
    }
  }

  throw lastError;
}

/**
 * Ensure target Kubernetes namespace exists safely
 * @param {string} namespace - Target namespace name
 * @param {Object} [options] - Options
 */
export async function ensureNamespace(namespace = 'default', options = {}) {
  if (!namespace || namespace === 'default') {
    return;
  }

  const { onLog = null } = options;

  try {
    // Check if namespace already exists
    await execa('kubectl', ['get', 'namespace', namespace, '--request-timeout=5s']);
    return;
  } catch {
    // Namespace does not exist or API call failed; attempt creation
  }

  try {
    await execa('kubectl', ['create', 'namespace', namespace]);
    if (onLog) onLog(`✔ Created Kubernetes namespace '${namespace}'.`);
  } catch (createErr) {
    const errMsg = createErr.message || '';
    if (errMsg.includes('AlreadyExists') || createErr.stderr?.includes('AlreadyExists')) {
      return;
    }

    // Fallback: apply via dry-run YAML with retries and --validate=false
    try {
      const { stdout } = await execa('kubectl', [
        'create', 'namespace', namespace,
        '--dry-run=client', '-o', 'yaml'
      ]);
      await safeKubectlApply(stdout, options);
    } catch (finalErr) {
      if (!finalErr.message?.includes('AlreadyExists')) {
        throw finalErr;
      }
    }
  }
}

/**
 * Wait for Kubernetes API server to be fully ready and responsive
 * @param {string} [clusterName='vigilante-dev']
 * @param {number} [timeoutMs=60000]
 * @param {Function} [onLog]
 */
export async function waitForApiServerReady(clusterName = 'vigilante-dev', timeoutMs = 60000, onLog = null) {
  const startTime = Date.now();
  logger.info('K8S:WAIT_READY', `Waiting for Kubernetes API server '${clusterName}' to become ready...`);

  while (Date.now() - startTime < timeoutMs) {
    try {
      const { stdout } = await execa('kubectl', [
        'get', '--raw', '/readyz',
        '--request-timeout=3s'
      ]);
      if (stdout && stdout.trim() === 'ok') {
        logger.info('K8S:READY', `Kubernetes API server '${clusterName}' /readyz returned ok.`);
        return true;
      }
    } catch {
      // API server not ready yet
    }

    try {
      const { stdout } = await execa('kubectl', [
        'get', 'namespaces',
        '--request-timeout=3s'
      ]);
      if (stdout && stdout.includes('default')) {
        logger.info('K8S:READY', `Kubernetes API server '${clusterName}' listed namespaces successfully.`);
        return true;
      }
    } catch {
      // Still warming up
    }

    await new Promise((r) => setTimeout(r, 1500));
  }

  return false;
}
