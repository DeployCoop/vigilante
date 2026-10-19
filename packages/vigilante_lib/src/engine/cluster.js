import { execa } from 'execa';
import fsSync from 'node:fs';
import { execStream, commandExists } from '../utils/exec.js';
import { logger } from '../utils/logger.js';
import { waitForApiServerReady, getClusterContextArgs } from './k8s.js';
import { assertCliTarget } from './config.js';

export { getClusterContextArgs };

/**
 * List all k3d clusters
 */
export async function listK3dClusters() {
  try {
    const { stdout } = await execa('k3d', ['cluster', 'list', '-o', 'json']);
    return JSON.parse(stdout || '[]');
  } catch (err) {
    // A broken/missing k3d must not be indistinguishable from "no
    // clusters": callers still get [] (their contract), but the failure
    // is on the record instead of being swallowed silently.
    logger.warn('CLUSTER', `'k3d cluster list' failed (${err.message}); treating as no clusters.`);
    return [];
  }
}

/**
 * Detect if k3s is active or available on the host
 * @returns {Promise<{ available: boolean, hasK3sBinary: boolean, hasK3sKubeconfig: boolean, serviceActive: boolean, kubectlK3sConnected: boolean }>}
 */
export async function detectK3sAvailability() {
  const hasK3sBinary = await commandExists('k3s');
  let hasK3sKubeconfig = false;
  try {
    hasK3sKubeconfig = fsSync.existsSync('/etc/rancher/k3s/k3s.yaml');
  } catch {
    hasK3sKubeconfig = false;
  }

  let serviceActive = false;
  if (hasK3sBinary) {
    try {
      const { stdout } = await execa('systemctl', ['is-active', 'k3s']);
      serviceActive = stdout.trim() === 'active';
    } catch {
      serviceActive = false;
    }
  }

  let kubectlK3sConnected = false;
  try {
    const { stdout } = await execa('kubectl', ['get', 'nodes', '-o', 'json', '--request-timeout=2s']);
    const parsed = JSON.parse(stdout || '{"items":[]}');
    kubectlK3sConnected = (parsed.items || []).some(n =>
      n.status?.nodeInfo?.kubeletVersion?.includes('+k3s')
    );
  } catch {
    kubectlK3sConnected = false;
  }

  return {
    available: hasK3sBinary || hasK3sKubeconfig || kubectlK3sConnected,
    hasK3sBinary,
    hasK3sKubeconfig,
    serviceActive,
    kubectlK3sConnected
  };
}

/**
 * List all k3s clusters detected on the host
 * @returns {Promise<Array<Object>>}
 */
export async function listK3sClusters() {
  const detection = await detectK3sAvailability();
  if (!detection.available) {
    return [];
  }

  const isRunning = detection.serviceActive || detection.kubectlK3sConnected;
  return [{
    name: 'k3s-default',
    provider: 'k3s',
    serversRunning: isRunning ? 1 : 0,
    serversCount: 1,
    agentsRunning: 0,
    agentsCount: 0
  }];
}

/**
 * Resolve the appropriate kubectl context for a cluster and provider
 * @param {string} [clusterName='vigilante-dev']
 * @param {string} [provider=null] - 'k3d' | 'k3s' | null
 * @returns {Promise<string|null>}
 */
export async function resolveKubeContext(clusterName = 'vigilante-dev', provider = null) {
  try {
    const { stdout } = await execa('kubectl', ['config', 'get-contexts', '-o', 'name']);
    const contexts = stdout.split('\n').map(c => c.trim()).filter(Boolean);

    if (provider === 'k3s') {
      if (contexts.includes(`k3s-${clusterName}`)) return `k3s-${clusterName}`;
      if (contexts.includes('k3s')) return 'k3s';
      if (contexts.includes('default')) return 'default';
      const { stdout: cur } = await execa('kubectl', ['config', 'current-context']);
      return cur.trim() || null;
    }

    if (provider === 'k3d') {
      return `k3d-${clusterName}`;
    }

    // Auto-detect based on context name precedence:
    if (contexts.includes(`k3d-${clusterName}`)) return `k3d-${clusterName}`;
    if (contexts.includes(`k3s-${clusterName}`)) return `k3s-${clusterName}`;
    if (contexts.includes('k3s')) return 'k3s';
    if (contexts.includes('default')) return 'default';
    const { stdout: cur } = await execa('kubectl', ['config', 'current-context']);
    return cur.trim() || `k3d-${clusterName}`;
  } catch {
    return provider === 'k3s' ? 'default' : `k3d-${clusterName}`;
  }
}

/**
 * Synchronous fallback to get expected cluster context string
 * @param {string} [clusterName='vigilante-dev']
 * @param {string} [provider='k3d']
 * @returns {string}
 */
export function getClusterContext(clusterName = 'vigilante-dev', provider = 'k3d') {
  if (provider === 'k3s') {
    return `k3s-${clusterName}`;
  }
  return `k3d-${clusterName}`;
}

/**
 * Create or reuse a k3s Kubernetes cluster on host
 * @param {string} [clusterName='vigilante-dev']
 * @param {Object} [options]
 */
export async function createK3sCluster(clusterName = 'vigilante-dev', options = {}) {
  const { onLog = null } = options;

  if (onLog) onLog(`[k3s] Initializing K3s cluster target '${clusterName}'...`);

  const detection = await detectK3sAvailability();

  // If systemd service exists and is inactive, start it
  if (detection.hasK3sBinary && !detection.serviceActive && !detection.kubectlK3sConnected) {
    if (onLog) onLog(`[k3s] Starting local k3s system service...`);
    try {
      await execa('systemctl', ['start', 'k3s']);
      if (onLog) onLog(`[k3s] Started systemctl k3s service.`);
    } catch (startErr) {
      if (onLog) onLog(`[k3s] Notice: Could not start systemctl k3s (${startErr.message}).`);
    }
  }

  // Ensure KUBECONFIG if /etc/rancher/k3s/k3s.yaml exists and not already set
  if (detection.hasK3sKubeconfig && !process.env.KUBECONFIG) {
    try {
      await execa('kubectl', ['get', 'nodes', '--request-timeout=2s']);
    } catch {
      process.env.KUBECONFIG = '/etc/rancher/k3s/k3s.yaml';
      if (onLog) onLog(`[k3s] Set KUBECONFIG=/etc/rancher/k3s/k3s.yaml for cluster session.`);
    }
  }

  // Switch context if needed
  const targetContext = await resolveKubeContext(clusterName, 'k3s');
  if (targetContext) {
    try {
      await execa('kubectl', ['config', 'use-context', targetContext]);
      if (onLog) onLog(`[k3s] Using kubectl context '${targetContext}'.`);
    } catch {
      // Context switch fallback
    }
  }

  // Wait for all nodes to be ready
  if (onLog) onLog(`[k3s] Waiting for Kubernetes nodes to reach Ready state...`);
  try {
    const ctxArgs = targetContext ? ['--context', targetContext] : [];
    await execa('kubectl', ['wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=120s', ...ctxArgs]);
  } catch (err) {
    if (onLog) onLog(`[k3s] Note: Nodes status check returned: ${err.message}`);
  }

  // Ensure Kubernetes API server is fully warmed up and responsive
  await waitForApiServerReady(clusterName, 60000, onLog);

  if (onLog) onLog(`[k3s] ✔ K3s cluster target '${clusterName}' is ready for chart deployments.`);

  return {
    status: 'ready',
    provider: 'k3s',
    clusterName,
    servers: 1,
    agents: 0
  };
}

/**
 * Delete or clean up a k3s cluster target
 * @param {string} [clusterName='vigilante-dev']
 * @param {Object} [options]
 */
export async function deleteK3sCluster(clusterName = 'vigilante-dev', options = {}) {
  const { onLog = null, stopService = false } = options;

  if (onLog) onLog(`[k3s] Cleaning up K3s target '${clusterName}'...`);

  if (stopService) {
    try {
      await execa('systemctl', ['stop', 'k3s']);
      if (onLog) onLog(`[k3s] Stopped k3s system service.`);
    } catch (err) {
      if (onLog) onLog(`[k3s] Could not stop k3s service: ${err.message}`);
    }
  }

  return {
    status: 'deleted',
    provider: 'k3s',
    clusterName
  };
}

/**
 * Unified cluster creator: supports both k3d and k3s
 * @param {string} [clusterName='vigilante-dev']
 * @param {Object} [options]
 * @param {string} [options.provider='k3d'] - 'k3d' | 'k3s'
 */
export async function createCluster(clusterName = 'vigilante-dev', options = {}) {
  const provider = options.provider || 'k3d';
  if (provider === 'k3s') {
    return createK3sCluster(clusterName, options);
  }
  return createK3dCluster(clusterName, options);
}

/**
 * Unified cluster deleter: supports both k3d and k3s
 * @param {string} [clusterName='vigilante-dev']
 * @param {Object} [options]
 * @param {string} [options.provider='k3d'] - 'k3d' | 'k3s'
 */
export async function deleteCluster(clusterName = 'vigilante-dev', options = {}) {
  const provider = options.provider || 'k3d';
  if (provider === 'k3s') {
    return deleteK3sCluster(clusterName, options);
  }
  return deleteK3dCluster(clusterName, options);
}

/**
 * Unified cluster lister: supports both k3d and k3s
 * @param {Object} [options]
 * @param {string} [options.provider] - 'k3d' | 'k3s' | 'all'
 */
export async function listClusters({ provider = null } = {}) {
  if (provider === 'k3s') {
    return listK3sClusters();
  }
  if (provider === 'k3d') {
    return listK3dClusters();
  }
  const [k3dList, k3sList] = await Promise.all([
    listK3dClusters(),
    listK3sClusters()
  ]);
  return [...k3dList, ...k3sList];
}

/**
 * Create or reuse a k3d Kubernetes cluster
 */
export async function createK3dCluster(clusterName = 'vigilante-dev', options = {}) {
  // The name is a positional k3d argument (and becomes a kubectl context
  // suffix): reject option-shaped or whitespace-bearing values.
  assertCliTarget(clusterName, 'cluster name');
  const {
    httpPort = 80,
    httpsPort = 443,
    agents = 1,
    servers = 1,
    onLog = null
  } = options;

  for (const [label, port] of [['httpPort', httpPort], ['httpsPort', httpsPort]]) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error(`Invalid ${label} '${port}': expected an integer TCP port (1-65535).`);
    }
  }

  const clusters = await listK3dClusters();
  const existingCluster = clusters.find(c => c.name === clusterName);

  if (existingCluster) {
    if (onLog) onLog(`Cluster '${clusterName}' already exists.`);
    if ((options.httpPort !== undefined || options.httpsPort !== undefined) && onLog) {
      onLog(`Note: requested port bindings (${httpPort}->80, ${httpsPort}->443) are NOT re-applied to an existing cluster; it keeps its original bindings. Delete and recreate the cluster to change them.`);
    }
    
    // Check if stopped and start if needed
    if (existingCluster.serversRunning === 0) {
      if (onLog) onLog(`Starting existing stopped cluster '${clusterName}'...`);
      await execa('k3d', ['cluster', 'start', clusterName]);
    }

    // Ensure kubectl context is pointing to this cluster
    try {
      await execa('kubectl', ['config', 'use-context', `k3d-${clusterName}`]);
    } catch {
      // Ignore if context name differs
    }

    return {
      status: 'exists',
      provider: 'k3d',
      clusterName,
      servers: existingCluster.serversCount,
      agents: existingCluster.agentsCount
    };
  }

  if (onLog) onLog(`Provisioning new k3d cluster '${clusterName}' with Ingress port bindings (${httpPort}->80, ${httpsPort}->443)...`);

  const k3dArgs = [
    'cluster', 'create', clusterName,
    '--servers', String(servers),
    '--agents', String(agents),
    '-p', `${httpPort}:80@loadbalancer`,
    '-p', `${httpsPort}:443@loadbalancer`,
    '--wait'
  ];

  await execStream('k3d', k3dArgs, { onLog });

  // Set kubectl context
  try {
    await execa('kubectl', ['config', 'use-context', `k3d-${clusterName}`]);
  } catch {
    // context switch fallback
  }

  // Wait for all nodes to be ready
  if (onLog) onLog('Waiting for Kubernetes nodes to reach Ready state...');
  try {
    await execa('kubectl', ['wait', '--for=condition=Ready', 'nodes', '--all', '--timeout=120s']);
  } catch {
    // Non-fatal if timeout or condition isn't reached immediately
  }

  // Ensure Kubernetes API server is fully warmed up and responsive
  await waitForApiServerReady(clusterName, 60000, onLog);

  return {
    status: 'created',
    provider: 'k3d',
    clusterName,
    servers,
    agents
  };
}

/**
 * Delete a k3d cluster
 */
export async function deleteK3dCluster(clusterName = 'vigilante-dev', options = {}) {
  assertCliTarget(clusterName, 'cluster name');
  const { onLog = null } = options;
  const clusters = await listK3dClusters();
  const exists = clusters.some(c => c.name === clusterName);

  if (!exists) {
    return {
      status: 'not_found',
      provider: 'k3d',
      clusterName
    };
  }

  if (onLog) onLog(`Deleting k3d cluster '${clusterName}'...`);
  await execa('k3d', ['cluster', 'delete', clusterName]);

  return {
    status: 'deleted',
    provider: 'k3d',
    clusterName
  };
}

/**
 * Get detailed cluster info and health across k3d and k3s
 * @param {string} [clusterName='vigilante-dev']
 * @param {string} [provider=null] - 'k3d' | 'k3s' | null
 */
export async function getClusterInfo(clusterName = 'vigilante-dev', provider = null) {
  const targetContext = await resolveKubeContext(clusterName, provider);
  const isK3s = provider === 'k3s' || (targetContext && !targetContext.startsWith('k3d-'));

  if (isK3s) {
    const k3sClusters = await listK3sClusters();
    const cluster = k3sClusters.find(c => c.name === clusterName || c.name === 'k3s-default') || {
      serversRunning: 1,
      serversCount: 1,
      agentsRunning: 0,
      agentsCount: 0
    };

    let nodes = [];
    let kubectlConnected = false;

    try {
      const ctxArgs = targetContext ? ['--context', targetContext] : [];
      const { stdout } = await execa('kubectl', [
        'get', 'nodes',
        ...ctxArgs,
        '--request-timeout=3s',
        '-o', 'json'
      ]);
      const parsed = JSON.parse(stdout);
      nodes = parsed.items?.map(node => ({
        name: node.metadata.name,
        status: node.status.conditions?.find(c => c.type === 'Ready')?.status === 'True' ? 'Ready' : 'NotReady',
        roles: Object.keys(node.metadata.labels || {})
          .filter(l => l.startsWith('node-role.kubernetes.io/'))
          .map(l => l.replace('node-role.kubernetes.io/', '')),
        kubeletVersion: node.status.nodeInfo?.kubeletVersion
      })) || [];
      kubectlConnected = true;
    } catch {
      kubectlConnected = false;
    }

    return {
      exists: true,
      provider: 'k3s',
      clusterName,
      serversRunning: cluster.serversRunning,
      serversCount: cluster.serversCount,
      agentsRunning: cluster.agentsRunning,
      agentsCount: cluster.agentsCount,
      nodes,
      kubectlConnected
    };
  }

  const clusters = await listK3dClusters();
  const cluster = clusters.find(c => c.name === clusterName);

  if (!cluster) {
    return {
      exists: false,
      provider: 'k3d',
      clusterName,
      serversRunning: 0,
      serversCount: 0,
      agentsRunning: 0,
      agentsCount: 0,
      nodes: [],
      kubectlConnected: false
    };
  }

  let nodes = [];
  let kubectlConnected = false;

  if (cluster.serversRunning > 0) {
    try {
      const ctxArgs = targetContext ? ['--context', targetContext] : ['--context', `k3d-${clusterName}`];
      const { stdout } = await execa('kubectl', [
        'get', 'nodes',
        ...ctxArgs,
        '--request-timeout=3s',
        '-o', 'json'
      ]);
      const parsed = JSON.parse(stdout);
      nodes = parsed.items?.map(node => ({
        name: node.metadata.name,
        status: node.status.conditions?.find(c => c.type === 'Ready')?.status === 'True' ? 'Ready' : 'NotReady',
        roles: Object.keys(node.metadata.labels || {})
          .filter(l => l.startsWith('node-role.kubernetes.io/'))
          .map(l => l.replace('node-role.kubernetes.io/', '')),
        kubeletVersion: node.status.nodeInfo?.kubeletVersion
      })) || [];
      kubectlConnected = true;
    } catch {
      kubectlConnected = false;
    }
  }

  return {
    exists: true,
    provider: 'k3d',
    clusterName,
    serversRunning: cluster.serversRunning,
    serversCount: cluster.serversCount,
    agentsRunning: cluster.agentsRunning,
    agentsCount: cluster.agentsCount,
    nodes,
    kubectlConnected
  };
}

