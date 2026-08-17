import { execa } from 'execa';
import { execStream } from '../utils/exec.js';
import { waitForApiServerReady } from './k8s.js';

/**
 * List all k3d clusters
 */
export async function listK3dClusters() {
  try {
    const { stdout } = await execa('k3d', ['cluster', 'list', '-o', 'json']);
    return JSON.parse(stdout || '[]');
  } catch {
    return [];
  }
}

/**
 * Create or reuse a k3d Kubernetes cluster
 */
export async function createK3dCluster(clusterName = 'vigilante-dev', options = {}) {
  const {
    httpPort = 80,
    httpsPort = 443,
    agents = 1,
    servers = 1,
    onLog = null
  } = options;

  const clusters = await listK3dClusters();
  const existingCluster = clusters.find(c => c.name === clusterName);

  if (existingCluster) {
    if (onLog) onLog(`Cluster '${clusterName}' already exists.`);
    
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
    clusterName,
    servers,
    agents
  };
}

/**
 * Delete a k3d cluster
 */
export async function deleteK3dCluster(clusterName = 'vigilante-dev', options = {}) {
  const { onLog = null } = options;
  const clusters = await listK3dClusters();
  const exists = clusters.some(c => c.name === clusterName);

  if (!exists) {
    return {
      status: 'not_found',
      clusterName
    };
  }

  if (onLog) onLog(`Deleting k3d cluster '${clusterName}'...`);
  await execa('k3d', ['cluster', 'delete', clusterName]);

  return {
    status: 'deleted',
    clusterName
  };
}

/**
 * Get detailed cluster info and health
 */
export async function getClusterInfo(clusterName = 'vigilante-dev') {
  const clusters = await listK3dClusters();
  const cluster = clusters.find(c => c.name === clusterName);

  if (!cluster) {
    return {
      exists: false,
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
      const { stdout } = await execa('kubectl', [
        'get', 'nodes',
        '--context', `k3d-${clusterName}`,
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
    clusterName,
    serversRunning: cluster.serversRunning,
    serversCount: cluster.serversCount,
    agentsRunning: cluster.agentsRunning,
    agentsCount: cluster.agentsCount,
    nodes,
    kubectlConnected
  };
}
