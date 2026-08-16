import { execa } from 'execa';
import { spawnSync } from 'node:child_process';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { logger } from '../utils/logger.js';
import { runInteractiveTerminal } from '../utils/terminal-runner.js';

/**
 * Format age from ISO timestamp into concise human string (e.g. 12s, 4m, 2h, 5d)
 * @param {string} timestamp
 * @returns {string}
 */
export function formatAge(timestamp) {
  if (!timestamp) return '<unknown>';
  const diffMs = Date.now() - new Date(timestamp).getTime();
  if (isNaN(diffMs) || diffMs < 0) return '0s';

  const seconds = Math.floor(diffMs / 1000);
  if (seconds < 60) return `${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h`;

  const days = Math.floor(hours / 24);
  return `${days}d`;
}

/**
 * Compute human pod status identical to `kubectl get pods`
 * @param {Object} pod
 * @returns {string}
 */
export function computePodStatus(pod) {
  if (pod.metadata?.deletionTimestamp) {
    return 'Terminating';
  }

  const containerStatuses = [
    ...(pod.status?.initContainerStatuses || []),
    ...(pod.status?.containerStatuses || [])
  ];

  for (const cs of containerStatuses) {
    if (cs.state?.waiting?.reason) {
      return cs.state.waiting.reason;
    }
    if (cs.state?.terminated?.reason) {
      return cs.state.terminated.reason;
    }
  }

  return pod.status?.phase || 'Unknown';
}

/**
 * Query all pods with detailed information matching `kubectl get pods -A -o wide`
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} [options.namespace]
 * @returns {Promise<Array<Object>>}
 */
export async function getPodsWide({ clusterName = 'vigilante-dev', namespace = null } = {}) {
  const args = ['get', 'pods'];
  if (namespace && namespace !== 'all') {
    args.push('-n', namespace);
  } else {
    args.push('-A');
  }

  if (clusterName) {
    args.push('--context', `k3d-${clusterName}`);
  }

  args.push('--request-timeout=4s', '-o', 'json');

  try {
    const { stdout } = await execa('kubectl', args);
    const parsed = JSON.parse(stdout || '{"items":[]}');
    const items = parsed.items || [];

    return items.map((pod) => {
      const totalContainers = pod.spec?.containers?.length || 0;
      const readyContainers = (pod.status?.containerStatuses || []).filter(c => c.ready).length;
      const readyStr = `${readyContainers}/${totalContainers}`;

      const totalRestarts = (pod.status?.containerStatuses || []).reduce(
        (sum, c) => sum + (c.restartCount || 0),
        0
      );

      const status = computePodStatus(pod);
      const age = formatAge(pod.metadata?.creationTimestamp);
      const ip = pod.status?.podIP || '<none>';
      const node = pod.spec?.nodeName || '<none>';
      const nominatedNode = pod.status?.nominatedNodeName || '<none>';
      const readinessGates = (pod.spec?.readinessGates?.length || 0) > 0 ? String(pod.spec.readinessGates.length) : '<none>';

      return {
        namespace: pod.metadata?.namespace || 'default',
        name: pod.metadata?.name || 'unknown',
        ready: readyStr,
        readyCount: readyContainers,
        totalCount: totalContainers,
        status,
        restarts: totalRestarts,
        age,
        ip,
        node,
        nominatedNode,
        readinessGates,
        creationTimestamp: pod.metadata?.creationTimestamp
      };
    });
  } catch (err) {
    logger.debug('PODS:GET', `kubectl get pods query failed: ${err.message}`);
    return [];
  }
}

/**
 * Deep compare two pod arrays to avoid redundant state updates and UI re-renders
 * @param {Array<Object>} a
 * @param {Array<Object>} b
 * @returns {boolean}
 */
export function arePodsEqual(a, b) {
  if (a === b) return true;
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    const p1 = a[i];
    const p2 = b[i];
    if (
      p1.namespace !== p2.namespace ||
      p1.name !== p2.name ||
      p1.ready !== p2.ready ||
      p1.status !== p2.status ||
      p1.restarts !== p2.restarts ||
      p1.age !== p2.age ||
      p1.ip !== p2.ip ||
      p1.node !== p2.node
    ) {
      return false;
    }
  }
  return true;
}

/**
 * Set up a live poller for pods matching `kubectl get pods -A -o wide`
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} [options.namespace]
 * @param {number} [options.intervalMs]
 * @param {Function} options.onUpdate
 * @param {Function} [options.onError]
 * @returns {Function} stop polling function
 */
export function watchPodsWide({
  clusterName = 'vigilante-dev',
  namespace = null,
  intervalMs = 2000,
  onUpdate,
  onError = null
}) {
  let active = true;
  let timerId = null;
  let lastPods = null;

  async function poll() {
    if (!active) return;
    try {
      const pods = await getPodsWide({ clusterName, namespace });
      if (active && onUpdate) {
        if (!lastPods || !arePodsEqual(lastPods, pods)) {
          lastPods = pods;
          onUpdate(pods);
        }
      }
    } catch (err) {
      if (active && onError) {
        onError(err);
      }
    } finally {
      if (active) {
        timerId = setTimeout(poll, intervalMs);
      }
    }
  }

  // Initial fetch immediately
  poll();

  return () => {
    active = false;
    if (timerId) {
      clearTimeout(timerId);
      timerId = null;
    }
  };
}

/**
 * Open text content in the system pager ($PAGER or less -R) and wait for user to exit
 * @param {string} content
 * @param {string} filenameHint
 */
export function openInSystemPager(content, filenameHint = 'output.txt') {
  if (!content) return;
  const pager = process.env.PAGER || 'less -R';
  const tmpFile = path.join(os.tmpdir(), `vigilante-${Date.now()}-${filenameHint}`);

  try {
    fsSync.writeFileSync(tmpFile, content, 'utf8');
  } catch (err) {
    logger.warn('PODS:PAGER', `Could not write temporary file: ${err.message}`);
    return;
  }

  runInteractiveTerminal(() => {
    try {
      const parts = pager.trim().split(/\s+/);
      const bin = parts[0];
      const args = [...parts.slice(1), tmpFile];
      spawnSync(bin, args, {
        stdio: 'inherit'
      });
    } catch (err) {
      logger.error('PODS:PAGER', `Failed to open pager: ${err.message}`, err);
    }
  });

  try {
    fsSync.unlinkSync(tmpFile);
  } catch {
    // Ignore cleanup error
  }
}

/**
 * Interactively describe a pod with the system pager
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} options.namespace
 * @param {string} options.podName
 */
export function describePodInteractive({ clusterName = 'vigilante-dev', namespace, podName }) {
  if (!podName || !namespace) return;
  logger.info('PODS:DESCRIBE', `Running kubectl describe pod ${podName} -n ${namespace}`);
  let output = '';
  try {
    const res = spawnSync('kubectl', [
      'describe',
      'pod',
      podName,
      '-n',
      namespace,
      '--context',
      `k3d-${clusterName}`
    ], { encoding: 'utf8' });
    output = res.stdout || res.stderr || 'No describe output available.';
  } catch (err) {
    output = `Failed to execute kubectl describe: ${err.message}`;
  }
  openInSystemPager(output, `describe-${namespace}-${podName}.txt`);
}

/**
 * Interactively view pod logs in the system pager
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} options.namespace
 * @param {string} options.podName
 */
export function viewPodLogsInteractive({ clusterName = 'vigilante-dev', namespace, podName }) {
  if (!podName || !namespace) return;
  logger.info('PODS:LOGS', `Viewing kubectl logs for ${podName} -n ${namespace}`);
  let output = '';
  try {
    const res = spawnSync('kubectl', [
      'logs',
      '--tail=5000',
      podName,
      '-n',
      namespace,
      '--context',
      `k3d-${clusterName}`,
      '--all-containers=true'
    ], { encoding: 'utf8' });
    output = res.stdout || res.stderr || 'No logs available for this pod.';
  } catch (err) {
    output = `Failed to retrieve logs: ${err.message}`;
  }
  openInSystemPager(output, `logs-${namespace}-${podName}.log`);
}

/**
 * Alias for viewPodLogsInteractive
 */
export const streamPodLogsInteractive = viewPodLogsInteractive;

/**
 * Interactively open a shell into a pod
 * @param {Object} options
 * @param {string} [options.clusterName]
 * @param {string} options.namespace
 * @param {string} options.podName
 */
export function openPodShellInteractive({ clusterName = 'vigilante-dev', namespace, podName }) {
  if (!podName || !namespace) return;
  logger.info('PODS:SHELL', `Opening shell into pod ${podName} -n ${namespace}`);
  runInteractiveTerminal(() => {
    console.log(`\x1b[1;32m=== Connecting interactive shell to pod: ${namespace}/${podName} (Type 'exit' to return to Vigilante) ===\x1b[0m\n`);
    spawnSync('kubectl', [
      'exec',
      '-it',
      podName,
      '-n',
      namespace,
      '--context',
      `k3d-${clusterName}`,
      '--',
      '/bin/sh',
      '-c',
      'command -v bash >/dev/null 2>&1 && exec bash || exec sh'
    ], { stdio: 'inherit' });
  });
}
