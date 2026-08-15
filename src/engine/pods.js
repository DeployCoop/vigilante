import { execa } from 'execa';
import { logger } from '../utils/logger.js';

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

  async function poll() {
    if (!active) return;
    try {
      const pods = await getPodsWide({ clusterName, namespace });
      if (active && onUpdate) {
        onUpdate(pods);
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
