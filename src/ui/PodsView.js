import React, { useState, useEffect, useMemo } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import {
  watchPodsWide,
  getPodsWide,
  describePodInteractive,
  streamPodLogsInteractive,
  openPodShellInteractive
} from '../engine/pods.js';
import { useClipboard } from './ClipboardManager.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { logger } from '../utils/logger.js';

export const PodsView = ({
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  onNavigate = null
}) => {
  const [pods, setPods] = useState([]);
  const [loading, setLoading] = useState(true);
  const [cursor, setCursor] = useState(0);
  const [selectedNamespace, setSelectedNamespace] = useState('all');
  const [copyFeedback, setCopyFeedback] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(new Date());
  const { registerPanes } = useClipboard();

  // Set up live watcher
  useEffect(() => {
    logger.info('PODS:VIEW', `Started live pod watcher for cluster ${clusterName}`);
    setLoading(true);

    const stopWatching = watchPodsWide({
      clusterName,
      intervalMs: 2000,
      onUpdate: (latestPods) => {
        setPods(latestPods);
        setLastUpdated(new Date());
        setLoading(false);
      },
      onError: (err) => {
        logger.debug('PODS:WATCH:ERROR', err.message);
        setLoading(false);
      }
    });

    return () => {
      logger.info('PODS:VIEW', 'Stopping live pod watcher');
      stopWatching();
    };
  }, [clusterName]);

  // Extract unique namespaces for filtering
  const availableNamespaces = useMemo(() => {
    const nsSet = new Set(pods.map(p => p.namespace));
    return ['all', ...Array.from(nsSet).sort()];
  }, [pods]);

  // Filtered pods based on selected namespace
  const filteredPods = useMemo(() => {
    if (selectedNamespace === 'all') return pods;
    return pods.filter(p => p.namespace === selectedNamespace);
  }, [pods, selectedNamespace]);

  // Viewport pagination (show up to 14 rows per view)
  const pageSize = 14;
  const startIdx = Math.max(0, Math.min(cursor - Math.floor(pageSize / 2), filteredPods.length - pageSize));
  const visiblePods = filteredPods.slice(startIdx, startIdx + pageSize);

  // Text formatter for clipboard
  const formatPodsTable = () => {
    const header = `${'NAMESPACE'.padEnd(16)} ${'NAME'.padEnd(42)} ${'READY'.padEnd(8)} ${'STATUS'.padEnd(18)} ${'RESTARTS'.padEnd(10)} ${'AGE'.padEnd(8)} ${'IP'.padEnd(16)} ${'NODE'}`;
    const divider = '-'.repeat(130);
    const rows = filteredPods.map(p =>
      `${p.namespace.padEnd(16)} ${p.name.padEnd(42)} ${p.ready.padEnd(8)} ${p.status.padEnd(18)} ${String(p.restarts).padEnd(10)} ${p.age.padEnd(8)} ${p.ip.padEnd(16)} ${p.node}`
    );
    return `KUBERNETES PODS (-A -o wide) - Cluster: ${clusterName} (${new Date().toISOString()})\n${divider}\n${header}\n${divider}\n${rows.join('\n')}`;
  };

  // Register clipboard pane
  useEffect(() => {
    registerPanes([
      {
        id: 'live-pods-table',
        title: 'Kubernetes Pods (-A -o wide)',
        startRow: 6,
        endRow: 35,
        getText: formatPodsTable
      }
    ]);
  }, [filteredPods, registerPanes]);

  // Keyboard navigation & pod actions
  useInput((input, key) => {
    const keyChar = (input || '').toLowerCase();
    const selectedPod = filteredPods[cursor];

    if (key.upArrow || keyChar === 'k') {
      setCursor(c => (c > 0 ? c - 1 : Math.max(0, filteredPods.length - 1)));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setCursor(c => (c < filteredPods.length - 1 ? c + 1 : 0));
      return;
    }

    // [d] -> kubectl describe pod
    if (keyChar === 'd') {
      if (selectedPod) {
        describePodInteractive({
          clusterName,
          namespace: selectedPod.namespace,
          podName: selectedPod.name
        });
      } else {
        setCopyFeedback('✖ No pod selected to describe.');
        setTimeout(() => setCopyFeedback(null), 2500);
      }
      return;
    }

    // [l] or [L] -> kubectl logs -f
    if (keyChar === 'l') {
      if (selectedPod) {
        streamPodLogsInteractive({
          clusterName,
          namespace: selectedPod.namespace,
          podName: selectedPod.name
        });
      } else {
        setCopyFeedback('✖ No pod selected to view logs.');
        setTimeout(() => setCopyFeedback(null), 2500);
      }
      return;
    }

    // [s] or [S] -> kubectl exec -it /bin/sh (Shell)
    if (keyChar === 's') {
      if (selectedPod) {
        openPodShellInteractive({
          clusterName,
          namespace: selectedPod.namespace,
          podName: selectedPod.name
        });
      } else {
        setCopyFeedback('✖ No pod selected to connect shell.');
        setTimeout(() => setCopyFeedback(null), 2500);
      }
      return;
    }

    // [f] -> Cycle namespace filter
    if (keyChar === 'f') {
      const currentIdx = availableNamespaces.indexOf(selectedNamespace);
      const nextIdx = (currentIdx + 1) % availableNamespaces.length;
      setSelectedNamespace(availableNamespaces[nextIdx]);
      setCursor(0);
      return;
    }

    // [c] -> Copy formatted table to clipboard
    if (keyChar === 'c') {
      const text = formatPodsTable();
      copyToClipboard(text);
      setCopyFeedback(`✔ Copied ${filteredPods.length} pod records to clipboard!`);
      setTimeout(() => setCopyFeedback(null), 3000);
      return;
    }

    // [r] -> Manual refresh
    if (keyChar === 'r') {
      getPodsWide({ clusterName }).then(latest => {
        setPods(latest);
        setLastUpdated(new Date());
      });
      return;
    }

    // Navigation delegates
    if (keyChar === 'm' && onNavigate) {
      onNavigate('modules');
      return;
    }
    if (keyChar === 'v' && onNavigate) {
      onNavigate('values');
      return;
    }
    if (keyChar === 'u' && onNavigate) {
      onNavigate('up');
      return;
    }
    if (keyChar === 't' && onNavigate) {
      onNavigate('threat-sim');
      return;
    }
    if (keyChar === 'h' && onNavigate) {
      onNavigate('hostr');
      return;
    }

    // [q] or [Esc] -> Return
    if (keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  // Calculate quick metrics
  const totalPods = pods.length;
  const runningPods = pods.filter(p => p.status === 'Running' || p.status === 'Completed').length;
  const issuePods = pods.filter(p => p.status !== 'Running' && p.status !== 'Completed').length;

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: 'cyan' },

    // Header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'green', bold: true }, '●'),
        React.createElement(
          Text,
          { bold: true, color: 'cyan', marginLeft: 1 },
          'LIVE KUBERNETES POD MONITOR (-A -o wide)'
        )
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'gray' }, `Auto-updating • Updated ${lastUpdated.toLocaleTimeString()}`)
      )
    ),

    // Status summary bar & namespace filter
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'white', bold: true }, `Total: ${totalPods}  `),
        React.createElement(Text, { color: 'green', bold: true }, `Running: ${runningPods}  `),
        issuePods > 0
          ? React.createElement(Text, { color: 'yellow', bold: true }, `Pending/Restarts: ${issuePods}  `)
          : null
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'gray' }, 'Filter [f]: '),
        React.createElement(
          Text,
          { color: 'yellow', bold: true },
          selectedNamespace === 'all' ? 'All Namespaces' : selectedNamespace
        )
      )
    ),

    // Copy feedback toast
    copyFeedback
      ? React.createElement(
          Box,
          { marginY: 0, paddingX: 1, borderStyle: 'single', borderColor: 'green' },
          React.createElement(Text, { color: 'green', bold: true }, copyFeedback)
        )
      : null,

    // Table Header
    React.createElement(
      Box,
      { borderStyle: 'single', borderColor: 'gray', paddingX: 1, justifyContent: 'space-between' },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: 'cyan', wrap: 'truncate-end' }, '  NAMESPACE'.padEnd(16)),
        React.createElement(Text, { bold: true, color: 'white', wrap: 'truncate-end' }, 'NAME'.padEnd(38)),
        React.createElement(Text, { bold: true, color: 'green', wrap: 'truncate-end' }, 'READY'.padEnd(8)),
        React.createElement(Text, { bold: true, color: 'yellow', wrap: 'truncate-end' }, 'STATUS'.padEnd(18)),
        React.createElement(Text, { bold: true, color: 'magenta', wrap: 'truncate-end' }, 'RESTARTS'.padEnd(10)),
        React.createElement(Text, { bold: true, color: 'gray', wrap: 'truncate-end' }, 'AGE'.padEnd(7)),
        React.createElement(Text, { bold: true, color: 'blue', wrap: 'truncate-end' }, 'IP'.padEnd(15)),
        React.createElement(Text, { bold: true, color: 'gray', wrap: 'truncate-end' }, 'NODE')
      )
    ),

    // Pod Rows
    loading && pods.length === 0
      ? React.createElement(
          Box,
          { marginY: 1 },
          React.createElement(Spinner, { type: 'dots' }),
          React.createElement(Text, { color: 'gray', marginLeft: 1 }, ' Fetching running pods from cluster...')
        )
      : visiblePods.length === 0
      ? React.createElement(
          Box,
          { marginY: 1, paddingX: 1 },
          React.createElement(Text, { color: 'gray' }, 'No running pods found in cluster.')
        )
      : visiblePods.map((pod, idx) => {
          const absoluteIndex = startIdx + idx;
          const isFocused = absoluteIndex === cursor;

          // Status Color
          let statusColor = 'green';
          if (pod.status === 'ContainerCreating' || pod.status === 'Pending') {
            statusColor = 'yellow';
          } else if (pod.status === 'CrashLoopBackOff' || pod.status === 'Error' || pod.status === 'OOMKilled' || pod.status === 'Terminating') {
            statusColor = 'red';
          } else if (pod.status === 'Completed') {
            statusColor = 'gray';
          }

          // Truncate name if too long
          const displayName = pod.name.length > 36 ? `${pod.name.slice(0, 33)}...` : pod.name;

          return React.createElement(
            Box,
            {
              key: `${pod.namespace}-${pod.name}`,
              paddingX: 1,
              backgroundColor: isFocused ? 'gray' : undefined
            },
            React.createElement(
              Text,
              { color: isFocused ? 'yellow' : 'gray', bold: isFocused, wrap: 'truncate-end' },
              isFocused ? '❯ ' : '  '
            ),
            React.createElement(
              Text,
              { color: isFocused ? 'white' : 'cyan', wrap: 'truncate-end' },
              pod.namespace.padEnd(14)
            ),
            React.createElement(
              Text,
              { bold: isFocused, color: isFocused ? 'yellow' : 'white', wrap: 'truncate-end' },
              displayName.padEnd(38)
            ),
            React.createElement(
              Text,
              { color: pod.readyCount === pod.totalCount && pod.totalCount > 0 ? 'green' : 'gray', wrap: 'truncate-end' },
              pod.ready.padEnd(8)
            ),
            React.createElement(
              Text,
              { color: statusColor, bold: statusColor === 'red' || statusColor === 'yellow', wrap: 'truncate-end' },
              pod.status.padEnd(18)
            ),
            React.createElement(
              Text,
              { color: pod.restarts > 0 ? 'yellow' : 'gray', wrap: 'truncate-end' },
              String(pod.restarts).padEnd(10)
            ),
            React.createElement(
              Text,
              { color: 'gray', wrap: 'truncate-end' },
              pod.age.padEnd(7)
            ),
            React.createElement(
              Text,
              { color: 'blue', wrap: 'truncate-end' },
              pod.ip.padEnd(15)
            ),
            React.createElement(
              Text,
              { color: 'gray', wrap: 'truncate-end' },
              pod.node
            )
          );
        }),

    // Pagination info
    filteredPods.length > pageSize
      ? React.createElement(
          Box,
          { justifyContent: 'center', marginTop: 1 },
          React.createElement(
            Text,
            { color: 'gray', dimColor: true },
            `Showing pods ${startIdx + 1}-${Math.min(startIdx + pageSize, filteredPods.length)} of ${filteredPods.length} (Use ↑/↓ or j/k to scroll)`
          )
        )
      : null,

    // Footer actions
    React.createElement(
      Box,
      {
        marginTop: 1,
        paddingTop: 1,
        borderStyle: 'single',
        borderColor: 'gray',
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'green', bold: true }, '[d] '),
        React.createElement(Text, { color: 'white' }, 'Describe  '),
        React.createElement(Text, { color: 'cyan', bold: true }, '[L] '),
        React.createElement(Text, { color: 'white' }, 'Logs  '),
        React.createElement(Text, { color: 'magenta', bold: true }, '[S] '),
        React.createElement(Text, { color: 'white' }, 'Shell  '),
        React.createElement(Text, { color: 'yellow', bold: true }, '[f] '),
        React.createElement(Text, { color: 'white' }, 'Filter NS  '),
        React.createElement(Text, { color: 'white', bold: true }, '[c] '),
        React.createElement(Text, { color: 'white' }, 'Copy  '),
        React.createElement(Text, { color: 'gray' }, '| [m] Modules  [v] Values  [q/Esc] Return')
      ),
      React.createElement(
        Text,
        { color: 'gray', dimColor: true },
        'Auto-refreshes every 2s'
      )
    )
  );
};
