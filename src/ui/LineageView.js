import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { buildProcessLineageTree, renderAsciiProcessTree, detectAnomalousProcessLineage } from '../engine/lineage.js';
import { useTheme } from './theme.js';

export function LineageView({ onBack }) {
  const theme = useTheme();

  const mockEvents = [
    { pid: 1, ppid: 0, comm: 'systemd' },
    { pid: 100, ppid: 1, comm: 'containerd' },
    { pid: 200, ppid: 100, comm: 'nginx', args: ['-g', 'daemon off;'], podName: 'ingress-nginx-4b7' },
    { pid: 250, ppid: 200, comm: '/bin/sh', args: ['-i'], podName: 'ingress-nginx-4b7' },
    { pid: 310, ppid: 250, comm: 'curl', args: ['-s', 'http://169.254.169.254/latest/meta-data/'], podName: 'ingress-nginx-4b7' },
    { pid: 400, ppid: 100, comm: 'kubelet' }
  ];

  const tree = buildProcessLineageTree(mockEvents);
  const anomalies = detectAnomalousProcessLineage(tree);
  const asciiTree = tree.roots.length > 0 ? renderAsciiProcessTree(tree.roots[0]) : 'No active lineage';

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%', height: '100%', padding: 1 },
    React.createElement(
      Box,
      { borderStyle: 'round', borderColor: theme.colors.primary, paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.header, bold: true }, '🐝 Kernel-Native eBPF Lineage & Process Ancestry Engine')
    ),
    React.createElement(
      Box,
      { marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.muted }, 'Hierarchical Process Ancestry, Shell Spawns, and Breakout Detection')
    ),
    React.createElement(
      Box,
      { borderStyle: 'single', borderColor: anomalies.length > 0 ? theme.colors.error : theme.colors.success, flexDirection: 'column', padding: 1, marginBottom: 1 },
      React.createElement(Text, { color: anomalies.length > 0 ? theme.colors.error : theme.colors.success, bold: true }, `Active Anomalies (${anomalies.length}):`),
      anomalies.map((a, i) =>
        React.createElement(
          Box,
          { key: i, marginY: 0 },
          React.createElement(Text, { color: theme.colors.error }, `🚨 [${a.mitreTechnique}] ${a.message}`)
        )
      )
    ),
    React.createElement(
      Box,
      { borderStyle: 'single', borderColor: theme.colors.border, flexDirection: 'column', padding: 1 },
      React.createElement(Text, { color: theme.colors.accent, bold: true }, 'Process Hierarchy Tree:'),
      React.createElement(Text, { color: theme.colors.text }, asciiTree)
    ),
    React.createElement(
      Box,
      { marginTop: 1, borderStyle: 'single', borderColor: theme.colors.border, paddingX: 1 },
      React.createElement(Text, { color: theme.colors.muted }, '[Esc/q] Back to Hub  |  [r] Refresh Trace  |  [x] Isolate Anomalous Workload')
    )
  );
}
