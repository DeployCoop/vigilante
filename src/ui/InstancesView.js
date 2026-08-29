import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { PulseIndicator } from './PulseIndicator.js';
import { listInstances, deleteInstance } from '../engine/instances.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

export const InstancesView = memo(function InstancesView({ onNavigate = null }) {
  const theme = useTheme();
  const [instances, setInstances] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [feedback, setFeedback] = useState(null);

  const loadInstances = useCallback(async () => {
    setIsLoading(true);
    try {
      const list = await listInstances();
      setInstances(list);
    } catch (err) {
      logger.error('INSTANCES_VIEW:LOAD', err.message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadInstances();
  }, [loadInstances]);

  const selectedInstance = instances[cursor] || null;

  useInput((input, key) => {
    const keyChar = (input || '').toLowerCase();

    if (key.upArrow || keyChar === 'k') {
      setCursor(c => (c > 0 ? c - 1 : Math.max(0, instances.length - 1)));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setCursor(c => (c < instances.length - 1 ? c + 1 : 0));
      return;
    }

    // Refresh [r]
    if (keyChar === 'r') {
      loadInstances();
      return;
    }

    // Deploy selected [u]
    if (keyChar === 'u' && onNavigate && selectedInstance) {
      onNavigate('up', selectedInstance.clusterName);
      return;
    }

    // Status of selected [s]
    if (keyChar === 's' && onNavigate && selectedInstance) {
      onNavigate('status', selectedInstance.clusterName);
      return;
    }

    // Pods for selected [p]
    if (keyChar === 'p' && onNavigate && selectedInstance) {
      onNavigate('pods', selectedInstance.clusterName);
      return;
    }

    // Delete instance [d] / [x]
    if ((keyChar === 'd' || keyChar === 'x') && selectedInstance) {
      deleteInstance(selectedInstance.instanceName, { deleteCluster: true }).then(() => {
        setFeedback({ type: 'success', text: `✔ Deleted instance '${selectedInstance.instanceName}'` });
        loadInstances();
      });
      return;
    }

    // Return to dashboard [q] / [Esc] / [b]
    if (keyChar === 'q' || key.escape || keyChar === 'b') {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  if (isLoading) {
    return React.createElement(
      Box,
      { padding: 1, borderStyle: 'round', borderColor: theme.border },
      React.createElement(PulseIndicator, { type: 'dots', color: theme.accent }),
      React.createElement(Text, { color: theme.accent, marginLeft: 1 }, 'Discovering k3d cluster instances...')
    );
  }

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: theme.border },

    // Header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Text,
        { color: theme.header || theme.primary, bold: true },
        '📦 VIGILANTE K3D CLUSTER INSTANCES'
      ),
      React.createElement(
        Text,
        { color: theme.accent },
        `Total Instances: ${instances.length}`
      )
    ),

    feedback
      ? React.createElement(
          Box,
          { marginY: 1, paddingX: 1, borderStyle: 'single', borderColor: theme.success },
          React.createElement(Text, { color: theme.success, bold: true }, feedback.text)
        )
      : null,

    instances.length === 0
      ? React.createElement(
          Box,
          { marginY: 1, padding: 1, borderStyle: 'single', borderColor: theme.muted },
          React.createElement(
            Text,
            { color: theme.muted },
            'No instances registered yet in $XDG_CONFIG_HOME/.vigilante/instances/. Launch an instance with "vigilante up -c <name>"!'
          )
        )
      : React.createElement(
          Box,
          { flexDirection: 'column', marginY: 1 },
          instances.map((inst, idx) => {
            const isSelected = idx === cursor;
            const statusColor = inst.k3dStatus === 'running'
              ? theme.success
              : inst.k3dStatus === 'stopped'
              ? theme.warning
              : theme.muted;

            return React.createElement(
              Box,
              {
                key: inst.instanceName,
                flexDirection: 'column',
                paddingX: 1,
                paddingY: 0,
                borderStyle: isSelected ? 'double' : 'single',
                borderColor: isSelected ? theme.accent : theme.muted,
                marginBottom: 1
              },
              React.createElement(
                Box,
                { justifyContent: 'space-between' },
                React.createElement(
                  Box,
                  null,
                  React.createElement(
                    Text,
                    { color: isSelected ? theme.accent : theme.text, bold: true },
                    `${isSelected ? '❯ ' : '  '}${inst.instanceName} `
                  ),
                  React.createElement(
                    Text,
                    { color: statusColor, bold: true },
                    `[${inst.k3dStatus.toUpperCase()}]`
                  )
                ),
                React.createElement(
                  Text,
                  { color: theme.muted },
                  `Domain: *.${inst.domain} | Ingress: ${inst.httpPort}->80, ${inst.httpsPort}->443`
                )
              ),
              React.createElement(
                Box,
                { marginLeft: 4, flexDirection: 'column' },
                React.createElement(
                  Text,
                  { color: theme.muted, dimColor: true },
                  `Path: ${inst.instanceDir}`
                ),
                React.createElement(
                  Text,
                  { color: inst.hasCerts ? theme.success : theme.warning },
                  inst.hasCerts ? `✔ TLS Certificates Present in ${inst.certsDir}` : '⚠ No certificates generated yet'
                ),
                inst.k3dStatus === 'running'
                  ? React.createElement(
                      Text,
                      { color: theme.primary },
                      `Cluster Nodes: ${inst.serversRunning}/${inst.serversCount} servers, ${inst.agentsCount} agents`
                    )
                  : null
              )
            );
          })
        ),

    // Footer actions
    React.createElement(
      Box,
      { marginTop: 1, borderStyle: 'single', borderColor: theme.muted, paddingX: 1 },
      React.createElement(Text, { color: theme.accent, bold: true }, '[u] '),
      React.createElement(Text, { color: theme.text }, 'Deploy (Up)  '),
      React.createElement(Text, { color: theme.warning, bold: true }, '[s] '),
      React.createElement(Text, { color: theme.text }, 'Status  '),
      React.createElement(Text, { color: theme.primary, bold: true }, '[p] '),
      React.createElement(Text, { color: theme.text }, 'Pods  '),
      React.createElement(Text, { color: theme.error, bold: true }, '[d] '),
      React.createElement(Text, { color: theme.text }, 'Delete  '),
      React.createElement(Text, { color: theme.text, bold: true }, '[r] '),
      React.createElement(Text, { color: theme.text }, 'Refresh  '),
      React.createElement(Text, { color: theme.muted }, '| [q/Esc] Return')
    )
  );
});
