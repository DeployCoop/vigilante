import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import { globalModuleRegistry } from '../modules/registry.js';
import { useClipboard } from './ClipboardManager.js';

export const ThreatSimView = ({ domain = 'vigilante.local', onDone }) => {
  const [status, setStatus] = useState('running');
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const { registerPanes } = useClipboard();

  useEffect(() => {
    registerPanes([
      {
        id: 'threat-sim',
        title: 'Threat Simulation Output',
        startRow: 6,
        endRow: 35,
        getText: () => logs.join('\n')
      }
    ]);
  }, [logs, registerPanes]);

  useEffect(() => {
    async function runSim() {
      try {
        setLogs(l => [...l, '🎯 Initializing Network Threat Simulation Pipeline...']);
        const simModule = globalModuleRegistry.get('opensearch') || globalModuleRegistry.get('vigil-soc');
        if (!simModule || typeof simModule.simulateThreats !== 'function') {
          throw new Error('OpenSearch or Vigil SOC module with threat simulation support not found in registry.');
        }

        setLogs(l => [...l, '📡 Generating ECS-formatted Network Threat Events:']);
        setLogs(l => [...l, '  • [T1046] Port Scan Reconnaissance (TCP SYN burst)']);
        setLogs(l => [...l, '  • [T1110] SSH Brute Force Authentication Flooding']);
        setLogs(l => [...l, '  • [T1071.004] DNS Tunneling / High Entropy Exfiltration']);

        await simModule.simulateThreats({
          onLog: (msg) => setLogs(l => [...l, msg])
        });

        setStatus('completed');
        if (onDone) onDone();
      } catch (err) {
        setError(err.message);
        setStatus('error');
      }
    }

    runSim();
  }, []);

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: 'magenta' },
    React.createElement(
      Text,
      { bold: true, color: 'magenta' },
      '⚡ NETWORK THREAT ANALYSIS & SIMULATION'
    ),
    React.createElement(
      Box,
      { flexDirection: 'column', marginY: 1 },
      logs.map((log, idx) =>
        React.createElement(Text, { key: idx, color: 'gray' }, log)
      )
    ),
    status === 'running'
      ? React.createElement(
          Box,
          null,
          React.createElement(Spinner, { type: 'dots' }),
          React.createElement(Text, { color: 'yellow', marginLeft: 1 }, ' Injecting threat traffic into OpenSearch SIEM...')
        )
      : null,
    status === 'completed'
      ? React.createElement(
          Box,
          { flexDirection: 'column' },
          React.createElement(Text, { color: 'green', bold: true }, '✔ Simulated threat events ingested successfully!'),
          React.createElement(
            Text,
            { color: 'cyan', marginTop: 1 },
            `View alert detections in SIEM Dashboard: https://siem.${domain}`
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(
              Text,
              { color: 'yellow', bold: true },
              '⚡ Press [s] or [Esc] to return to Status Dashboard | [q] to exit'
            )
          )
        )
      : null,
    status === 'error'
      ? React.createElement(
          Text,
          { color: 'red', bold: true },
          `✖ Threat Simulation Failed: ${error}`
        )
      : null
  );
};
