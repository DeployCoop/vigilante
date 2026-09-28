import React, { useState, useEffect } from 'react';
import { Box, Text } from 'ink';
import { listActiveCanaries, triggerCanaryAlarm } from '../engine/deception.js';
import { useTheme } from './theme.js';

export function DeceptionView({ onBack, onTriggerAlarm }) {
  const theme = useTheme();
  const [canaries, setCanaries] = useState([]);
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState('');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const items = await listActiveCanaries();
        if (mounted) {
          setCanaries(items);
          setLoading(false);
        }
      } catch (err) {
        if (mounted) {
          setStatusMessage(`Error loading canaries: ${err.message}`);
          setLoading(false);
        }
      }
    }
    load();
    return () => { mounted = false; };
  }, []);

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%', height: '100%', padding: 1 },
    React.createElement(
      Box,
      { borderStyle: 'round', borderColor: theme.colors.primary, paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.header, bold: true }, '🪤 Vigilante Autonomous Deception Mesh ("Canary Kube")')
    ),
    React.createElement(
      Box,
      { marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.muted }, 'Active Honeytokens, Decoy ServiceAccounts, and Honeypot Network Services')
    ),
    loading
      ? React.createElement(Text, { color: theme.colors.accent }, 'Loading deployed canaries...')
      : canaries.length === 0
        ? React.createElement(
            Box,
            { flexDirection: 'column', padding: 1 },
            React.createElement(Text, { color: theme.colors.muted }, 'No canaries currently registered.'),
            React.createElement(Text, { color: theme.colors.info }, 'Deploy assets with: vigilante canary deploy [sa|secret|decoy]')
          )
        : React.createElement(
            Box,
            { flexDirection: 'column' },
            React.createElement(
              Box,
              { borderStyle: 'single', borderColor: theme.colors.border, flexDirection: 'column', paddingX: 1 },
              canaries.map((c, idx) =>
                React.createElement(
                  Box,
                  { key: c.id || idx, justifyContent: 'space-between', marginY: 0 },
                  React.createElement(
                    Text,
                    null,
                    React.createElement(Text, { color: c.tripped ? theme.colors.error : theme.colors.success, bold: true }, c.tripped ? '🚨 TRIPPED ' : '🟢 ARMED '),
                    React.createElement(Text, { color: theme.colors.accent, bold: true }, `[${c.type}] `),
                    React.createElement(Text, { color: theme.colors.text }, `${c.name} (${c.namespace})`)
                  ),
                  React.createElement(
                    Text,
                    { color: theme.colors.muted },
                    c.tripped ? `Tripped by ${c.lastTrippedBy || 'attacker'}` : `ID: ${c.id}`
                  )
                )
              )
            )
          ),
    statusMessage
      ? React.createElement(Box, { marginTop: 1 }, React.createElement(Text, { color: theme.colors.warning }, statusMessage))
      : null,
    React.createElement(
      Box,
      { marginTop: 1, borderStyle: 'single', borderColor: theme.colors.border, paddingX: 1 },
      React.createElement(Text, { color: theme.colors.muted }, '[Esc/q] Back to Hub  |  [r] Refresh  |  [d] Deploy Canary')
    )
  );
}
