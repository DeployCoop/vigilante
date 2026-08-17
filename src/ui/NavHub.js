import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';
import { useTheme } from './theme.js';

export const HUB_ITEMS = [
  // Section 1: Workflows & Provisioning
  {
    id: 'up',
    section: '🚀 Workflows & Provisioning',
    title: 'Cluster Up & Full Provisioning',
    subtitle: 'Deploy k3d cluster, TLS certificates, DNS & security modules',
    key: '1',
    altKey: 'u',
    action: 'UP'
  },
  {
    id: 'modules',
    section: '🚀 Workflows & Provisioning',
    title: 'Security Modules & Packages',
    subtitle: 'Manage SIEM, SOC, and tooling per-namespace (press [n] inside for namespace)',
    key: '2',
    altKey: 'm',
    action: 'MODULES'
  },
  {
    id: 'values',
    section: '🚀 Workflows & Provisioning',
    title: 'Helm Values Editor & Overrides',
    subtitle: 'Inspect and configure chart parameters and XDG overrides',
    key: '3',
    altKey: 'v',
    action: 'VALUES'
  },
  {
    id: 'instances',
    section: '🚀 Workflows & Provisioning',
    title: 'Cluster Instances Manager',
    subtitle: 'Manage isolated multi-cluster k3d instances and certs',
    key: '4',
    altKey: 'i',
    action: 'INSTANCES'
  },
  {
    id: 'down',
    section: '🚀 Workflows & Provisioning',
    title: 'Cluster Teardown (Down)',
    subtitle: 'Destroy k3d cluster and clean up local ingress routes',
    key: '5',
    altKey: 'd',
    action: 'DOWN'
  },

  // Section 2: Infrastructure Status & Diagnostics
  {
    id: 'status',
    section: '📊 Infrastructure Status & Diagnostics',
    title: 'Environment Status Dashboard',
    subtitle: 'Live cluster health, TLS certs, ingress routes & DNS status',
    key: '6',
    altKey: 's',
    action: 'DASHBOARD'
  },
  {
    id: 'pods',
    section: '📊 Infrastructure Status & Diagnostics',
    title: 'Kubernetes Live Pods Monitor',
    subtitle: 'Real-time kubectl -A -o wide table with logs, describe & shell',
    key: '7',
    altKey: 'p',
    action: 'PODS'
  },
  {
    id: 'threat-sim',
    section: '📊 Infrastructure Status & Diagnostics',
    title: 'Threat Simulation Engine',
    subtitle: 'Inject simulated security events and attacks into SIEM',
    key: '8',
    altKey: 't',
    action: 'THREAT_SIM'
  },
  {
    id: 'hosts',
    section: '📊 Infrastructure Status & Diagnostics',
    title: 'Local /etc/hosts Sync (hostr)',
    subtitle: 'Synchronize local *.domain ingress mappings',
    key: '9',
    altKey: 'h',
    action: 'HOSTR'
  },

  // Section 3: Network Reconnaissance & Forensics
  {
    id: 'nmap',
    section: '🌐 Network Reconnaissance & Forensics',
    title: 'Nmap Network Reconnaissance & Scanner',
    subtitle: 'Run subnet sweeps, service detection & vulnerability scans',
    key: '0',
    altKey: 'n',
    action: 'NMAP'
  },
  {
    id: 'xml-visualizer',
    section: '🌐 Network Reconnaissance & Forensics',
    title: 'XML Network Topology Visualizer',
    subtitle: 'Interactive host matrix with ping, ab, mtr, curl & dig diagnostics',
    key: 'x',
    altKey: null,
    action: 'XML_VISUALIZER'
  },

  // Section 4: Configuration & Settings
  {
    id: 'config',
    section: '⚙️ Configuration & Settings',
    title: 'Configuration & Theming Settings',
    subtitle: 'Inspect XDG config.yaml, color palettes & default settings',
    key: 'c',
    altKey: 'g',
    action: 'CONFIG'
  }
];

export const NavHub = ({
  clusterName = 'vigilante-dev',
  namespace = 'default',
  domain = 'vigilante.local',
  onSelect,
  onClose,
  activeView = 'DASHBOARD'
}) => {
  const theme = useTheme();
  const [cursor, setCursor] = useState(0);

  // Group items by section
  const sections = Array.from(new Set(HUB_ITEMS.map(i => i.section)));

  useInput((input, key) => {
    // Navigation
    if (key.upArrow || input === 'k') {
      setCursor(c => (c > 0 ? c - 1 : HUB_ITEMS.length - 1));
      return;
    }
    if (key.downArrow || input === 'j') {
      setCursor(c => (c < HUB_ITEMS.length - 1 ? c + 1 : 0));
      return;
    }

    // Launch selected item
    if (key.return) {
      const current = HUB_ITEMS[cursor];
      if (current && onSelect) {
        onSelect(current.action);
      }
      return;
    }

    // Close hub menu
    if (key.escape || key.tab || input === 'q' || input === 'Q') {
      if (onClose) {
        onClose();
      }
      return;
    }

    // Hotkey direct jump
    const inputChar = (input || '').toLowerCase();
    const matchedItem = HUB_ITEMS.find(
      i => i.key.toLowerCase() === inputChar || (i.altKey && i.altKey.toLowerCase() === inputChar)
    );

    if (matchedItem && onSelect) {
      onSelect(matchedItem.action);
    }
  });

  let globalIndex = 0;

  return React.createElement(
    Box,
    {
      flexDirection: 'column',
      padding: 1,
      borderStyle: 'double',
      borderColor: theme.header || theme.primary || 'cyan'
    },

    // Hub Header
    React.createElement(
      Box,
      {
        flexDirection: 'column',
        borderStyle: 'round',
        borderColor: theme.accent || 'cyan',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        { justifyContent: 'space-between' },
        React.createElement(
          Text,
          { bold: true, color: theme.header || theme.primary || 'cyan' },
          '🛡️  VIGILANTE OPERATIONS HUB & WORKFLOW DISPATCHER'
        ),
        React.createElement(
          Text,
          { color: theme.warning || 'yellow', bold: true },
          `[Cluster: ${clusterName}] [NS: ${namespace}]`
        )
      ),
      React.createElement(
        Text,
        { color: theme.muted || 'gray' },
        `Central navigation menu: Select any destination with ↑/↓ or press direct hotkeys.`
      )
    ),

    // Hub Sections Grid
    sections.map((secName) => {
      const secItems = HUB_ITEMS.filter(i => i.section === secName);

      return React.createElement(
        Box,
        {
          key: secName,
          flexDirection: 'column',
          borderStyle: 'single',
          borderColor: theme.border || 'gray',
          paddingX: 1,
          paddingY: 0,
          marginBottom: 1
        },
        React.createElement(
          Text,
          { bold: true, color: theme.accent || 'magenta', underline: true },
          secName
        ),
        secItems.map((item) => {
          const itemIdx = globalIndex++;
          const isFocused = itemIdx === cursor;

          return React.createElement(
            Box,
            {
              key: item.id,
              flexDirection: 'column',
              paddingLeft: 1,
              marginY: 0
            },
            React.createElement(
              Box,
              null,
              React.createElement(
                Text,
                { color: isFocused ? (theme.accent || 'cyan') : (theme.muted || 'gray'), bold: isFocused },
                isFocused ? '❯ ' : '  '
              ),
              React.createElement(
                Text,
                { color: theme.warning || 'yellow', bold: true },
                `[${item.key}]${item.altKey ? '/' + item.altKey : ''} `
              ),
              React.createElement(
                Text,
                {
                  bold: isFocused,
                  color: isFocused ? (theme.accent || 'yellow') : (theme.text || 'white')
                },
                item.title
              ),
              item.action === activeView
                ? React.createElement(
                    Text,
                    { color: theme.success || 'green', bold: true, marginLeft: 2 },
                    '(Current)'
                  )
                : null
            ),
            React.createElement(
              Box,
              { marginLeft: 6 },
              React.createElement(
                Text,
                { color: isFocused ? (theme.text || 'white') : (theme.muted || 'gray'), dimColor: !isFocused },
                item.subtitle
              )
            )
          );
        })
      );
    }),

    // Action Footer
    React.createElement(
      Box,
      {
        marginTop: 0,
        paddingTop: 1,
        borderStyle: 'single',
        borderColor: theme.border || 'gray',
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.success || 'green', bold: true }, '[Enter] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Launch Selected   '),
        React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, '[0-9 / Keys] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Direct Jump   '),
        React.createElement(Text, { color: theme.error || 'red', bold: true }, '[Esc / Tab] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Return to View')
      ),
      React.createElement(
        Text,
        { color: theme.muted || 'gray', dimColor: true },
        'Press [Tab] anytime for Hub'
      )
    )
  );
};
