import React, { useState, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { useTheme } from './theme.js';

export const HUB_ITEMS = [
  // Section 1: NIST Phase 1: Preparation
  {
    id: 'status',
    section: '🛠️ NIST Phase 1: Preparation & Readiness',
    title: 'Environment Status & Jump Station Readiness',
    subtitle: 'Live cluster health, TLS certs, ingress routes & GPG signing identity',
    key: '1',
    altKey: 's',
    action: 'DASHBOARD'
  },
  {
    id: 'config',
    section: '🛠️ NIST Phase 1: Preparation & Readiness',
    title: 'Configuration & Cryptographic Identity',
    subtitle: 'Inspect config.yaml, GPG keys, color themes & defaults',
    key: '2',
    altKey: 'c',
    action: 'CONFIG'
  },
  {
    id: 'instances',
    section: '🛠️ NIST Phase 1: Preparation & Readiness',
    title: 'Cluster Instances Manager',
    subtitle: 'Manage isolated multi-cluster k3d instances, directories & certs',
    key: '3',
    altKey: 'i',
    action: 'INSTANCES'
  },
  {
    id: 'values',
    section: '🛠️ NIST Phase 1: Preparation & Readiness',
    title: 'Helm Values Editor & Overrides',
    subtitle: 'Inspect and configure chart parameters and XDG overrides',
    key: '4',
    altKey: 'v',
    action: 'VALUES'
  },

  // Section 2: NIST Phase 2: Detection & Analysis
  {
    id: 'nmap',
    section: '🔍 NIST Phase 2: Detection & Analysis',
    title: 'Nmap Network Reconnaissance & Subnet Sweeps',
    subtitle: 'Discover live hosts, open ports, service banners & CVE vulnerabilities',
    key: '5',
    altKey: 'n',
    action: 'NMAP'
  },
  {
    id: 'xml-visualizer',
    section: '🔍 NIST Phase 2: Detection & Analysis',
    title: 'XML Network Topology & Volatile Forensics',
    subtitle: 'Host matrix, parallel triage bundle [t], ping, mtr, dns, tls, arp',
    key: '6',
    altKey: 'x',
    action: 'XML_VISUALIZER'
  },
  {
    id: 'ai-analyst',
    section: '🔍 NIST Phase 2: Detection & Analysis',
    title: 'AI Security Analyst (NIST Triage & Reasoning)',
    subtitle: 'Local Ollama, Claude, or ChatGPT grounded in real-time MCP context',
    key: '7',
    altKey: 'a',
    action: 'AI_ANALYST'
  },
  {
    id: 'pods',
    section: '🔍 NIST Phase 2: Detection & Analysis',
    title: 'Kubernetes Live Pods & Workload Monitor',
    subtitle: 'Real-time kubectl -A -o wide table with logs, describe & shell',
    key: '8',
    altKey: 'p',
    action: 'PODS'
  },

  // Section 3: NIST Phase 3: Containment, Eradication & Recovery
  {
    id: 'threat-sim',
    section: '⚡ NIST Phase 3: Containment, Eradication & Recovery',
    title: 'Threat Simulation Engine & Attack Playbooks',
    subtitle: 'Inject simulated attack vectors (MITRE/NIST) into OpenSearch SIEM',
    key: '9',
    altKey: 't',
    action: 'THREAT_SIM'
  },
  {
    id: 'modules',
    section: '⚡ NIST Phase 3: Containment, Eradication & Recovery',
    title: 'Security Modules & Multi-Tenant Stacks',
    subtitle: 'Deploy SIEM, SOC, and containment stacks per-namespace',
    key: '0',
    altKey: 'm',
    action: 'MODULES'
  },
  {
    id: 'up',
    section: '⚡ NIST Phase 3: Containment, Eradication & Recovery',
    title: 'Cluster Up & Clean Provisioning',
    subtitle: 'Deploy clean k3d cluster, TLS certificates, DNS & security modules',
    key: 'u',
    altKey: null,
    action: 'UP'
  },
  {
    id: 'hosts',
    section: '⚡ NIST Phase 3: Containment, Eradication & Recovery',
    title: 'Local /etc/hosts Sync & Ingress Cleanup (hostr)',
    subtitle: 'Synchronize or revoke local *.domain ingress mappings',
    key: 'h',
    altKey: null,
    action: 'HOSTR'
  },
  {
    id: 'down',
    section: '⚡ NIST Phase 3: Containment, Eradication & Recovery',
    title: 'Cluster Teardown & Ingress Flush',
    subtitle: 'Destroy k3d cluster and clean up local ingress routes',
    key: 'd',
    altKey: null,
    action: 'DOWN'
  }
];

export const NavHub = memo(function NavHub({
  clusterName = 'vigilante-dev',
  namespace = 'default',
  domain = 'vigilante.local',
  onSelect,
  onClose,
  activeView = 'DASHBOARD'
}) {
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
});
