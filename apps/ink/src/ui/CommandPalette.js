import React, { useState, useMemo, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { useTheme } from './theme.js';

export const COMMAND_ITEMS = [
  // Quick View Launchers
  { id: 'view-battlestation', title: 'Battle Station: Live eBPF & IDS Telemetry', category: 'Views', action: 'BATTLESTATION', shortcut: 'l' },
  { id: 'view-kspm', title: 'KSPM: Kubernetes Security Posture Management', category: 'Views', action: 'KSPM', shortcut: 'k' },
  { id: 'view-audit', title: 'Shift-Left CI/CD Security Audit', category: 'Views', action: 'AUDIT', shortcut: 'g' },
  { id: 'view-canary', title: 'Canary Kube: Autonomous Deception Mesh & Honeynet', category: 'Views', action: 'CANARY', shortcut: 'y' },
  { id: 'view-purple', title: 'Purple Team Arena: Autonomous Adversarial Wargames', category: 'Views', action: 'PURPLE', shortcut: 'w' },
  { id: 'view-forensics', title: 'PCAP Forensics: File Carving & Stream Ladders', category: 'Views', action: 'FORENSICS', shortcut: 'z' },
  { id: 'view-lineage', title: 'eBPF Process Ancestry & Shell Breakout Lineage', category: 'Views', action: 'LINEAGE', shortcut: 'e' },
  { id: 'view-cloudsec', title: 'Multi-Cloud Workload Identity & CSPM Posture', category: 'Views', action: 'CLOUDSEC', shortcut: 'c' },
  { id: 'view-vuln', title: 'Vulnerability & Threat Center (Unified Dossiers)', category: 'Views', action: 'VULN', shortcut: 'v' },
  { id: 'view-netmap', title: 'NastyMap: XML Network Topology & Diagnostics', category: 'Views', action: 'XML_VISUALIZER', shortcut: 'x' },
  { id: 'view-pods', title: 'Kubernetes Pods Live Monitor (-A -o wide)', category: 'Views', action: 'PODS', shortcut: 'p' },
  { id: 'view-ai', title: 'AI Security Analyst (LLM Forensics & NIST Triage)', category: 'Views', action: 'AI_ANALYST', shortcut: 'a' },
  { id: 'view-openvas', title: 'OpenVAS / Greenbone Vulnerability Scanner', category: 'Views', action: 'OPENVAS', shortcut: 'o' },
  { id: 'view-kctf', title: 'kCTF Cyber Range & Challenge Manager', category: 'Views', action: 'KCTF', shortcut: 'f' },
  { id: 'view-oobscan', title: 'OOBscan: Out-of-Band BMC/IPMI Hardware Audit', category: 'Views', action: 'OOBSCAN', shortcut: 'b' },
  { id: 'view-threats', title: 'Threat Simulation Playbooks & SIEM Injection', category: 'Views', action: 'THREAT_SIM', shortcut: 't' },
  { id: 'view-modules', title: 'Security Modules & Multi-Tenant Stacks', category: 'Views', action: 'MODULES', shortcut: 'm' },
  { id: 'view-status', title: 'Global Status & Jump Station Dashboard', category: 'Views', action: 'DASHBOARD', shortcut: 's' },
  { id: 'view-config', title: 'Configuration & Cryptographic Identity', category: 'Views', action: 'CONFIG', shortcut: 'c' },
  { id: 'view-values', title: 'Helm Values Editor & Overrides', category: 'Views', action: 'VALUES', shortcut: 'v' },
  { id: 'view-instances', title: 'Cluster Instances Manager', category: 'Views', action: 'INSTANCES', shortcut: 'i' },

  // SOAR & Threat Operations
  { id: 'act-soar-isolate', title: 'SOAR: Active Pod Network Isolation (Zero-Trust)', category: 'SOAR Action', action: 'BATTLESTATION' },
  { id: 'act-soc-investigate', title: 'Agent SOC: Autonomous ReAct Investigation & NIST Post-Mortem', category: 'Autonomous SOC', action: 'BATTLESTATION' },
  { id: 'act-cti-sync', title: 'CTI: Synchronize Feodo C2, URLhaus & Emerging Threats', category: 'Threat Intel', action: 'SYNC_CTI' },
  { id: 'act-kspm-scorecard', title: 'KSPM: Generate CIS Benchmark Compliance Report', category: 'Posture', action: 'KSPM' },
  { id: 'act-audit-manifests', title: 'Audit: Shift-Left Scan Kubernetes & Dockerfiles', category: 'CI/CD Audit', action: 'AUDIT' },

  // Threat Scenarios
  { id: 'sim-cred-brute', title: 'Simulate: Credential Brute-force & Spraying', category: 'Playbook', action: 'THREAT_SIM' },
  { id: 'sim-dns-tunnel', title: 'Simulate: High-Entropy DNS Exfiltration Tunneling', category: 'Playbook', action: 'THREAT_SIM' },
  { id: 'sim-c2-beacon', title: 'Simulate: Cobalt Strike / Feodo C2 Heartbeat', category: 'Playbook', action: 'THREAT_SIM' },
  { id: 'sim-lateral-move', title: 'Simulate: Lateral Movement & Privilege Escalation', category: 'Playbook', action: 'THREAT_SIM' }
];

export const CommandPalette = memo(function CommandPalette({
  isOpen = false,
  onSelect,
  onClose
}) {
  const theme = useTheme();
  const [query, setQuery] = useState('');
  const [cursor, setCursor] = useState(0);

  // Filter items
  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim();
    if (!q) return COMMAND_ITEMS;
    return COMMAND_ITEMS.filter(
      item =>
        item.title.toLowerCase().includes(q) ||
        item.category.toLowerCase().includes(q) ||
        (item.shortcut && item.shortcut.toLowerCase() === q)
    );
  }, [query]);

  useInput((input, key) => {
    if (!isOpen) return;

    // Close on Escape or Ctrl+P
    if (key.escape || (key.ctrl && input === 'p')) {
      if (onClose) onClose();
      return;
    }

    // Navigation
    if (key.upArrow) {
      setCursor(c => (c > 0 ? c - 1 : Math.max(0, filtered.length - 1)));
      return;
    }
    if (key.downArrow) {
      setCursor(c => (c < filtered.length - 1 ? c + 1 : 0));
      return;
    }

    // Execute
    if (key.return) {
      const selected = filtered[cursor];
      if (selected && onSelect) {
        onSelect(selected.action, selected);
      }
      if (onClose) onClose();
      return;
    }

    // Backspace / typing
    if (key.backspace || key.delete) {
      setQuery(q => q.slice(0, -1));
      setCursor(0);
      return;
    }

    // Standard character input
    if (input && !key.ctrl && !key.meta) {
      setQuery(q => q + input);
      setCursor(0);
      return;
    }
  });

  if (!isOpen) return null;

  return React.createElement(
    Box,
    {
      flexDirection: 'column',
      borderStyle: 'double',
      borderColor: 'cyan',
      padding: 1,
      width: '100%',
      marginBottom: 1
    },

    // Search header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'cyan', bold: true }, '⚡ COMMAND PALETTE  '),
        React.createElement(Text, { color: 'gray' }, '| Type to search commands, playbooks, tools & views')
      ),
      React.createElement(Text, { color: 'gray' }, '[Esc to close]')
    ),

    // Search input bar
    React.createElement(
      Box,
      {
        borderStyle: 'single',
        borderColor: 'yellow',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(Text, { color: 'yellow', bold: true }, '> '),
      React.createElement(Text, { color: 'white', bold: true }, query),
      React.createElement(Text, { color: 'cyan' }, '█')
    ),

    // Results list
    filtered.length === 0
      ? React.createElement(
          Box,
          { paddingY: 1 },
          React.createElement(Text, { color: 'gray' }, 'No matching commands or playbooks found.')
        )
      : filtered.slice(0, 8).map((item, idx) => {
          const isSelected = idx === cursor;
          return React.createElement(
            Box,
            {
              key: item.id,
              justifyContent: 'space-between',
              paddingX: 1,
              backgroundColor: isSelected ? 'blue' : undefined
            },
            React.createElement(
              Box,
              null,
              React.createElement(
                Text,
                { color: isSelected ? 'white' : 'cyan', bold: isSelected },
                `${isSelected ? '▶ ' : '  '}${item.title}`
              )
            ),
            React.createElement(
              Box,
              null,
              React.createElement(
                Text,
                { color: isSelected ? 'yellow' : 'gray', dimColor: !isSelected },
                `[${item.category}]`
              )
            )
          );
        })
  );
});
