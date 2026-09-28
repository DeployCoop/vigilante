import React, { memo } from 'react';
import { Box, Text } from 'ink';
import { useTheme } from './theme.js';

// The canonical Vigilante operational workflow stages
export const WORKFLOW_STAGES = [
  { id: 'MENU', label: '0. Hub [Tab]', key: 'Tab', view: 'MENU' },
  { id: 'UP', label: '1. UP', key: 'u', view: 'RUNNING' },
  { id: 'MODULES', label: '2. Modules', key: 'm', view: 'MODULES' },
  { id: 'STATUS', label: '3. Status', key: 's', view: 'DASHBOARD' },
  { id: 'PODS', label: '4. Pods', key: 'p', view: 'PODS' },
  { id: 'NMAP', label: '5. Nmap', key: 'n', view: 'NMAP' },
  { id: 'VISUALIZER', label: '6. Visualizer', key: 'x', view: 'XML_VISUALIZER' },
  { id: 'AI', label: '7. AI Analyst', key: 'a', view: 'AI_ANALYST' }
];

/**
 * Maps viewState to a normalized workflow stage ID
 */
export function getActiveWorkflowStage(viewState) {
  switch (viewState) {
    case 'MENU':
      return 'MENU';
    case 'RUNNING':
    case 'SELECT_MODULES':
    case 'SUCCESS':
      return 'UP';
    case 'MODULES':
      return 'MODULES';
    case 'DASHBOARD':
    case 'STATUS':
      return 'STATUS';
    case 'PODS':
      return 'PODS';
    case 'NMAP':
    case 'OOBSCAN':
      return 'NMAP';
    case 'XML_VISUALIZER':
    case 'OPENVAS':
    case 'VULN':
    case 'BATTLESTATION':
    case 'KSPM':
    case 'AUDIT':
      return 'VISUALIZER';
    case 'AI_ANALYST':
    case 'AI':
    case 'LLM':
      return 'AI';
    case 'VALUES':
      return 'MODULES';
    case 'KCTF':
      return 'MODULES';
    case 'THREAT_SIM':
      return 'STATUS';
    default:
      return 'STATUS';
  }
}

/**
 * Returns the contextual actions and next recommended workflow step for the active view
 */
export function getContextualMenuConfig(viewState, contextData = {}, theme = {}) {
  const {
    isRunning = false,
    isDone = false,
    selectedHost = null,
    activeDiagnostic = null,
    isInputMode = false,
    hasChanges = false
  } = contextData;

  // Running Active Task
  if (isRunning) {
    return {
      title: '⏳ Deployment Task in Progress',
      nextStepHint: null,
      items: [
        { key: 'Esc/q', label: 'Abort Task', color: theme.error || 'red' }
      ]
    };
  }

  // Central Navigation & Workflow Hub
  if (viewState === 'MENU') {
    return {
      title: '🛡️  Vigilante Operations Hub & Workflow Dispatcher',
      nextStepHint: null,
      items: [
        { key: '↑/↓', label: 'Select Item', color: theme.muted || 'gray' },
        { key: 'Enter', label: 'Launch', color: theme.success || 'green' },
        { key: '0-9 / Keys', label: 'Direct Hotkey', color: theme.warning || 'yellow' },
        { key: 'Tab/Esc', label: 'Close Hub', color: theme.error || 'red' }
      ]
    };
  }

  // Completed Task / Success View
  if (viewState === 'SUCCESS' || (viewState === 'RUNNING' && isDone)) {
    return {
      title: '🎉 Deployment Complete',
      nextStepHint: { label: 'Status Dashboard', key: 'Enter/s' },
      items: [
        { key: 'Enter', label: '➔ Status Dashboard', color: theme.success || 'green' },
        { key: 'p', label: 'Pods (Live)', color: theme.primary || 'cyan' },
        { key: 'm', label: 'Modules', color: theme.text || 'white' },
        { key: 'q', label: 'Quit', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Modules Management
  if (viewState === 'MODULES' || viewState === 'SELECT_MODULES') {
    if (isInputMode) {
      return {
        title: '🏷️ Set Target Kubernetes Namespace',
        nextStepHint: null,
        items: [
          { key: 'Enter', label: 'Confirm Namespace', color: theme.success || 'green' },
          { key: 'Esc', label: 'Cancel', color: theme.error || 'red' }
        ]
      };
    }
    return {
      title: '📦 Security Modules & Packages',
      nextStepHint: { label: 'Deploy Modules', key: 'u' },
      items: [
        { key: '↑/↓', label: 'Navigate', color: theme.muted || 'gray' },
        { key: 'Space', label: 'Toggle', color: theme.accent || 'magenta' },
        { key: 'n', label: 'Namespace', color: theme.warning || 'yellow' },
        { key: 'x', label: 'Uninstall', color: theme.error || 'red' },
        { key: 'r', label: 'Reset', color: theme.primary || 'cyan' },
        { key: 'Enter', label: hasChanges ? 'Apply Changes' : 'Select', color: theme.success || 'green' },
        { key: 'u', label: '➔ Deploy (Up)', color: theme.success || 'green' },
        { key: 's', label: 'Status', color: theme.info || 'blue' },
        { key: 'v', label: 'Values', color: theme.secondary || 'yellow' },
        { key: 'q/Esc', label: 'Back', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Pods Live Monitor
  if (viewState === 'PODS') {
    return {
      title: '⚡ Kubernetes Pods Live Monitor (-A -o wide)',
      nextStepHint: { label: 'Nmap Reconnaissance', key: 'n' },
      items: [
        { key: '↑/↓', label: 'Select Pod', color: theme.muted || 'gray' },
        { key: 'd', label: 'Describe', color: theme.success || 'green' },
        { key: 'l', label: 'Logs', color: theme.info || 'cyan' },
        { key: 's', label: 'Shell', color: theme.secondary || 'magenta' },
        { key: 'f', label: 'Filter NS', color: theme.warning || 'yellow' },
        { key: 'r', label: 'Refresh', color: theme.text || 'white' },
        { key: 'n', label: '➔ Nmap (Scan)', color: theme.accent || 'cyan' },
        { key: 'x', label: 'Visualizer', color: theme.secondary || 'magenta' },
        { key: 'c', label: 'Copy Table', color: theme.text || 'white' },
        { key: 'q/Esc', label: 'Dashboard', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Nmap Reconnaissance & Data Collection
  if (viewState === 'NMAP') {
    if (isInputMode) {
      return {
        title: '🎯 Enter Custom Target / CIDR',
        nextStepHint: null,
        items: [
          { key: 'Enter', label: 'Confirm Target', color: theme.success || 'green' },
          { key: 'Esc', label: 'Cancel', color: theme.error || 'red' }
        ]
      };
    }
    return {
      title: '🌐 Network Reconnaissance & Data Collection',
      nextStepHint: { label: 'XML Visualizer', key: 'x' },
      items: [
        { key: 'n', label: 'Run Scan', color: theme.success || 'green' },
        { key: 'i', label: 'Custom CIDR/IP', color: theme.accent || 'cyan' },
        { key: 't', label: 'Target', color: theme.accent || 'cyan' },
        { key: 'p', label: 'Profile', color: theme.primary || 'blue' },
        { key: 'x', label: '➔ XML Visualizer', color: theme.secondary || 'magenta' },
        { key: 'v/Enter', label: 'Pager', color: theme.info || 'blue' },
        { key: 'e', label: 'Editor', color: theme.secondary || 'yellow' },
        { key: 'c', label: 'Copy', color: theme.text || 'white' },
        { key: 'd', label: 'Delete', color: theme.error || 'red' },
        { key: 'q/Esc', label: 'Dashboard', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: XML Network Topology Visualizer
  if (viewState === 'XML_VISUALIZER') {
    if (activeDiagnostic) {
      return {
        title: `⚡ Host Diagnostic Inspector: ${activeDiagnostic.tool}`,
        nextStepHint: null,
        items: [
          { key: 'v/Enter', label: 'Full Pager', color: theme.info || 'blue' },
          { key: 'c', label: 'Copy Output', color: theme.success || 'green' },
          { key: 'Esc/q', label: 'Close Inspector', color: theme.warning || 'yellow' }
        ]
      };
    }

    return {
      title: '📊 Nmap XML Topology & Host Diagnostics',
      nextStepHint: null,
      items: [
        { key: '↑/↓', label: 'Select Host', color: theme.muted || 'gray' },
        { key: 't', label: 'Triage (IR Bundle)', color: theme.error || 'red' },
        { key: 'p', label: 'Ping', color: theme.success || 'green' },
        { key: 'b', label: 'Bench', color: theme.primary || 'cyan' },
        { key: 'm', label: 'MTR', color: theme.accent || 'magenta' },
        { key: 'h', label: 'HTTP', color: theme.info || 'blue' },
        { key: 'c', label: 'TLS Certs', color: theme.secondary || 'magenta' },
        { key: 'd', label: 'DNS', color: theme.warning || 'yellow' },
        { key: 'a', label: 'ARP', color: theme.accent || 'cyan' },
        { key: 's', label: 'Switch Scan', color: theme.secondary || 'yellow' },
        { key: 'f', label: 'Filter', color: theme.primary || 'blue' },
        { key: 'x/v', label: 'Raw XML', color: theme.info || 'blue' },
        { key: 'e', label: 'Editor', color: theme.secondary || 'yellow' },
        { key: 'y', label: 'Copy JSON', color: theme.text || 'white' },
        { key: 'q/Esc', label: 'Dashboard', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: OpenVAS / Greenbone Vulnerability Scanner
  if (viewState === 'OPENVAS') {
    return {
      title: '🛡️  OpenVAS Vulnerability Management Suite (GVM)',
      nextStepHint: { label: 'AI Analyst', key: 'a' },
      items: [
        { key: 's', label: 'Start Scan', color: theme.success || 'green' },
        { key: 'p', label: 'Profile', color: theme.primary || 'blue' },
        { key: 'i', label: 'Target Host', color: theme.accent || 'cyan' },
        { key: 'h', label: 'Cycle Hosts', color: theme.secondary || 'magenta' },
        { key: 'w', label: 'Web UI', color: theme.warning || 'yellow' },
        { key: 'Enter/v', label: 'Advisory', color: theme.info || 'blue' },
        { key: 'c', label: 'Copy JSON', color: theme.text || 'white' },
        { key: 'r', label: 'Refresh', color: theme.primary || 'cyan' },
        { key: 'q/Esc', label: 'Dashboard', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: kCTF Cyber Range & Challenges
  if (viewState === 'KCTF') {
    return {
      title: '🚩 kCTF Cyber Range & Challenge Spin-Up',
      nextStepHint: { label: 'Web Portal', key: 'w' },
      items: [
        { key: 'Tab', label: 'Switch Tab', color: theme.warning || 'yellow' },
        { key: 's/Enter', label: 'Spin Up', color: theme.success || 'green' },
        { key: 't', label: 'Test Probe', color: theme.primary || 'cyan' },
        { key: 'l', label: 'Pod Logs', color: theme.info || 'blue' },
        { key: 'x', label: 'Pause/Resume', color: theme.warning || 'yellow' },
        { key: 'd', label: 'Delete', color: theme.error || 'red' },
        { key: 'c', label: 'Copy Cmd', color: theme.secondary || 'magenta' },
        { key: 'w', label: 'Web Portal', color: theme.accent || 'cyan' },
        { key: 'r', label: 'Refresh', color: theme.primary || 'blue' },
        { key: 'q/Esc', label: 'Dashboard', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: OOBscan BMC Hardware Audit
  if (viewState === 'OOBSCAN') {
    return {
      title: '📡 OOBscan BMC & Out-of-Band Hardware Security Audit',
      nextStepHint: { label: 'Operations Hub', key: 'Tab' },
      items: [
        { key: 'Tab', label: 'Switch Tab', color: theme.accent || 'cyan' },
        { key: 'Enter', label: 'Start Scan', color: theme.success || 'green' },
        { key: 'i', label: 'Custom Target', color: theme.primary || 'blue' },
        { key: 'c/y', label: 'Copy Hash', color: theme.warning || 'yellow' },
        { key: 'h', label: 'Export Hashes', color: theme.secondary || 'magenta' },
        { key: 'p', label: 'Pager', color: theme.info || 'cyan' },
        { key: 'd', label: 'Delete', color: theme.error || 'red' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Vulnerability & Threat Center
  if (viewState === 'VULN') {
    return {
      title: '⚡ Vulnerability & Threat Center (Dossiers & Brain)',
      nextStepHint: { label: 'AI Analyst', key: 'a' },
      items: [
        { key: 'Tab', label: 'Cycle Tabs', color: theme.primary || 'cyan' },
        { key: '1-4', label: 'Jump Tab', color: theme.secondary || 'blue' },
        { key: '↑/↓', label: 'Select Host', color: theme.muted || 'gray' },
        { key: 'r', label: 'Refresh Dossier', color: theme.success || 'green' },
        { key: 'c', label: 'Copy JSON', color: theme.text || 'white' },
        { key: 'q/Esc', label: 'Hub', color: theme.warning || 'yellow' }
      ]
    };
  }

  // State: Battle Station
  if (viewState === 'BATTLESTATION') {
    return {
      title: '⚔️ Battle Station (eBPF Runtime + IDS Network Stream)',
      nextStepHint: { label: 'AI Analyst', key: 'a' },
      items: [
        { key: 'Tab', label: 'Switch Stream', color: theme.warning || 'yellow' },
        { key: '↑/↓', label: 'Scroll Events', color: theme.muted || 'gray' },
        { key: 'x', label: 'SOAR Isolate/Block', color: theme.error || 'red' },
        { key: 'a', label: 'Agent SOC ReAct', color: theme.primary || 'cyan' },
        { key: 'Space/p', label: 'Pause/Resume', color: theme.success || 'green' },
        { key: 'c', label: 'Copy Event', color: theme.info || 'blue' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: KSPM
  if (viewState === 'KSPM') {
    return {
      title: '🛡️ Kubernetes Security Posture Management (KSPM)',
      nextStepHint: { label: 'Battle Station', key: 'b' },
      items: [
        { key: '↑/↓', label: 'Select Violation', color: theme.muted || 'gray' },
        { key: 'r', label: 'Refresh Scorecard', color: theme.success || 'green' },
        { key: 'e', label: 'Export Signed Report', color: theme.secondary || 'yellow' },
        { key: 'c', label: 'Copy JSON', color: theme.text || 'white' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Shift-Left Audit
  if (viewState === 'AUDIT') {
    return {
      title: '🛡️ Shift-Left CI/CD Security Audit',
      nextStepHint: { label: 'KSPM', key: 'k' },
      items: [
        { key: '↑/↓', label: 'Select Finding', color: theme.muted || 'gray' },
        { key: 'r', label: 'Re-scan', color: theme.success || 'green' },
        { key: 's', label: 'Copy SARIF', color: theme.accent || 'cyan' },
        { key: 'c', label: 'Copy JSON', color: theme.text || 'white' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Autonomous Deception Mesh
  if (viewState === 'CANARY') {
    return {
      title: '🪤 Autonomous Deception Mesh ("Canary Kube")',
      nextStepHint: { label: 'Purple Team', key: 'w' },
      items: [
        { key: 'r', label: 'Refresh Canaries', color: theme.success || 'green' },
        { key: 'd', label: 'Deploy Decoy', color: theme.accent || 'cyan' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Purple Team Arena
  if (viewState === 'PURPLE') {
    return {
      title: '⚔️ Autonomous Purple Team Arena',
      nextStepHint: { label: 'Deception', key: 'y' },
      items: [
        { key: 's', label: 'Start Wargame', color: theme.success || 'green' },
        { key: '1/2', label: 'Select Scenario', color: theme.accent || 'cyan' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: PCAP Forensics
  if (viewState === 'FORENSICS') {
    return {
      title: '🔬 Deep PCAP Forensic Extraction',
      nextStepHint: { label: 'Lineage', key: 'e' },
      items: [
        { key: 'r', label: 'Rescan Dropzone', color: theme.success || 'green' },
        { key: 'c', label: 'Carve Payloads', color: theme.accent || 'cyan' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Kernel eBPF Lineage
  if (viewState === 'LINEAGE') {
    return {
      title: '🐝 Kernel eBPF Process Lineage Tree',
      nextStepHint: { label: 'CloudSec', key: 'c' },
      items: [
        { key: 'r', label: 'Refresh Trace', color: theme.success || 'green' },
        { key: 'x', label: 'SOAR Isolate', color: theme.error || 'red' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Multi-Cloud Identity & CSPM
  if (viewState === 'CLOUDSEC') {
    return {
      title: '☁️ Multi-Cloud Workload Identity & CSPM',
      nextStepHint: { label: 'KSPM', key: 'k' },
      items: [
        { key: 'r', label: 'Rescan Clouds', color: theme.success || 'green' },
        { key: 'p', label: 'Export Report', color: theme.secondary || 'yellow' },
        { key: 'q/Esc', label: 'Hub', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Helm Values Overrides
  if (viewState === 'VALUES') {
    return {
      title: '⚙️ Helm Chart Values Overrides',
      nextStepHint: { label: 'Deploy Up', key: 'u' },
      items: [
        { key: '↑/↓', label: 'Select Chart', color: theme.muted || 'gray' },
        { key: 'e/Enter', label: 'Edit in $EDITOR', color: theme.accent || 'cyan' },
        { key: 'v', label: 'View Pager', color: theme.info || 'blue' },
        { key: 'x', label: 'Export Starters', color: theme.secondary || 'yellow' },
        { key: 'u', label: '➔ Deploy (Up)', color: theme.success || 'green' },
        { key: 'm', label: 'Modules', color: theme.text || 'white' },
        { key: 'q/Esc', label: 'Back', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: Threat Simulation
  if (viewState === 'THREAT_SIM') {
    return {
      title: '🎯 SIEM Adversary Threat Simulation',
      nextStepHint: null,
      items: [
        { key: '↑/↓', label: 'Select Scenario', color: theme.muted || 'gray' },
        { key: 'Enter', label: 'Run Scenario', color: theme.success || 'green' },
        { key: 'a', label: 'Run All', color: theme.warning || 'yellow' },
        { key: 's', label: 'Open SIEM UI', color: theme.info || 'cyan' },
        { key: 'q/Esc', label: 'Back', color: theme.muted || 'gray' }
      ]
    };
  }

  // State: AI Security & Forensics Analyst (LLM)
  if (viewState === 'AI_ANALYST' || viewState === 'AI' || viewState === 'LLM') {
    return {
      title: '🤖 AI Security & Forensics Analyst (LLM)',
      nextStepHint: { label: 'Status Dashboard', key: 'q' },
      items: [
        { key: 'i/Space', label: 'Ask Query', color: theme.accent || 'yellow' },
        { key: '1-5', label: 'Forensic Presets', color: theme.primary || 'cyan' },
        { key: 'm', label: 'Switch Model', color: theme.secondary || 'magenta' },
        { key: 'c', label: 'Copy Response', color: theme.info || 'blue' },
        { key: 'x', label: 'Export Report', color: theme.success || 'green' },
        { key: 'Tab', label: 'Hub Menu', color: theme.warning || 'yellow' },
        { key: 'q', label: 'Return', color: theme.muted || 'gray' }
      ]
    };
  }

  // Default: Main Status Dashboard
  return {
    title: '🎮 Global Dashboard & Environment Controls',
    nextStepHint: { label: 'Live Pods Monitor', key: 'p' },
    items: [
      { key: 'p', label: '➔ Pods (Live)', color: theme.primary || 'cyan' },
      { key: 'n', label: 'Nmap (Scan)', color: theme.accent || 'cyan' },
      { key: 'x', label: 'XML Visualizer', color: theme.secondary || 'magenta' },
      { key: 'a', label: 'AI Analyst', color: theme.accent || 'yellow' },
      { key: 't', label: 'Threat-Sim', color: theme.secondary || 'yellow' },
      { key: 'm', label: 'Modules', color: theme.text || 'white' },
      { key: 'v', label: 'Values', color: theme.accent || 'blue' },
      { key: 'h', label: 'Hostr (DNS)', color: theme.accent || 'cyan' },
      { key: 'u', label: 'Up (Deploy)', color: theme.success || 'green' },
      { key: 'd', label: 'Down (Teardown)', color: theme.error || 'red' },
      { key: '1-6', label: 'Copy Pane', color: theme.muted || 'gray' },
      { key: 'q', label: 'Quit', color: theme.muted || 'gray' }
    ]
  };
}

/**
 * Globally Context-Aware Persistent Action Menu & Workflow Breadcrumb Bar
 */
export const MenuBar = memo(function MenuBar({
  activeView = 'DASHBOARD',
  contextData = {}
}) {
  const theme = useTheme();
  const currentStage = getActiveWorkflowStage(activeView);
  const menuConfig = getContextualMenuConfig(activeView, contextData, theme);

  return React.createElement(
    Box,
    {
      marginTop: 1,
      flexDirection: 'column',
      paddingX: 1,
      paddingY: 0,
      borderStyle: 'round',
      borderColor: theme.border || 'gray'
    },

    // Row 1: Workflow Breadcrumbs & Context Title
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 0 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.text, bold: true }, `${menuConfig.title} `)
      ),
      // Workflow progression trail
      React.createElement(
        Box,
        null,
        WORKFLOW_STAGES.map((stage, idx) => {
          const isActive = stage.id === currentStage;
          return React.createElement(
            Box,
            { key: stage.id },
            React.createElement(
              Text,
              {
                color: isActive ? theme.accent : theme.muted,
                bold: isActive,
                underline: isActive
              },
              isActive ? `[● ${stage.label}]` : stage.label
            ),
            idx < WORKFLOW_STAGES.length - 1
              ? React.createElement(Text, { color: theme.muted, dimColor: true }, ' ➔ ')
              : null
          );
        })
      )
    ),

    // Row 2: Contextual Action Buttons
    React.createElement(
      Box,
      { flexWrap: 'wrap', marginTop: 0, justifyContent: 'space-between' },
      React.createElement(
        Box,
        { flexWrap: 'wrap' },
        menuConfig.items.map((item) =>
          React.createElement(
            Box,
            { key: item.key, marginRight: 2 },
            React.createElement(
              Text,
              { color: item.color, bold: true },
              `[${item.key}] `
            ),
            React.createElement(
              Text,
              { color: theme.text },
              item.label
            )
          )
        )
      ),
      menuConfig.nextStepHint
        ? React.createElement(
            Box,
            null,
            React.createElement(Text, { color: theme.warning, bold: true }, 'Next ➔ '),
            React.createElement(Text, { color: theme.accent, bold: true }, `[${menuConfig.nextStepHint.key}] `),
            React.createElement(Text, { color: theme.text }, menuConfig.nextStepHint.label)
          )
        : null
    )
  );
});
