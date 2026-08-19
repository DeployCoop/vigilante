import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import path from 'node:path';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import {
  listAvailablePlaybooks,
  loadPlaybook,
  executeThreatPlaybook,
  createCustomPlaybookTemplate
} from '../engine/threats.js';
import { openInEditor } from '../utils/editor.js';
import { getVigilantePlaybooksDir, getVigilanteEvidenceDir } from '../engine/config.js';
import { useClipboard } from './ClipboardManager.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

export const ThreatSimView = ({ domain = 'vigilante.local', onDone = null, onNavigate = null }) => {
  const theme = useTheme();
  const { copyToClipboard, registerPanes } = useClipboard();

  const [mode, setMode] = useState('picker'); // 'picker' | 'running' | 'completed' | 'error'
  const [playbooks, setPlaybooks] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [filterText, setFilterText] = useState('');
  const [isFiltering, setIsFiltering] = useState(false);
  const [targetNamespace, setTargetNamespace] = useState('opensearch');
  const [isNamespaceInputOpen, setIsNamespaceInputOpen] = useState(false);
  const [customNsText, setCustomNsText] = useState('');

  const [activePlaybook, setActivePlaybook] = useState(null);
  const [logs, setLogs] = useState([]);
  const [error, setError] = useState(null);
  const [feedback, setFeedback] = useState(null);

  // Load all available playbooks
  const refreshPlaybooks = useCallback(async () => {
    try {
      const list = await listAvailablePlaybooks();
      setPlaybooks(list);
    } catch (err) {
      logger.error('THREAT:UI:LOAD_ERR', `Failed to load playbooks: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    refreshPlaybooks();
  }, [refreshPlaybooks]);

  // Register clipboard pane
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

  // Filtered playbooks list
  const filteredPlaybooks = playbooks.filter(p => {
    if (!filterText) return true;
    const query = filterText.toLowerCase();
    return (
      p.id.toLowerCase().includes(query) ||
      p.name.toLowerCase().includes(query) ||
      (p.category && p.category.toLowerCase().includes(query)) ||
      (p.tags && p.tags.some(t => t.toLowerCase().includes(query))) ||
      (p.mitreTechniques && p.mitreTechniques.some(t => t.id.toLowerCase().includes(query) || t.name.toLowerCase().includes(query)))
    );
  });

  // Run a single playbook
  const handleRunPlaybook = async (pb) => {
    if (!pb) return;
    setActivePlaybook(pb);
    setMode('running');
    setLogs([]);
    setError(null);
    setFeedback(null);

    try {
      setLogs(l => [...l, `🎯 Initializing Modular Threat Simulation Pipeline for '${pb.name}'...`]);
      setLogs(l => [...l, `📁 Playbook Source: ${pb.isBuiltin ? 'Built-in Engine' : `Custom Playbook (${pb.filePath})`}`]);
      setLogs(l => [...l, `🏷️ Category: ${(pb.category || 'general').toUpperCase()} | Severity: ${pb.severity || 'HIGH'}`]);
      setLogs(l => [...l, `📡 MITRE ATT&CK Techniques: ${(pb.mitreTechniques || []).map(t => `${t.id} (${t.name})`).join(', ') || 'N/A'}`]);
      setLogs(l => [...l, `📦 Target Ingress Namespace: '${targetNamespace}'`]);
      setLogs(l => [...l, '------------------------------------------------------------']);

      const res = await executeThreatPlaybook({
        playbook: pb,
        namespace: targetNamespace,
        onLog: (msg) => setLogs(l => [...l, msg])
      });

      setLogs(l => [...l, '------------------------------------------------------------']);
      setLogs(l => [...l, `✔ Ingestion Job completed: ${res.eventsCount} threat events dispatched to OpenSearch SIEM.`]);
      setMode('completed');
      if (onDone) onDone();
    } catch (err) {
      setError(err.message);
      setLogs(l => [...l, `✖ Simulation failed: ${err.message}`]);
      setMode('error');
    }
  };

  // Run all playbooks sequentially
  const handleRunAll = async () => {
    if (playbooks.length === 0) return;
    setActivePlaybook({ name: 'Multi-Stage APT Campaign (All Scenarios)', id: 'all-scenarios' });
    setMode('running');
    setLogs([]);
    setError(null);

    try {
      setLogs(l => [...l, `🚀 Launching Full Multi-Stage Threat Simulation Campaign across ${playbooks.length} scenarios...`]);
      setLogs(l => [...l, `📦 Target Namespace: '${targetNamespace}'`]);
      setLogs(l => [...l, '============================================================']);

      for (let i = 0; i < playbooks.length; i++) {
        const pb = playbooks[i];
        setLogs(l => [...l, `\n[Stage ${i + 1}/${playbooks.length}] Executing Scenario: ${pb.name} (${pb.id})...`]);
        await executeThreatPlaybook({
          playbook: pb,
          namespace: targetNamespace,
          onLog: (msg) => setLogs(l => [...l, `  ${msg}`])
        });
      }

      setLogs(l => [...l, '\n============================================================']);
      setLogs(l => [...l, `🎉 ALL ${playbooks.length} Threat Simulation Scenarios successfully executed and ingested into SIEM!`]);
      setMode('completed');
      if (onDone) onDone();
    } catch (err) {
      setError(err.message);
      setLogs(l => [...l, `✖ Multi-stage campaign failed: ${err.message}`]);
      setMode('error');
    }
  };

  // Create new custom playbook template
  const handleCreatePlaybook = async () => {
    try {
      const templateName = `custom-scenario-${Date.now().toString().slice(-4)}`;
      const res = await createCustomPlaybookTemplate(templateName);
      setFeedback({ type: 'success', text: `Created template: ${path.basename(res.filePath)}` });
      await refreshPlaybooks();
      setTimeout(() => setFeedback(null), 3500);

      // Open in editor
      await openInEditor(res.filePath);
      await refreshPlaybooks();
    } catch (err) {
      setFeedback({ type: 'error', text: `Failed to create playbook: ${err.message}` });
    }
  };

  // Edit selected custom playbook
  const handleEditPlaybook = async (pb) => {
    if (!pb || !pb.filePath) {
      setFeedback({ type: 'info', text: 'Selected playbook is built-in. Press [c] to create a custom editable playbook.' });
      setTimeout(() => setFeedback(null), 3000);
      return;
    }

    try {
      await openInEditor(pb.filePath);
      await refreshPlaybooks();
      setFeedback({ type: 'success', text: `Reloaded ${path.basename(pb.filePath)}` });
      setTimeout(() => setFeedback(null), 2500);
    } catch (err) {
      setFeedback({ type: 'error', text: `Failed to open editor: ${err.message}` });
    }
  };

  // Export report
  const handleExportReport = async () => {
    try {
      const evidenceDir = getVigilanteEvidenceDir();
      const reportsDir = path.join(evidenceDir, 'threat_reports');
      await fs.mkdir(reportsDir, { recursive: true });

      const safeName = (activePlaybook?.id || 'simulation').toLowerCase().replace(/[^a-z0-9_-]/g, '-');
      const filename = `threat-sim-${Date.now()}-${safeName}.md`;
      const filePath = path.join(reportsDir, filename);

      const reportContent = `# ⚡ Vigilante Threat Simulation Execution Report
**Scenario**: ${activePlaybook?.name || 'Simulation'} (${activePlaybook?.id || 'id'})
**Namespace**: ${targetNamespace}
**Date**: ${new Date().toUTCString()}
**Status**: ${mode.toUpperCase()}

---

## Execution Logs
\`\`\`
${logs.join('\n')}
\`\`\`

---
*Generated by Vigilante Modular Threat Simulation Engine*
`;

      await fs.writeFile(filePath, reportContent, 'utf8');
      setFeedback({ type: 'success', text: `✔ Exported report to ${filename}` });
      setTimeout(() => setFeedback(null), 3500);
    } catch (err) {
      setFeedback({ type: 'error', text: `Failed to export report: ${err.message}` });
    }
  };

  // Keyboard navigation
  useInput((input, key) => {
    // Mode A: Namespace Input Modal
    if (isNamespaceInputOpen) {
      if (key.return) {
        if (customNsText.trim()) {
          setTargetNamespace(customNsText.trim());
          setFeedback({ type: 'success', text: `Set target namespace to '${customNsText.trim()}'` });
          setTimeout(() => setFeedback(null), 2500);
        }
        setIsNamespaceInputOpen(false);
        setCustomNsText('');
        return;
      }
      if (key.escape) {
        setIsNamespaceInputOpen(false);
        setCustomNsText('');
        return;
      }
      if (key.backspace || key.delete) {
        setCustomNsText(prev => prev.slice(0, -1));
        return;
      }
      if (input && input.length === 1 && !key.ctrl && !key.meta) {
        setCustomNsText(prev => prev + input);
        return;
      }
      return;
    }

    // Mode B: Search Filtering
    if (isFiltering) {
      if (key.return || key.escape) {
        setIsFiltering(false);
        return;
      }
      if (key.backspace || key.delete) {
        setFilterText(prev => prev.slice(0, -1));
        setCursor(0);
        return;
      }
      if (input && input.length === 1 && !key.ctrl && !key.meta) {
        setFilterText(prev => prev + input);
        setCursor(0);
        return;
      }
      return;
    }

    // Mode C: Scenario Picker
    if (mode === 'picker') {
      if (key.upArrow || input === 'k') {
        setCursor(c => (c > 0 ? c - 1 : Math.max(0, filteredPlaybooks.length - 1)));
        return;
      }
      if (key.downArrow || input === 'j') {
        setCursor(c => (c < filteredPlaybooks.length - 1 ? c + 1 : 0));
        return;
      }
      if (key.return) {
        const selected = filteredPlaybooks[cursor];
        if (selected) {
          handleRunPlaybook(selected);
        }
        return;
      }

      const keyChar = (input || '').toLowerCase();

      // Number keys 1-7
      const num = parseInt(keyChar, 10);
      if (!isNaN(num) && num >= 1 && num <= filteredPlaybooks.length) {
        handleRunPlaybook(filteredPlaybooks[num - 1]);
        return;
      }

      // [a] -> Run All Scenarios
      if (keyChar === 'a') {
        handleRunAll();
        return;
      }

      // [/] -> Filter
      if (keyChar === '/') {
        setIsFiltering(true);
        return;
      }

      // [n] -> Switch Namespace
      if (keyChar === 'n') {
        setIsNamespaceInputOpen(true);
        return;
      }

      // [c] -> Create Playbook Template
      if (keyChar === 'c') {
        handleCreatePlaybook();
        return;
      }

      // [e] -> Edit Playbook in $EDITOR
      if (keyChar === 'e') {
        const selected = filteredPlaybooks[cursor];
        handleEditPlaybook(selected);
        return;
      }

      // [Tab] -> Hub
      if (key.tab && onNavigate) {
        onNavigate('menu');
        return;
      }

      // [q] or [Esc] -> Return
      if (keyChar === 'q' || key.escape || keyChar === 's') {
        if (onNavigate) {
          onNavigate('dashboard');
        }
      }
      return;
    }

    // Mode D: Running / Completed / Error View
    const keyChar = (input || '').toLowerCase();

    // [r] -> Run another scenario
    if (keyChar === 'r' && mode !== 'running') {
      setMode('picker');
      return;
    }

    // [c] -> Copy logs
    if (keyChar === 'c') {
      copyToClipboard(logs.join('\n'));
      setFeedback({ type: 'success', text: '✔ Copied simulation output to clipboard!' });
      setTimeout(() => setFeedback(null), 2500);
      return;
    }

    // [x] -> Export report
    if (keyChar === 'x') {
      handleExportReport();
      return;
    }

    // [s] or [Esc] or [q] -> Return
    if (keyChar === 's' || keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  // Severity color mapper
  const getSeverityColor = (sev) => {
    const s = (sev || '').toUpperCase();
    if (s === 'CRITICAL') return theme.error || 'red';
    if (s === 'HIGH') return theme.warning || 'yellow';
    if (s === 'MEDIUM') return theme.accent || 'cyan';
    return theme.muted || 'gray';
  };

  return React.createElement(
    Box,
    {
      flexDirection: 'column',
      padding: 1,
      borderStyle: 'round',
      borderColor: theme.secondary || 'magenta'
    },
    // Header Bar
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.secondary || 'magenta', bold: true }, '⚡ MODULAR NETWORK THREAT SIMULATOR '),
        React.createElement(Text, { color: theme.text || 'white' }, `[Namespace: `),
        React.createElement(Text, { color: theme.accent || 'yellow', bold: true }, targetNamespace),
        React.createElement(Text, { color: theme.text || 'white' }, `]`)
      ),
      React.createElement(
        Box,
        null,
        React.createElement(
          Text,
          { color: theme.muted || 'gray', dimColor: true },
          `${playbooks.length} Scenarios Available (Built-in & Custom)`
        )
      )
    ),

    // Feedback Toast
    feedback
      ? React.createElement(
          Box,
          { marginBottom: 1 },
          React.createElement(
            Text,
            { color: feedback.type === 'error' ? theme.error : feedback.type === 'warning' ? theme.warning : theme.success, bold: true },
            feedback.text
          )
        )
      : null,

    // VIEW MODE 1: Scenario Picker Table
    mode === 'picker'
      ? React.createElement(
          Box,
          { flexDirection: 'column' },
          React.createElement(
            Box,
            { marginBottom: 1, justifyContent: 'space-between' },
            React.createElement(
              Text,
              { color: theme.text || 'white' },
              isFiltering
                ? `🔍 Search: ${filterText}█`
                : filterText
                  ? `🔍 Filter: "${filterText}" (Press [/] to edit, [Esc] to clear)`
                  : 'Select an attack scenario to inject into OpenSearch SIEM (Use ↑/↓ and Enter or [1-7]):'
            ),
            React.createElement(
              Text,
              { color: theme.accent || 'yellow', bold: true },
              `[${filteredPlaybooks.length} playbooks]`
            )
          ),

          // Scenario List
          React.createElement(
            Box,
            {
              flexDirection: 'column',
              minHeight: 12,
              maxHeight: 18,
              borderStyle: 'single',
              borderColor: theme.muted || 'gray',
              padding: 1
            },
            filteredPlaybooks.length === 0
              ? React.createElement(
                  Text,
                  { color: theme.muted || 'gray' },
                  `No scenarios found matching "${filterText}". Press [c] to create a custom playbook.`
                )
              : filteredPlaybooks.map((pb, idx) => {
                  const isSelected = idx === cursor;
                  const sevColor = getSeverityColor(pb.severity);
                  const mitreTags = (pb.mitreTechniques || []).map(t => `[${t.id}]`).join(' ');

                  return React.createElement(
                    Box,
                    { key: pb.id, flexDirection: 'column', marginBottom: 1 },
                    React.createElement(
                      Box,
                      { justifyContent: 'space-between' },
                      React.createElement(
                        Box,
                        null,
                        React.createElement(
                          Text,
                          { color: isSelected ? theme.accent : theme.text, bold: isSelected },
                          `${isSelected ? '❯ ' : '  '}[${idx + 1}] ${pb.name} `
                        ),
                        React.createElement(
                          Text,
                          { color: sevColor, bold: true },
                          `[${pb.severity || 'HIGH'}] `
                        ),
                        pb.nistVector
                          ? React.createElement(Text, { color: theme.secondary || 'magenta', bold: true }, `[NIST: ${pb.nistVector}] `)
                          : null,
                        pb.signType === 'PRECURSOR'
                          ? React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, `[PRECURSOR] `)
                          : null,
                        pb.isCustom
                          ? React.createElement(Text, { color: theme.success || 'green', bold: true }, '⭐ [CUSTOM] ')
                          : null
                      ),
                      React.createElement(
                        Text,
                        { color: theme.primary || 'cyan', dimColor: true },
                        mitreTags
                      )
                    ),
                    React.createElement(
                      Text,
                      { color: theme.muted || 'gray', marginLeft: 4 },
                      `${pb.description} (${pb.events?.length || 0} events)`
                    )
                  );
                })
          ),

          // Action Toolbar
          React.createElement(
            Box,
            { marginTop: 1, justifyContent: 'space-between' },
            React.createElement(
              Box,
              null,
              React.createElement(Text, { color: theme.accent, bold: true }, '[Enter] '),
              React.createElement(Text, { color: theme.text }, 'Run Selected  '),
              React.createElement(Text, { color: theme.secondary, bold: true }, '[a] '),
              React.createElement(Text, { color: theme.text }, 'Run All Scenarios  '),
              React.createElement(Text, { color: theme.primary, bold: true }, '[c] '),
              React.createElement(Text, { color: theme.text }, 'New Playbook  '),
              React.createElement(Text, { color: theme.secondary, bold: true }, '[e] '),
              React.createElement(Text, { color: theme.text }, 'Edit in $EDITOR')
            ),
            React.createElement(
              Box,
              null,
              React.createElement(Text, { color: theme.accent, bold: true }, '[n] '),
              React.createElement(Text, { color: theme.text }, 'Namespace  '),
              React.createElement(Text, { color: theme.secondary, bold: true }, '[Tab] '),
              React.createElement(Text, { color: theme.text }, 'Hub  '),
              React.createElement(Text, { color: theme.muted, bold: true }, '[q] '),
              React.createElement(Text, { color: theme.muted }, 'Return')
            )
          )
        )
      : null,

    // VIEW MODE 2: Execution & Real-Time Log Streaming
    mode !== 'picker'
      ? React.createElement(
          Box,
          { flexDirection: 'column' },
          // Sub-header
          React.createElement(
            Box,
            { justifyContent: 'space-between', marginBottom: 1 },
            React.createElement(
              Text,
              { color: theme.accent || 'yellow', bold: true },
              `🎯 ACTIVE ATTACK: ${activePlaybook?.name || 'Simulation'} [${activePlaybook?.id}]`
            ),
            mode === 'running'
              ? React.createElement(
                  Box,
                  null,
                  React.createElement(Spinner, { type: 'dots' }),
                  React.createElement(Text, { color: theme.warning || 'yellow', marginLeft: 1, bold: true }, ' INJECTING THREAT TRAFFIC...')
                )
              : mode === 'completed'
                ? React.createElement(Text, { color: theme.success || 'green', bold: true }, '✔ SIMULATION COMPLETE')
                : React.createElement(Text, { color: theme.error || 'red', bold: true }, '✖ FAILED')
          ),

          // Log display box
          React.createElement(
            Box,
            {
              flexDirection: 'column',
              minHeight: 14,
              maxHeight: 22,
              borderStyle: 'single',
              borderColor: mode === 'error' ? theme.error : theme.muted || 'gray',
              padding: 1
            },
            logs.map((log, idx) =>
              React.createElement(Text, { key: idx, color: log.startsWith('✔') ? (theme.success || 'green') : log.startsWith('✖') ? (theme.error || 'red') : log.startsWith('🎯') || log.startsWith('🚀') ? (theme.accent || 'yellow') : (theme.text || 'white') }, log)
            )
          ),

          // Post-Execution Links & Next Actions
          mode === 'completed'
            ? React.createElement(
                Box,
                { flexDirection: 'column', marginTop: 1 },
                React.createElement(
                  Text,
                  { color: theme.primary || 'cyan', bold: true },
                  `🌐 SIEM Dashboard: https://${targetNamespace === 'default' || targetNamespace === 'opensearch' ? 'siem' : `${targetNamespace}-siem`}.${domain}`
                ),
                React.createElement(
                  Text,
                  { color: theme.muted || 'gray' },
                  `Query Index: 'vigilante-network-events' | Ingested: ${activePlaybook?.events?.length || 'all'} ECS attack events`
                )
              )
            : null,

          // Bottom Action Bar
          React.createElement(
            Box,
            { marginTop: 1, justifyContent: 'space-between' },
            React.createElement(
              Box,
              null,
              React.createElement(Text, { color: theme.accent, bold: true }, '[r] '),
              React.createElement(Text, { color: theme.text }, 'Select Another Scenario  '),
              React.createElement(Text, { color: theme.secondary, bold: true }, '[c] '),
              React.createElement(Text, { color: theme.text }, 'Copy Output  '),
              React.createElement(Text, { color: theme.secondary, bold: true }, '[x] '),
              React.createElement(Text, { color: theme.text }, 'Export Report')
            ),
            React.createElement(
              Box,
              null,
              React.createElement(Text, { color: theme.secondary, bold: true }, '[Tab] '),
              React.createElement(Text, { color: theme.text }, 'Hub  '),
              React.createElement(Text, { color: theme.muted, bold: true }, '[s/Esc] '),
              React.createElement(Text, { color: theme.muted }, 'Dashboard')
            )
          )
        )
      : null,

    // Modal: Target Namespace Switcher
    isNamespaceInputOpen
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            marginTop: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.accent || 'yellow'
          },
          React.createElement(
            Text,
            { color: theme.accent || 'yellow', bold: true },
            '🎯 ENTER TARGET KUBERNETES NAMESPACE (e.g. opensearch, threat-lab, tenant-a):'
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(Text, { color: theme.accent, bold: true }, '❯ '),
            React.createElement(Text, { color: theme.text }, customNsText || targetNamespace),
            React.createElement(Text, { color: theme.accent, bold: true }, ' █')
          ),
          React.createElement(
            Text,
            { color: theme.muted || 'gray', marginTop: 1 },
            'Press [Enter] to confirm | [Esc] to cancel'
          )
        )
      : null
  );
};
