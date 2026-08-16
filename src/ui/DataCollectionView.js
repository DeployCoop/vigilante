import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import path from 'node:path';
import {
  listSavedNmapScans,
  runNmapScan,
  deleteSavedScan,
  readSavedScan,
  checkNmapInstalled,
  getNmapsDir,
  detectNetworkSubnets,
  SCAN_PROFILES
} from '../engine/nmap.js';
import { openInSystemPager } from '../engine/pods.js';
import { openInEditor } from '../utils/editor.js';
import { useClipboard } from './ClipboardManager.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

export const DataCollectionView = ({
  domain = 'vigilante.local',
  ip = '127.0.0.1',
  onNavigate = null
}) => {
  const theme = useTheme();
  const [scans, setScans] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [scanLogs, setScanLogs] = useState([]);
  const [targets, setTargets] = useState([]);
  const [selectedTargetIdx, setSelectedTargetIdx] = useState(0);
  const [selectedProfileIdx, setSelectedProfileIdx] = useState(0);
  const [feedback, setFeedback] = useState(null);
  const [nmapInfo, setNmapInfo] = useState({ installed: true, version: '' });
  
  // Custom CIDR / Target Input Mode State
  const [isInputMode, setIsInputMode] = useState(false);
  const [customInputText, setCustomInputText] = useState('');

  const { registerPanes } = useClipboard();

  // Populate smart targets (Endpoints, IPs, and Auto-detected CIDR subnets)
  useEffect(() => {
    const subnets = detectNetworkSubnets();
    const list = [
      { label: `Endpoint: siem.${domain}`, value: `siem.${domain}`, isCidr: false },
      { label: `Endpoint: vigil.${domain}`, value: `vigil.${domain}`, isCidr: false },
      { label: `Host IP: ${ip}`, value: ip, isCidr: false },
      ...subnets.map(s => ({
        label: `${s.label} [${s.cidr}]`,
        value: s.cidr,
        isCidr: true
      })),
      { label: 'Localhost Loopback', value: '127.0.0.1', isCidr: false }
    ];
    setTargets(list);
  }, [domain, ip]);

  const currentTargetObj = targets[selectedTargetIdx] || { label: ip, value: ip, isCidr: false };
  const currentTarget = currentTargetObj.value;
  const isCidrTarget = currentTarget.includes('/') || currentTargetObj.isCidr;
  const currentProfile = SCAN_PROFILES[selectedProfileIdx] || SCAN_PROFILES[0];
  const nmapsDir = getNmapsDir();

  const loadScans = useCallback(async () => {
    try {
      const items = await listSavedNmapScans();
      setScans(items);
    } catch (err) {
      logger.error('DATA_COLLECT:LOAD', `Failed to load scans: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    checkNmapInstalled().then(setNmapInfo);
    loadScans();
  }, [loadScans]);

  // Register clipboard pane
  useEffect(() => {
    registerPanes([
      {
        id: 'data-collect',
        title: 'Nmap Data Collection & Reconnaissance Overview',
        startRow: 6,
        endRow: 35,
        getText: () => {
          if (isScanning) {
            return scanLogs.join('\n');
          }
          const lines = [
            `Nmap Reconnaissance Archive: ${nmapsDir}`,
            `Total Saved Scans: ${scans.length}`,
            '',
            ...scans.map(s => `• Target: ${s.target} ${s.isCidr ? '(CIDR Network Map)' : ''}\n  File: ${s.filename}\n  Summary: ${s.summary}\n  Date: ${s.mtime.toLocaleString()}`)
          ];
          return lines.join('\n\n');
        }
      }
    ]);
  }, [scans, scanLogs, isScanning, nmapsDir, registerPanes]);

  const handleStartScan = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanLogs([]);
    setFeedback({
      type: 'info',
      text: `Launching Nmap [${currentProfile.name}] against ${currentTarget} (${isCidrTarget ? 'CIDR Network Sweep' : 'Host'})...`
    });

    try {
      const result = await runNmapScan({
        target: currentTarget,
        profile: currentProfile.id,
        onLog: (msg) => setScanLogs(prev => [...prev, msg])
      });

      await loadScans();
      setFeedback({
        type: 'success',
        text: `✔ Scan finished in ${(result.durationMs / 1000).toFixed(2)}s! Saved to: ${path.basename(result.nmapFilePath)}`
      });
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Scan failed: ${err.message}` });
    } finally {
      setIsScanning(false);
    }
  };

  const handleViewScan = async (scan) => {
    if (!scan) return;
    try {
      const content = await readSavedScan(scan.filePath);
      openInSystemPager(content, scan.filename);
      await loadScans();
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Could not open scan: ${err.message}` });
    }
  };

  const handleEditScan = (scan) => {
    if (!scan) return;
    try {
      const res = openInEditor(scan.filePath);
      if (res.success) {
        setFeedback({ type: 'success', text: `✔ Closed editor for ${scan.filename}` });
      }
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Editor error: ${err.message}` });
    }
  };

  const handleDeleteScan = async (scan) => {
    if (!scan) return;
    try {
      await deleteSavedScan(scan.filePath);
      await loadScans();
      setCursor(c => Math.max(0, c - 1));
      setFeedback({ type: 'info', text: `🗑️ Deleted scan: ${scan.filename}` });
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Failed to delete: ${err.message}` });
    }
  };

  const handleCopyScan = async (scan) => {
    if (!scan) return;
    try {
      const content = await readSavedScan(scan.filePath);
      copyToClipboard(content);
      setFeedback({ type: 'success', text: `✔ Copied scan report for ${scan.target} to clipboard!` });
      setTimeout(() => setFeedback(null), 3000);
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Failed to copy: ${err.message}` });
    }
  };

  // Keyboard navigation & Text Input
  useInput(async (input, key) => {
    // ---------------------------------------------------------
    // Mode 1: Custom CIDR / Target Text Input Mode
    // ---------------------------------------------------------
    if (isInputMode) {
      if (key.return) {
        const trimmed = customInputText.trim();
        if (trimmed) {
          const isCidr = trimmed.includes('/');
          const newEntry = {
            label: `Custom ${isCidr ? 'CIDR' : 'Target'}: ${trimmed}`,
            value: trimmed,
            isCidr
          };
          setTargets(prev => [newEntry, ...prev]);
          setSelectedTargetIdx(0);
          // If CIDR, automatically switch profile to Sweep if currently on quick single host
          if (isCidr && selectedProfileIdx === 3) {
            setSelectedProfileIdx(0); // Ping sweep
          }
          setFeedback({ type: 'success', text: `✔ Target set to: ${trimmed}` });
        }
        setIsInputMode(false);
        setCustomInputText('');
        return;
      }

      if (key.escape) {
        setIsInputMode(false);
        setCustomInputText('');
        return;
      }

      if (key.backspace || key.delete) {
        setCustomInputText(t => t.slice(0, -1));
        return;
      }

      if (input && !key.ctrl && !key.meta) {
        setCustomInputText(t => t + input);
      }
      return;
    }

    // ---------------------------------------------------------
    // Mode 2: Standard Navigation & Actions
    // ---------------------------------------------------------
    const keyChar = (input || '').toLowerCase();

    // If active scan is running, only allow abort / escape
    if (isScanning) {
      if (key.escape || keyChar === 'q') {
        setIsScanning(false);
      }
      return;
    }

    if (key.upArrow || keyChar === 'k') {
      setCursor(c => (c > 0 ? c - 1 : Math.max(0, scans.length - 1)));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setCursor(c => (c < scans.length - 1 ? c + 1 : 0));
      return;
    }

    // [n] or [s] -> Launch New Scan
    if (keyChar === 'n' || keyChar === 's') {
      await handleStartScan();
      return;
    }

    // [i] or [/] -> Open Custom CIDR / Target Input Mode
    if (keyChar === 'i' || keyChar === '/') {
      setIsInputMode(true);
      setCustomInputText('');
      return;
    }

    // [t] -> Cycle Target
    if (keyChar === 't') {
      const nextIdx = (selectedTargetIdx + 1) % targets.length;
      setSelectedTargetIdx(nextIdx);
      const nextTarget = targets[nextIdx];
      // If switching to a CIDR target and profile is single-host quick, nudge to ping sweep
      if (nextTarget?.isCidr && selectedProfileIdx === 3) {
        setSelectedProfileIdx(0);
      }
      return;
    }

    // [p] -> Cycle Profile
    if (keyChar === 'p') {
      setSelectedProfileIdx(idx => (idx + 1) % SCAN_PROFILES.length);
      return;
    }

    // [x] -> View in XML Visualizer
    if (keyChar === 'x') {
      const scan = scans[cursor];
      if (onNavigate) {
        onNavigate('xml-visualizer', scan?.xmlPath);
      }
      return;
    }

    // [v] or [Enter] -> View in System Pager ($PAGER)
    if (keyChar === 'v' || key.return) {
      const scan = scans[cursor];
      if (scan) {
        await handleViewScan(scan);
      } else {
        await handleStartScan();
      }
      return;
    }

    // [e] -> Edit in $EDITOR
    if (keyChar === 'e') {
      const scan = scans[cursor];
      if (scan) {
        handleEditScan(scan);
      }
      return;
    }

    // [c] -> Copy to clipboard
    if (keyChar === 'c') {
      const scan = scans[cursor];
      if (scan) {
        await handleCopyScan(scan);
      }
      return;
    }

    // [d] -> Delete scan
    if (keyChar === 'd') {
      const scan = scans[cursor];
      if (scan) {
        await handleDeleteScan(scan);
      }
      return;
    }

    // Navigation delegates
    if (keyChar === 'b' && onNavigate) {
      onNavigate('dashboard');
      return;
    }
    if (keyChar === 'm' && onNavigate) {
      onNavigate('modules');
      return;
    }
    if (keyChar === 'v' && onNavigate) {
      onNavigate('values');
      return;
    }
    if (keyChar === 'u' && onNavigate) {
      onNavigate('up');
      return;
    }
    if (keyChar === 'h' && onNavigate) {
      onNavigate('hostr');
      return;
    }

    // [q] or [Esc] -> Return
    if (keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  const selectedScan = scans[cursor] || null;

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: theme.border },

    // Header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: theme.header || theme.primary }, '📡 DATA COLLECTION & NETWORK MAPPING (Nmap) '),
        React.createElement(Text, { color: theme.muted }, `(${nmapInfo.installed ? 'v' + nmapInfo.version : 'Binary Missing'})`)
      ),
      React.createElement(
        Text,
        { color: theme.muted },
        `Storage: ${nmapsDir}`
      )
    ),

    // Active Scan Configuration Bar
    React.createElement(
      Box,
      {
        flexDirection: 'column',
        paddingX: 1,
        paddingY: 0,
        marginBottom: 1,
        borderStyle: 'single',
        borderColor: isScanning ? theme.warning : theme.accent
      },
      React.createElement(
        Box,
        { justifyContent: 'space-between' },
        React.createElement(
          Box,
          null,
          React.createElement(Text, { color: theme.text, bold: true }, '🎯 Target [t]: '),
          React.createElement(
            Text,
            { color: isCidrTarget ? theme.accent : theme.text, bold: true },
            `${currentTarget} ${isCidrTarget ? '(CIDR Netmap)' : ''}  `
          ),
          React.createElement(Text, { color: theme.text, bold: true }, '⚙️ Profile [p]: '),
          React.createElement(Text, { color: theme.primary, bold: true }, `${currentProfile.name}`)
        ),
        React.createElement(
          Box,
          null,
          React.createElement(
            Text,
            { color: isScanning ? theme.warning : theme.success, bold: true },
            isScanning ? '⏳ SCANNING...' : '▶ Press [n] to Scan'
          )
        )
      ),

      // Target Label description
      React.createElement(
        Box,
        { marginTop: 0 },
        React.createElement(
          Text,
          { color: theme.muted, dimColor: true },
          `Target Description: ${currentTargetObj.label} | ${currentProfile.description}`
        )
      )
    ),

    // Custom CIDR / Target Input Box (Interactive modal overlay)
    isInputMode
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            marginY: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.accent
          },
          React.createElement(
            Text,
            { color: theme.accent, bold: true },
            '⌨️  Enter Custom Target IP or Network CIDR (e.g. 10.0.1.0/24, 192.168.1.0/24, 172.18.0.0/16):'
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(Text, { color: theme.text, bold: true }, '❯ '),
            React.createElement(Text, { color: theme.header || theme.primary, bold: true }, customInputText),
            React.createElement(Text, { color: theme.accent }, '█')
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(Text, { color: theme.muted }, 'Press [Enter] to scan target | Press [Esc] to cancel')
          )
        )
      : null,

    // Live Streaming Logs when scan is in progress
    isScanning
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginY: 1, padding: 1, borderStyle: 'single', borderColor: theme.warning },
          React.createElement(
            Box,
            null,
            React.createElement(Spinner, { type: 'dots' }),
            React.createElement(
              Text,
              { color: theme.warning, bold: true, marginLeft: 1 },
              `Executing Nmap ${currentProfile.args.join(' ')} ${currentTarget}...`
            )
          ),
          React.createElement(
            Box,
            { flexDirection: 'column', marginTop: 1 },
            scanLogs.slice(-8).map((log, i) =>
              React.createElement(Text, { key: i, color: theme.muted }, log)
            )
          )
        )
      : null,

    // Feedback Toast inside view
    feedback
      ? React.createElement(
          Box,
          {
            marginY: 1,
            paddingX: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'success' ? theme.success : feedback.type === 'error' ? theme.error : theme.info
          },
          React.createElement(
            Text,
            {
              color: feedback.type === 'success' ? theme.success : feedback.type === 'error' ? theme.error : theme.info,
              bold: true
            },
            feedback.text
          )
        )
      : null,

    // Saved Scans List Header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 0 },
      React.createElement(
        Text,
        { color: theme.text, bold: true },
        `📁 Historical Reconnaissance Archive (${scans.length} scans in XDG directory):`
      ),
      React.createElement(
        Text,
        { color: theme.muted },
        'Select with ↑/↓ | Press [v] or [Enter] to open in Pager'
      )
    ),

    // Saved Scans List
    scans.length === 0 && !isScanning
      ? React.createElement(
          Box,
          { marginY: 1, padding: 1, borderStyle: 'single', borderColor: theme.muted },
          React.createElement(
            Text,
            { color: theme.muted },
            `No saved nmap scans found in ${nmapsDir}. Press [n] to launch your first scan or [i] to enter a custom CIDR!`
          )
        )
      : scans.map((scan, index) => {
          const isFocused = index === cursor;
          return React.createElement(
            Box,
            {
              key: scan.id,
              flexDirection: 'column',
              paddingX: 1,
              paddingY: 0
            },
            React.createElement(
              Box,
              null,
              React.createElement(
                Text,
                { color: isFocused ? theme.accent : theme.muted, bold: isFocused },
                isFocused ? '❯ ' : '  '
              ),
              React.createElement(
                Text,
                { color: scan.isCidr ? theme.accent : scan.openPortsCount > 0 ? theme.success : theme.muted, bold: true },
                scan.isCidr ? `[🗺️ ${scan.hostsUp || 1} hosts] ` : `[${scan.openPortsCount} ports] `
              ),
              React.createElement(
                Text,
                { color: isFocused ? theme.accent : theme.text, bold: true },
                scan.target.padEnd(26)
              ),
              React.createElement(
                Text,
                { color: theme.muted },
                `${scan.mtime.toLocaleDateString()} ${scan.mtime.toLocaleTimeString()}  `
              ),
              React.createElement(
                Text,
                { color: theme.primary },
                `(${scan.filename})`
              )
            ),
            React.createElement(
              Box,
              { marginLeft: 4, marginBottom: 0 },
              React.createElement(
                Text,
                { color: isFocused ? theme.text : theme.muted },
                scan.summary
              )
            )
          );
        }),

    // Discovered Network Hosts Breakdown for Selected CIDR Scan
    selectedScan && selectedScan.isCidr && selectedScan.discoveredHosts && selectedScan.discoveredHosts.length > 0
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            marginTop: 1,
            padding: 1,
            borderStyle: 'single',
            borderColor: theme.accent
          },
          React.createElement(
            Text,
            { color: theme.accent, bold: true },
            `🗺️  Discovered Network Hosts Map for [${selectedScan.target}]:`
          ),
          React.createElement(
            Box,
            { flexDirection: 'column', marginTop: 1 },
            selectedScan.discoveredHosts.slice(0, 6).map((host, idx) =>
              React.createElement(
                Box,
                { key: idx },
                React.createElement(Text, { color: theme.success }, ' • '),
                React.createElement(Text, { color: theme.text, bold: true }, host.ip.padEnd(16)),
                React.createElement(
                  Text,
                  { color: theme.muted },
                  host.host !== host.ip ? `(${host.host}) ` : ''
                ),
                React.createElement(
                  Text,
                  { color: host.openPortsCount > 0 ? theme.accent : theme.muted },
                  host.openPortsCount > 0
                    ? `Open: ${host.openPorts.map(p => p.port).join(', ')}`
                    : 'Host alive (no open ports reported)'
                )
              )
            ),
            selectedScan.discoveredHosts.length > 6
              ? React.createElement(
                  Text,
                  { color: theme.muted, dimColor: true },
                  `  ...and ${selectedScan.discoveredHosts.length - 6} more hosts. Press [v] to view full map in pager.`
                )
              : null
          )
        )
      : null,

    // Footer Actions
    React.createElement(
      Box,
      {
        marginTop: 1,
        paddingTop: 1,
        borderStyle: 'single',
        borderColor: theme.muted,
        justifyContent: 'space-between',
        flexWrap: 'wrap'
      },
      React.createElement(
        Box,
        { flexWrap: 'wrap' },
        React.createElement(Text, { color: theme.success, bold: true }, '[n] '),
        React.createElement(Text, { color: theme.text }, 'Run Scan  '),
        React.createElement(Text, { color: theme.accent, bold: true }, '[i] '),
        React.createElement(Text, { color: theme.text }, 'Custom CIDR/IP  '),
        React.createElement(Text, { color: theme.accent, bold: true }, '[t] '),
        React.createElement(Text, { color: theme.text }, 'Cycle Target  '),
        React.createElement(Text, { color: theme.primary, bold: true }, '[p] '),
        React.createElement(Text, { color: theme.text }, 'Profile  '),
        React.createElement(Text, { color: theme.secondary, bold: true }, '[x] '),
        React.createElement(Text, { color: theme.text }, 'XML Map  '),
        React.createElement(Text, { color: theme.info, bold: true }, '[v] '),
        React.createElement(Text, { color: theme.text }, 'Pager  '),
        React.createElement(Text, { color: theme.secondary, bold: true }, '[e] '),
        React.createElement(Text, { color: theme.text }, 'Editor  '),
        React.createElement(Text, { color: theme.error, bold: true }, '[d] '),
        React.createElement(Text, { color: theme.text }, 'Delete  '),
        React.createElement(Text, { color: theme.muted }, '| [q/Esc] Return')
      ),
      React.createElement(
        Text,
        { color: theme.muted, dimColor: true },
        'Saved to $XDG_CONFIG_HOME/vigilante/nmaps/'
      )
    )
  );
};
