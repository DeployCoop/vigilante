import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import Spinner from 'ink-spinner';
import path from 'node:path';
import { listSavedXmlScans, readXmlScan } from '../engine/nmap-xml.js';
import {
  runPing,
  runBenchmark,
  runMtr,
  runCurlHeaders,
  runDnsLookup,
  runTlsCertDump,
  runArpNeighLookup,
  runFullTriageCapture
} from '../engine/diagnostics.js';
import { listHostEvidence, saveEvidenceFile, readEvidenceContent } from '../engine/evidence.js';
import { openInSystemPager } from '../engine/pods.js';
import { openInEditor } from '../utils/editor.js';
import { useClipboard } from './ClipboardManager.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

const FILTER_MODES = [
  { id: 'ALL', label: 'All Hosts' },
  { id: 'LIVE', label: '🟢 Live Hosts' },
  { id: 'OPEN_PORTS', label: '🔓 Open Ports' },
  { id: 'VULNS', label: '🛡️ Script / CVEs' }
];

export const NmapVisualizerView = ({
  initialXmlPath = null,
  onNavigate = null
}) => {
  const theme = useTheme();
  const [scans, setScans] = useState([]);
  const [activeScanIdx, setActiveScanIdx] = useState(0);
  const [hostCursor, setHostCursor] = useState(0);
  const [filterIdx, setFilterIdx] = useState(0);
  const [feedback, setFeedback] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeDiagnostic, setActiveDiagnostic] = useState(null);
  const [hostEvidenceList, setHostEvidenceList] = useState([]);

  const { registerPanes } = useClipboard();

  const loadXmlScans = useCallback(async () => {
    setIsLoading(true);
    try {
      const items = await listSavedXmlScans();
      setScans(items);

      if (initialXmlPath && items.length > 0) {
        const foundIdx = items.findIndex(s => s.filePath === initialXmlPath || s.filename === path.basename(initialXmlPath));
        if (foundIdx !== -1) {
          setActiveScanIdx(foundIdx);
        }
      }
    } catch (err) {
      logger.error('NMAP_VISUALIZER:LOAD', `Failed to load XML scans: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [initialXmlPath]);

  useEffect(() => {
    loadXmlScans();
  }, [loadXmlScans]);

  const activeScan = scans[activeScanIdx] || null;
  const currentFilter = FILTER_MODES[filterIdx] || FILTER_MODES[0];

  // Filter hosts according to active filter
  const allHosts = activeScan?.hosts || [];
  const filteredHosts = allHosts.filter(h => {
    if (currentFilter.id === 'LIVE') return h.isUp;
    if (currentFilter.id === 'OPEN_PORTS') return h.openPortsCount > 0;
    if (currentFilter.id === 'VULNS') return h.ports.some(p => p.scripts && p.scripts.length > 0);
    return true;
  });

  const selectedHost = filteredHosts[hostCursor] || null;
  const networkTarget = activeScan?.target || 'local_network';

  // Load existing evidence for selected host
  useEffect(() => {
    if (selectedHost) {
      listHostEvidence(networkTarget, selectedHost.ip).then(items => {
        setHostEvidenceList(items);
      });
    } else {
      setHostEvidenceList([]);
    }
  }, [selectedHost, networkTarget]);

  // Register clipboard pane
  useEffect(() => {
    if (!activeScan) return;
    registerPanes([
      {
        id: 'nmap-xml-visualizer',
        title: `Nmap XML Topology: ${activeScan.target}`,
        startRow: 6,
        endRow: 35,
        getText: () => {
          const lines = [
            `Nmap XML Scan Report: ${activeScan.target}`,
            `Command: ${activeScan.args}`,
            `Scanned at: ${activeScan.startStr} (Elapsed: ${activeScan.runStats.elapsedSec}s)`,
            `Total Hosts: ${activeScan.runStats.hostsTotal} | Hosts Up: ${activeScan.runStats.hostsUp} | Open Ports: ${activeScan.totalOpenPorts}`,
            '',
            '=== DISCOVERED HOSTS & PORTS ===',
            ...filteredHosts.map(h => {
              const portSummary = h.openPorts.map(p => `${p.port}/${p.protocol} (${p.service} ${p.product} ${p.version})`).join(', ');
              return `• ${h.ip} ${h.primaryHostname !== h.ip ? '(' + h.primaryHostname + ')' : ''} [${h.status.state}] - ${portSummary || 'No open ports'}`;
            })
          ];
          return lines.join('\n');
        }
      }
    ]);
  }, [activeScan, filteredHosts, registerPanes]);

  const handleViewRawXml = async () => {
    if (!activeScan) return;
    try {
      const xmlRaw = await readXmlScan(activeScan.filePath);
      const content = typeof xmlRaw === 'string' ? xmlRaw : await import('node:fs/promises').then(fs => fs.readFile(activeScan.filePath, 'utf8'));
      openInSystemPager(content, activeScan.filename);
      await loadXmlScans();
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Pager error: ${err.message}` });
    }
  };

  const handleEditXml = () => {
    if (!activeScan) return;
    try {
      const res = openInEditor(activeScan.filePath);
      if (res.success) {
        setFeedback({ type: 'success', text: `✔ Closed editor for ${activeScan.filename}` });
        loadXmlScans();
      }
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Editor error: ${err.message}` });
    }
  };

  const handleCopyReport = () => {
    if (!activeScan) return;
    try {
      const jsonReport = JSON.stringify(activeScan, null, 2);
      copyToClipboard(jsonReport);
      setFeedback({ type: 'success', text: `✔ Copied structured JSON report for ${activeScan.target} to clipboard!` });
      setTimeout(() => setFeedback(null), 3000);
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Failed to copy: ${err.message}` });
    }
  };

  // Diagnostic Executions
  const executePing = async (host) => {
    if (!host) return;
    setActiveDiagnostic({ tool: 'Ping (ICMP)', host: host.ip, isRunning: true, output: '' });
    const res = await runPing(host.ip);
    await saveEvidenceFile(networkTarget, host.ip, 'ping.json', res);
    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    setActiveDiagnostic({
      tool: 'Ping (ICMP)',
      host: host.ip,
      isRunning: false,
      command: res.command,
      output: res.output,
      success: res.success,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/ping.json`
    });
  };

  const executeBenchmark = async (host) => {
    if (!host) return;
    const hasHttps = host.ports.some(p => p.port === 443 && p.state === 'open');
    const httpPort = host.ports.find(p => (p.port === 80 || p.port === 443 || p.service.includes('http')) && p.state === 'open');
    const targetPort = httpPort ? httpPort.port : (hasHttps ? 443 : 80);

    setActiveDiagnostic({ tool: 'HTTP Benchmark (ab)', host: host.ip, isRunning: true, output: '' });
    const res = await runBenchmark(host.ip, { port: targetPort, isHttps: hasHttps });
    await saveEvidenceFile(networkTarget, host.ip, 'benchmark.txt', res.output);
    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    setActiveDiagnostic({
      tool: res.tool || 'HTTP Benchmark (ab)',
      host: host.ip,
      isRunning: false,
      command: res.command,
      output: res.output,
      success: res.success,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/benchmark.txt`
    });
  };

  const executeMtr = async (host) => {
    if (!host) return;
    setActiveDiagnostic({ tool: 'MTR Network Path Trace', host: host.ip, isRunning: true, output: '' });
    const res = await runMtr(host.ip);
    await saveEvidenceFile(networkTarget, host.ip, 'mtr.txt', res.output);
    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    setActiveDiagnostic({
      tool: res.tool || 'MTR',
      host: host.ip,
      isRunning: false,
      command: res.command,
      output: res.output,
      success: res.success,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/mtr.txt`
    });
  };

  const executeCurl = async (host) => {
    if (!host) return;
    const hasHttps = host.ports.some(p => p.port === 443 && p.state === 'open');
    const httpPort = host.ports.find(p => (p.port === 80 || p.port === 443 || p.service.includes('http')) && p.state === 'open');
    const targetPort = httpPort ? httpPort.port : (hasHttps ? 443 : 80);

    setActiveDiagnostic({ tool: 'HTTP Headers & TLS (curl)', host: host.ip, isRunning: true, output: '' });
    const res = await runCurlHeaders(host.ip, { port: targetPort, isHttps: hasHttps });
    await saveEvidenceFile(networkTarget, host.ip, 'http_headers.txt', res.output);
    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    setActiveDiagnostic({
      tool: 'HTTP Headers (curl)',
      host: host.ip,
      isRunning: false,
      command: res.command,
      output: res.output,
      success: res.success,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/http_headers.txt`
    });
  };

  const executeTlsCertDump = async (host) => {
    if (!host) return;
    const sslPort = host.ports.find(p => p.port === 443 || p.service.includes('ssl') || p.service.includes('https'));
    const targetPort = sslPort ? sslPort.port : 443;

    setActiveDiagnostic({ tool: 'OpenSSL TLS Certificate Dump', host: host.ip, isRunning: true, output: '' });
    const res = await runTlsCertDump(host.ip, targetPort);
    await saveEvidenceFile(networkTarget, host.ip, 'tls_certificates.pem', res.output);
    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    setActiveDiagnostic({
      tool: 'TLS Certificate Chain (OpenSSL)',
      host: host.ip,
      isRunning: false,
      command: res.command,
      output: res.output,
      success: res.success,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/tls_certificates.pem`
    });
  };

  const executeDns = async (host) => {
    if (!host) return;
    setActiveDiagnostic({ tool: 'DNS Resolution & PTR (dig)', host: host.ip, isRunning: true, output: '' });
    const res = await runDnsLookup(host.ip);
    await saveEvidenceFile(networkTarget, host.ip, 'dns_records.json', res);
    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    setActiveDiagnostic({
      tool: 'DNS Lookup (dig)',
      host: host.ip,
      isRunning: false,
      command: res.command,
      output: res.output,
      success: res.success,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/dns_records.json`
    });
  };

  const executeArp = async (host) => {
    if (!host) return;
    setActiveDiagnostic({ tool: 'Kernel ARP & Neighbor Lookup', host: host.ip, isRunning: true, output: '' });
    const res = await runArpNeighLookup(host.ip);
    await saveEvidenceFile(networkTarget, host.ip, 'arp_neighbors.json', res);
    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    setActiveDiagnostic({
      tool: 'ARP & Neighbor Table (ip neigh)',
      host: host.ip,
      isRunning: false,
      command: res.command,
      output: res.output,
      success: res.success,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/arp_neighbors.json`
    });
  };

  const executeFullTriage = async (host) => {
    if (!host) return;
    const hasHttps = host.ports.some(p => p.port === 443 && p.state === 'open');
    const httpPort = host.ports.find(p => (p.port === 80 || p.port === 443 || p.service.includes('http')) && p.state === 'open');
    const targetPort = httpPort ? httpPort.port : (hasHttps ? 443 : 80);

    setActiveDiagnostic({ tool: '🚨 Full IR Triage Evidence Bundle', host: host.ip, isRunning: true, output: '' });
    const res = await runFullTriageCapture(host.ip, {
      networkCidr: networkTarget,
      port: targetPort,
      isHttps: hasHttps
    });

    const updatedEvidence = await listHostEvidence(networkTarget, host.ip);
    setHostEvidenceList(updatedEvidence);

    const artifactList = res.saved.artifacts.map(a => `  • ${a.name} (${a.type})`).join('\n');
    const summaryText = [
      `=== 🛡️ Incident Response Triage Bundle Complete ===`,
      `Target: ${host.ip} in network ${networkTarget}`,
      `Captured: ${res.saved.artifacts.length} evidence artifacts in ${res.durationMs}ms`,
      `Saved to: $XDG_CONFIG_HOME/vigilante/evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/`,
      '',
      `Evidence Artifacts Generated:`,
      artifactList,
      '',
      `Press [v] to inspect the triage summary index in pager.`
    ].join('\n');

    setActiveDiagnostic({
      tool: 'Full IR Triage Bundle',
      host: host.ip,
      isRunning: false,
      command: `Parallel forensic triage probes against ${host.ip}`,
      output: summaryText,
      success: true,
      savedFile: `evidence/${networkTarget.replace(/\//g, '_')}/${host.ip}/triage_summary.json`
    });
  };

  // Keyboard navigation
  useInput((input, key) => {
    // [Tab] -> Operations Hub Menu
    if (key.tab && onNavigate) {
      onNavigate('menu');
      return;
    }

    const keyChar = (input || '').toLowerCase();

    // If active diagnostic modal is open
    if (activeDiagnostic) {
      if (key.escape || keyChar === 'q' || keyChar === 'x') {
        setActiveDiagnostic(null);
        return;
      }
      if (keyChar === 'v' || key.return) {
        if (activeDiagnostic.output) {
          openInSystemPager(activeDiagnostic.output, `${activeDiagnostic.tool}-${activeDiagnostic.host}`);
        }
        return;
      }
      if (keyChar === 'c') {
        if (activeDiagnostic.output) {
          copyToClipboard(activeDiagnostic.output);
          setFeedback({ type: 'success', text: '✔ Copied diagnostic output to clipboard!' });
          setTimeout(() => setFeedback(null), 3000);
        }
        return;
      }
      return;
    }

    // Host Quick Diagnostic Triggers
    if (selectedHost) {
      // [t] -> Full Incident Response Triage Bundle
      if (keyChar === 't') {
        executeFullTriage(selectedHost);
        return;
      }
      // [p] -> Ping host
      if (keyChar === 'p') {
        executePing(selectedHost);
        return;
      }
      // [b] -> ApacheBench / HTTP load test
      if (keyChar === 'b') {
        executeBenchmark(selectedHost);
        return;
      }
      // [m] -> MTR Network trace
      if (keyChar === 'm') {
        executeMtr(selectedHost);
        return;
      }
      // [h] -> HTTP Header inspection (curl -I)
      if (keyChar === 'h') {
        executeCurl(selectedHost);
        return;
      }
      // [c] -> OpenSSL TLS Certificate Dump
      if (keyChar === 'c') {
        executeTlsCertDump(selectedHost);
        return;
      }
      // [d] -> DNS resolution (dig)
      if (keyChar === 'd') {
        executeDns(selectedHost);
        return;
      }
      // [a] -> ARP / Neighbor table inspection
      if (keyChar === 'a') {
        executeArp(selectedHost);
        return;
      }
    }

    // Navigate hosts
    if (key.upArrow || keyChar === 'k') {
      setHostCursor(c => (c > 0 ? c - 1 : Math.max(0, filteredHosts.length - 1)));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setHostCursor(c => (c < filteredHosts.length - 1 ? c + 1 : 0));
      return;
    }

    // Switch XML scan file [s] or [Tab]
    if (keyChar === 's' || key.tab) {
      if (scans.length > 1) {
        const nextScan = (activeScanIdx + 1) % scans.length;
        setActiveScanIdx(nextScan);
        setHostCursor(0);
        setFeedback({ type: 'info', text: `Switched to scan: ${scans[nextScan].filename}` });
      }
      return;
    }

    // Cycle filter [f]
    if (keyChar === 'f') {
      const nextFilter = (filterIdx + 1) % FILTER_MODES.length;
      setFilterIdx(nextFilter);
      setHostCursor(0);
      return;
    }

    // View raw XML [x] or [v] or [Enter]
    if (keyChar === 'x' || keyChar === 'v' || key.return) {
      handleViewRawXml();
      return;
    }

    // Edit XML in $EDITOR [e]
    if (keyChar === 'e') {
      handleEditXml();
      return;
    }

    // Copy report [y]
    if (keyChar === 'y') {
      handleCopyReport();
      return;
    }

    // Jump to Nmap Scanner [n]
    if (keyChar === 'n' && onNavigate) {
      onNavigate('nmap');
      return;
    }

    // Standard navigation
    if (keyChar === 'b' && onNavigate) {
      onNavigate('dashboard');
      return;
    }
    if (keyChar === 'u' && onNavigate) {
      onNavigate('up');
      return;
    }

    // [q] or [Esc] -> Return
    if (keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  if (isLoading) {
    return React.createElement(
      Box,
      { padding: 1, borderStyle: 'round', borderColor: theme.border },
      React.createElement(Text, { color: theme.accent }, '⏳ Loading Nmap XML reports...')
    );
  }

  if (!activeScan) {
    return React.createElement(
      Box,
      { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: theme.border },
      React.createElement(
        Text,
        { color: theme.header || theme.primary, bold: true },
        '📊 NMAP XML TOPOLOGY & NETWORK VISUALIZER'
      ),
      React.createElement(
        Box,
        { marginY: 1, padding: 1, borderStyle: 'single', borderColor: theme.muted },
        React.createElement(
          Text,
          { color: theme.muted },
          'No saved Nmap XML reports found in $XDG_CONFIG_HOME/vigilante/nmaps/. Press [n] to launch an Nmap scan and generate XML reports!'
        )
      ),
      React.createElement(
        Box,
        { marginTop: 1 },
        React.createElement(Text, { color: theme.success, bold: true }, '[n] '),
        React.createElement(Text, { color: theme.text }, 'Launch Nmap Scanner  '),
        React.createElement(Text, { color: theme.muted }, '| [q/Esc] Return')
      )
    );
  }

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: theme.border },

    // Top Header Banner
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: theme.header || theme.primary }, '📊 NMAP XML NETWORK TOPOLOGY VISUALIZER '),
        React.createElement(Text, { color: theme.muted }, `(${activeScan.scanner} v${activeScan.version})`)
      ),
      React.createElement(
        Text,
        { color: theme.accent, bold: true },
        `Scan [${activeScanIdx + 1}/${scans.length}]: ${activeScan.filename}`
      )
    ),

    // Scan Metadata Card
    React.createElement(
      Box,
      {
        flexDirection: 'column',
        paddingX: 1,
        paddingY: 0,
        marginBottom: 1,
        borderStyle: 'single',
        borderColor: theme.accent
      },
      React.createElement(
        Box,
        { justifyContent: 'space-between' },
        React.createElement(
          Box,
          null,
          React.createElement(Text, { color: theme.text, bold: true }, '🎯 Target: '),
          React.createElement(Text, { color: theme.accent, bold: true }, `${activeScan.target}  `),
          React.createElement(Text, { color: theme.text, bold: true }, '🕒 Date: '),
          React.createElement(Text, { color: theme.text }, `${activeScan.startStr || 'Recent'}  `),
          React.createElement(Text, { color: theme.text, bold: true }, '⏱️  Duration: '),
          React.createElement(Text, { color: theme.text }, `${activeScan.runStats.elapsedSec}s`)
        ),
        React.createElement(
          Box,
          null,
          React.createElement(Text, { color: theme.success, bold: true }, `🟢 ${activeScan.runStats.hostsUp} Up  `),
          React.createElement(Text, { color: theme.muted }, `🔴 ${activeScan.runStats.hostsDown || 0} Down  `),
          React.createElement(Text, { color: theme.primary, bold: true }, `🔓 ${activeScan.totalOpenPorts} Ports  `),
          React.createElement(Text, { color: theme.secondary, bold: true }, `🛡️ ${activeScan.totalScripts} Scripts`)
        )
      ),
      React.createElement(
        Box,
        { marginTop: 0 },
        React.createElement(
          Text,
          { color: theme.muted, dimColor: true },
          `Command: ${activeScan.args}`
        )
      )
    ),

    // Filter Bar & Host Count
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.text, bold: true }, 'Filter [f]: '),
        FILTER_MODES.map((f, i) =>
          React.createElement(
            Box,
            { key: f.id, marginRight: 2 },
            React.createElement(
              Text,
              {
                color: i === filterIdx ? theme.accent : theme.muted,
                bold: i === filterIdx,
                underline: i === filterIdx
              },
              `[${f.label}]`
            )
          )
        )
      ),
      React.createElement(
        Text,
        { color: theme.muted },
        `Showing ${filteredHosts.length} of ${allHosts.length} hosts | Switch Scan [s]`
      )
    ),

    // Feedback Alert Banner
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

    // Live Diagnostic Inspector Modal / Box
    activeDiagnostic
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            marginBottom: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: activeDiagnostic.isRunning ? theme.warning : (activeDiagnostic.success ? theme.success : theme.error)
          },
          React.createElement(
            Box,
            { justifyContent: 'space-between', marginBottom: 0 },
            React.createElement(
              Box,
              null,
              activeDiagnostic.isRunning
                ? React.createElement(Spinner, { type: 'dots' })
                : null,
              React.createElement(
                Text,
                { color: theme.accent, bold: true, marginLeft: activeDiagnostic.isRunning ? 1 : 0 },
                ` ⚡ ${activeDiagnostic.tool}: ${activeDiagnostic.host}`
              )
            ),
            React.createElement(
              Text,
              { color: theme.muted },
              activeDiagnostic.isRunning ? 'Executing...' : '[v/Enter] Pager | [c] Copy | [Esc] Close'
            )
          ),
          activeDiagnostic.command
            ? React.createElement(
                Text,
                { color: theme.muted, dimColor: true },
                `Command: ${activeDiagnostic.command}`
              )
            : null,
          activeDiagnostic.savedFile
            ? React.createElement(
                Text,
                { color: theme.success, dimColor: true },
                `✔ Saved Artifact: $XDG_CONFIG_HOME/vigilante/${activeDiagnostic.savedFile}`
              )
            : null,
          React.createElement(
            Box,
            { marginY: 1, flexDirection: 'column' },
            activeDiagnostic.isRunning
              ? React.createElement(Text, { color: theme.text }, 'Running diagnostic probe against host...')
              : React.createElement(
                  Text,
                  { color: theme.text },
                  activeDiagnostic.output.split('\n').slice(0, 8).join('\n') +
                    (activeDiagnostic.output.split('\n').length > 8 ? '\n... (Press [v] to view full report in pager)' : '')
                )
          )
        )
      : null,

    // Main Content: Host Tree & Selected Host Detail Matrix
    React.createElement(
      Box,
      { flexDirection: 'row', justifyContent: 'space-between' },

      // Left Column: Discovered Hosts List
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '45%',
          borderStyle: 'single',
          borderColor: theme.muted,
          paddingX: 1
        },
        React.createElement(
          Text,
          { color: theme.text, bold: true, marginBottom: 0 },
          '🌐 Network Hosts Tree:'
        ),
        filteredHosts.length === 0
          ? React.createElement(
              Text,
              { color: theme.muted, marginY: 1 },
              'No hosts match current filter.'
            )
          : filteredHosts.map((host, idx) => {
              const isFocused = idx === hostCursor;
              return React.createElement(
                Box,
                { key: host.ip, flexDirection: 'column', marginY: 0 },
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
                    { color: host.isUp ? theme.success : theme.error, bold: true },
                    host.isUp ? '● ' : '○ '
                  ),
                  React.createElement(
                    Text,
                    { color: isFocused ? theme.accent : theme.text, bold: true },
                    host.ip.padEnd(16)
                  ),
                  React.createElement(
                    Text,
                    { color: host.openPortsCount > 0 ? theme.primary : theme.muted },
                    `[${host.openPortsCount} ports]`
                  )
                ),
                isFocused && host.primaryHostname !== host.ip
                  ? React.createElement(
                      Box,
                      { marginLeft: 4 },
                      React.createElement(Text, { color: theme.muted }, `↳ ${host.primaryHostname}`)
                    )
                  : null
              );
            })
      ),

      // Right Column: Selected Host Deep Inspection Matrix
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '53%',
          borderStyle: 'single',
          borderColor: theme.accent,
          paddingX: 1
        },
        selectedHost
          ? React.createElement(
              Box,
              { flexDirection: 'column' },
              React.createElement(
                Box,
                { justifyContent: 'space-between', marginBottom: 1 },
                React.createElement(
                  Text,
                  { color: theme.accent, bold: true },
                  `🔍 Host: ${selectedHost.ip} ${selectedHost.primaryHostname !== selectedHost.ip ? '(' + selectedHost.primaryHostname + ')' : ''}`
                ),
                React.createElement(
                  Text,
                  { color: selectedHost.isUp ? theme.success : theme.error, bold: true },
                  `Status: ${selectedHost.status.state.toUpperCase()} ${selectedHost.status.latency ? '(' + selectedHost.status.latency + ')' : ''}`
                )
              ),

              // Live Incident Response & Forensic Probes Banner
              React.createElement(
                Box,
                {
                  paddingX: 1,
                  marginBottom: 1,
                  borderStyle: 'single',
                  borderColor: theme.secondary,
                  flexWrap: 'wrap'
                },
                React.createElement(Text, { color: theme.error, bold: true }, '[t] '),
                React.createElement(Text, { color: theme.text }, 'Full Triage Bundle  '),
                React.createElement(Text, { color: theme.success, bold: true }, '[p] '),
                React.createElement(Text, { color: theme.text }, 'Ping  '),
                React.createElement(Text, { color: theme.primary, bold: true }, '[b] '),
                React.createElement(Text, { color: theme.text }, 'Bench  '),
                React.createElement(Text, { color: theme.accent, bold: true }, '[m] '),
                React.createElement(Text, { color: theme.text }, 'MTR  '),
                React.createElement(Text, { color: theme.info, bold: true }, '[h] '),
                React.createElement(Text, { color: theme.text }, 'HTTP  '),
                React.createElement(Text, { color: theme.secondary, bold: true }, '[c] '),
                React.createElement(Text, { color: theme.text }, 'TLS Certs  '),
                React.createElement(Text, { color: theme.warning, bold: true }, '[d] '),
                React.createElement(Text, { color: theme.text }, 'DNS  '),
                React.createElement(Text, { color: theme.accent, bold: true }, '[a] '),
                React.createElement(Text, { color: theme.text }, 'ARP')
              ),

              // Saved Evidence Vault Artifacts for this Host
              hostEvidenceList.length > 0
                ? React.createElement(
                    Box,
                    {
                      flexDirection: 'column',
                      marginBottom: 1,
                      paddingX: 1,
                      borderStyle: 'single',
                      borderColor: theme.success
                    },
                    React.createElement(
                      Text,
                      { color: theme.success, bold: true },
                      `📁 Saved Evidence in Vault (${hostEvidenceList.length} artifacts)${hostEvidenceList.some(a => a.isSigned) ? ' [🔏 GPG Signed]' : ''}:`
                    ),
                    React.createElement(
                      Text,
                      { color: theme.muted, dimColor: true },
                      `Path: evidence/${networkTarget.replace(/\//g, '_')}/${selectedHost.ip}/`
                    ),
                    React.createElement(
                      Text,
                      { color: theme.text },
                      hostEvidenceList.map(a => `${a.name}${a.isSigned ? ' 🔏' : ''} (${Math.round(a.sizeBytes / 1024 * 10) / 10}KB)`).join(' | ')
                    )
                  )
                : null,

              // Hardware & OS Info
              selectedHost.mac || selectedHost.bestOsMatch
                ? React.createElement(
                    Box,
                    { flexDirection: 'column', marginBottom: 1 },
                    selectedHost.mac
                      ? React.createElement(
                          Text,
                          { color: theme.muted },
                          `MAC: ${selectedHost.mac} ${selectedHost.macVendor ? '(' + selectedHost.macVendor + ')' : ''}`
                        )
                      : null,
                    selectedHost.bestOsMatch
                      ? React.createElement(
                          Text,
                          { color: theme.secondary },
                          `OS: ${selectedHost.bestOsMatch.name} (${selectedHost.bestOsMatch.accuracy}% match)`
                        )
                      : null
                  )
                : null,

              // Port Matrix
              React.createElement(
                Text,
                { color: theme.text, bold: true },
                `Ports & Services (${selectedHost.ports.length} total, ${selectedHost.openPortsCount} open):`
              ),
              selectedHost.ports.length === 0
                ? React.createElement(
                    Text,
                    { color: theme.muted },
                    'No ports scanned or all ports filtered.'
                  )
                : selectedHost.ports.map((p, i) =>
                    React.createElement(
                      Box,
                      { key: i, flexDirection: 'column', marginY: 0 },
                      React.createElement(
                        Box,
                        null,
                        React.createElement(
                          Text,
                          { color: p.state === 'open' ? theme.success : theme.muted, bold: true },
                          `  • ${String(p.port).padEnd(5)}/${p.protocol.padEnd(4)} `
                        ),
                        React.createElement(
                          Text,
                          { color: p.state === 'open' ? theme.accent : theme.muted, bold: true },
                          `${p.state.toUpperCase().padEnd(8)} `
                        ),
                        React.createElement(
                          Text,
                          { color: theme.text },
                          `${p.service} `
                        ),
                        React.createElement(
                          Text,
                          { color: theme.primary },
                          `${p.product} ${p.version}`.trim()
                        )
                      ),
                      // Scripts output
                      p.scripts && p.scripts.length > 0
                        ? p.scripts.map((script, sIdx) =>
                            React.createElement(
                              Box,
                              { key: sIdx, marginLeft: 6 },
                              React.createElement(
                                Text,
                                { color: theme.warning },
                                `↳ [${script.id}]: ${script.output.slice(0, 80)}${script.output.length > 80 ? '...' : ''}`
                              )
                            )
                          )
                        : null
                    )
                  )
            )
          : React.createElement(
              Text,
              { color: theme.muted },
              'Select a host from the list to view port matrix and security details.'
            )
      )
    )
  );
};
