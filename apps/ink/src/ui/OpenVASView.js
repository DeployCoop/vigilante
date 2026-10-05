import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { execa } from 'execa';
import { PulseIndicator } from './PulseIndicator.js';
import { useTheme } from './theme.js';
import { useClipboard } from './ClipboardManager.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { openInSystemPager } from '../engine/pods.js';
import { listSavedXmlScans } from '../engine/nmap-xml.js';
import {
  SCAN_PROFILES,
  checkOpenVasStatus,
  runHostVulnerabilityScan,
  getCvssSeverity,
  listSavedOpenVasReports
} from '../engine/openvas.js';
import { logger } from '../utils/logger.js';

export const OpenVASView = memo(function OpenVASView({
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  namespace = 'openvas',
  initialTargetHost = null,
  onNavigate = null
}) {
  const theme = useTheme();
  const { registerPanes } = useClipboard();

  // State
  const [targetHost, setTargetHost] = useState(initialTargetHost || '127.0.0.1');
  const [discoveredHosts, setDiscoveredHosts] = useState([]);
  const [selectedHostIdx, setSelectedHostIdx] = useState(0);
  const [profileIdx, setProfileIdx] = useState(0);
  const [clusterStatus, setClusterStatus] = useState({ installed: false, ready: false, pods: [] });
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [selectedFindingIdx, setSelectedFindingIdx] = useState(0);
  const [inspectingFinding, setInspectingFinding] = useState(null);
  const [feedback, setFeedback] = useState(null);
  const [isInputTarget, setIsInputTarget] = useState(false);
  const [inputBuffer, setInputBuffer] = useState('');

  const currentProfile = SCAN_PROFILES[profileIdx] || SCAN_PROFILES[0];
  const gsaWebUrl = `https://openvas.${domain}`;

  // Poll cluster health on mount
  const refreshStatus = useCallback(async () => {
    const status = await checkOpenVasStatus({ namespace, clusterName });
    setClusterStatus(status);
  }, [namespace, clusterName]);

  // Load discovered hosts from saved Nmap scans
  useEffect(() => {
    refreshStatus();
    listSavedXmlScans().then(scans => {
      const hosts = [];
      scans.forEach(s => {
        (s.hosts || []).forEach(h => {
          if (!hosts.some(existing => existing.ip === h.ip)) {
            hosts.push(h);
          }
        });
      });
      if (hosts.length > 0) {
        setDiscoveredHosts(hosts);
        if (!initialTargetHost) {
          setTargetHost(hosts[0].ip);
        } else {
          const foundIdx = hosts.findIndex(h => h.ip === initialTargetHost);
          if (foundIdx !== -1) setSelectedHostIdx(foundIdx);
        }
      }
    });

    // Check for prior reports
    listSavedOpenVasReports('local_network', initialTargetHost || '127.0.0.1').then(reports => {
      if (reports.length > 0) {
        setScanResult(reports[0]);
      }
    });
  }, [refreshStatus, initialTargetHost]);

  // Execute scan
  const handleStartScan = async () => {
    if (isScanning) return;
    setIsScanning(true);
    setScanResult(null);
    setSelectedFindingIdx(0);
    setFeedback(null);

    const activeHostObj = discoveredHosts.find(h => h.ip === targetHost) || { ip: targetHost, ports: [] };

    try {
      const result = await runHostVulnerabilityScan({
        host: activeHostObj,
        profile: currentProfile.id,
        networkTarget: 'local_network',
        namespace,
        clusterName,
        onProgress: (p) => setScanProgress(p),
        onLog: (msg) => logger.info('OPENVAS:UI', msg)
      });
      setScanResult(result);
      setFeedback({ type: 'success', text: `✔ Scan finished with ${result.findings.length} findings!` });
    } catch (err) {
      setFeedback({ type: 'error', text: `✖ Scan failed: ${err.message}` });
    } finally {
      setIsScanning(false);
      setScanProgress(null);
    }
  };

  // Launch Greenbone Web UI in browser
  const handleOpenBrowser = async () => {
    try {
      const platform = process.platform;
      const cmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
      await execa(cmd, [gsaWebUrl]).catch(() => {});
      setFeedback({ type: 'info', text: `🌐 Launched Greenbone Web Assistant: ${gsaWebUrl}` });
      setTimeout(() => setFeedback(null), 4000);
    } catch (err) {
      setFeedback({ type: 'error', text: `Could not open browser: ${err.message}` });
    }
  };

  // Register clipboard pane
  useEffect(() => {
    if (scanResult) {
      registerPanes([
        {
          id: 'openvas-report',
          title: 'OpenVAS Vulnerability Report',
          startRow: 1,
          endRow: 100,
          getText: () => JSON.stringify(scanResult, null, 2)
        }
      ]);
    }
  }, [scanResult, registerPanes]);

  // Input Handling
  useInput((input, key) => {
    // Custom target input buffer
    if (isInputTarget) {
      if (key.escape) {
        setIsInputTarget(false);
        setInputBuffer('');
        return;
      }
      if (key.return) {
        if (inputBuffer.trim()) {
          setTargetHost(inputBuffer.trim());
          setScanResult(null);
        }
        setIsInputTarget(false);
        setInputBuffer('');
        return;
      }
      if (key.backspace || key.delete) {
        setInputBuffer(b => b.slice(0, -1));
        return;
      }
      if (input && input.length === 1 && !key.ctrl && !key.meta) {
        setInputBuffer(b => b + input);
        return;
      }
      return;
    }

    // Modal finding inspector
    if (inspectingFinding) {
      if (key.escape || (input || '').toLowerCase() === 'q') {
        setInspectingFinding(null);
        return;
      }
      if (key.return || (input || '').toLowerCase() === 'v') {
        const detailText = [
          `=== OpenVAS Vulnerability Finding Detail ===`,
          `ID: ${inspectingFinding.id}`,
          `CVE: ${inspectingFinding.cve}`,
          `Title: ${inspectingFinding.title}`,
          `CVSS v3 Score: ${inspectingFinding.cvss} (${inspectingFinding.severity})`,
          `Target: ${targetHost}:${inspectingFinding.port}/${inspectingFinding.protocol}`,
          `Service: ${inspectingFinding.service}`,
          '',
          `Description:`,
          inspectingFinding.description,
          '',
          `Impact:`,
          inspectingFinding.impact,
          '',
          `Solution / Remediation:`,
          inspectingFinding.solution,
          '',
          `References:`,
          ...(inspectingFinding.references || []).map(r => `• ${r}`)
        ].join('\n');
        openInSystemPager(detailText, `openvas-${inspectingFinding.id}`);
        return;
      }
      return;
    }

    // Tab -> Menu Hub
    if (key.tab && onNavigate) {
      onNavigate('menu');
      return;
    }

    const keyChar = (input || '').toLowerCase();

    // Start scan
    if (keyChar === 's' && !isScanning) {
      handleStartScan();
      return;
    }

    // Cycle scan profile
    if (keyChar === 'p' && !isScanning) {
      setProfileIdx(i => (i + 1) % SCAN_PROFILES.length);
      return;
    }

    // Cycle target host from discovered hosts
    if (keyChar === 'h' && discoveredHosts.length > 0 && !isScanning) {
      const nextIdx = (selectedHostIdx + 1) % discoveredHosts.length;
      setSelectedHostIdx(nextIdx);
      setTargetHost(discoveredHosts[nextIdx].ip);
      setScanResult(null);
      return;
    }

    // Enter custom target
    if (keyChar === 'i' && !isScanning) {
      setIsInputTarget(true);
      setInputBuffer(targetHost);
      return;
    }

    // Refresh cluster status
    if (keyChar === 'r') {
      refreshStatus();
      setFeedback({ type: 'info', text: 'Refreshed cluster pod status.' });
      setTimeout(() => setFeedback(null), 3000);
      return;
    }

    // Open Web UI in browser
    if (keyChar === 'w') {
      handleOpenBrowser();
      return;
    }

    // Copy JSON report
    if (keyChar === 'c' && scanResult) {
      copyToClipboard(JSON.stringify(scanResult, null, 2));
      setFeedback({ type: 'success', text: '✔ Copied OpenVAS report JSON to clipboard!' });
      setTimeout(() => setFeedback(null), 3000);
      return;
    }

    // View finding details
    if ((key.return || keyChar === 'v') && scanResult?.findings?.length > 0) {
      setInspectingFinding(scanResult.findings[selectedFindingIdx]);
      return;
    }

    // Navigate findings
    if (scanResult?.findings?.length > 0) {
      if (key.upArrow || keyChar === 'k') {
        setSelectedFindingIdx(i => (i > 0 ? i - 1 : scanResult.findings.length - 1));
        return;
      }
      if (key.downArrow || keyChar === 'j') {
        setSelectedFindingIdx(i => (i < scanResult.findings.length - 1 ? i + 1 : 0));
        return;
      }
    }

    // Return to dashboard
    if (keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
    }
  });

  const findings = scanResult?.findings || [];
  const selectedFinding = findings[selectedFindingIdx] || null;

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: theme.primary },

    // Header Banner
    React.createElement(
      Box,
      { justifyContent: 'space-between', borderStyle: 'single', borderColor: theme.border, paddingX: 1, marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: theme.primary }, '🛡️  OPENVAS / GREENBONE VULNERABILITY SCANNER  '),
        React.createElement(Text, { color: theme.secondary }, '[Community Edition 24.10]')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.muted }, 'Cluster Status: '),
        clusterStatus.ready
          ? React.createElement(Text, { color: theme.success, bold: true }, '● Online & Ready')
          : clusterStatus.installed
            ? React.createElement(Text, { color: theme.warning, bold: true }, '● Deploying / Standby')
            : React.createElement(Text, { color: theme.accent }, '● Standby (Evaluator Ready)')
      )
    ),

    // Ingress Endpoint & Web Assistant Link
    React.createElement(
      Box,
      { marginX: 1, marginBottom: 1, justifyContent: 'space-between' },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.muted }, 'Web Console: '),
        React.createElement(Text, { color: theme.accent, underline: true }, gsaWebUrl),
        React.createElement(Text, { color: theme.muted }, ' (GSAD Ingress)')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.warning }, '[w] Open in Browser')
      )
    ),

    // Target Host & Scan Profile Controls
    React.createElement(
      Box,
      { flexDirection: 'row', borderStyle: 'single', borderColor: theme.border, padding: 1, marginBottom: 1 },

      // Target Host Box
      React.createElement(
        Box,
        { flexDirection: 'column', width: '50%', paddingRight: 2 },
        React.createElement(
          Box,
          { justifyContent: 'space-between' },
          React.createElement(Text, { bold: true, color: theme.text }, 'Target Host:'),
          React.createElement(Text, { color: theme.accent }, '[i] Custom  [h] Discovered')
        ),
        isInputTarget
          ? React.createElement(
              Box,
              { marginTop: 1 },
              React.createElement(Text, { color: theme.warning }, 'Enter IP/CIDR: '),
              React.createElement(Text, { color: theme.text, bold: true }, inputBuffer),
              React.createElement(PulseIndicator, { color: theme.accent })
            )
          : React.createElement(
              Box,
              { marginTop: 1 },
              React.createElement(Text, { color: theme.success, bold: true }, `🎯 ${targetHost} `),
              discoveredHosts.length > 0
                ? React.createElement(
                    Text,
                    { color: theme.muted },
                    `(${selectedHostIdx + 1}/${discoveredHosts.length} from Nmap)`
                  )
                : null
            )
      ),

      // Scan Profile Box
      React.createElement(
        Box,
        { flexDirection: 'column', width: '50%', paddingLeft: 2, borderLeft: true, borderLeftColor: theme.border },
        React.createElement(
          Box,
          { justifyContent: 'space-between' },
          React.createElement(Text, { bold: true, color: theme.text }, 'Scan Profile:'),
          React.createElement(Text, { color: theme.accent }, '[p] Switch Profile')
        ),
        React.createElement(
          Box,
          { marginTop: 1, flexDirection: 'column' },
          React.createElement(Text, { color: theme.primary, bold: true }, `⚡ ${currentProfile.name}`),
          React.createElement(Text, { color: theme.muted }, currentProfile.description)
        )
      )
    ),

    // Active Scanning Progress or Feedback Banner
    isScanning && scanProgress
      ? React.createElement(
          Box,
          { flexDirection: 'column', marginY: 1, borderStyle: 'single', borderColor: theme.warning, padding: 1 },
          React.createElement(
            Box,
            { justifyContent: 'space-between' },
            React.createElement(
              Box,
              null,
              React.createElement(PulseIndicator, { color: theme.warning }),
              React.createElement(Text, { bold: true, color: theme.warning, marginLeft: 1 }, `SCANNING TARGET: ${targetHost}`)
            ),
            React.createElement(Text, { bold: true, color: theme.text }, `${scanProgress.percent}%`)
          ),
          React.createElement(
            Box,
            { marginY: 1 },
            React.createElement(
              Text,
              { color: theme.accent },
              '[' + '█'.repeat(Math.floor(scanProgress.percent / 4)) + ' '.repeat(25 - Math.floor(scanProgress.percent / 4)) + ']'
            )
          ),
          React.createElement(Text, { color: theme.muted }, scanProgress.message)
        )
      : null,

    // Feedback message
    feedback
      ? React.createElement(
          Box,
          { marginY: 1, paddingX: 1 },
          React.createElement(
            Text,
            { color: feedback.type === 'error' ? theme.error : theme.success, bold: true },
            feedback.text
          )
        )
      : null,

    // Scan Results & Findings Section
    scanResult
      ? React.createElement(
          Box,
          { flexDirection: 'column', flexGrow: 1 },

          // Summary Badges
          React.createElement(
            Box,
            { justifyContent: 'space-between', borderStyle: 'single', borderColor: theme.border, paddingX: 1, marginY: 1 },
            React.createElement(
              Box,
              null,
              React.createElement(Text, { bold: true, color: theme.text }, `Findings (${scanResult.summary.totalFindings}): `),
              React.createElement(Text, { color: 'red', bold: true }, ` ${scanResult.summary.critical} Crit `),
              React.createElement(Text, { color: 'magenta', bold: true }, `| ${scanResult.summary.high} High `),
              React.createElement(Text, { color: 'yellow', bold: true }, `| ${scanResult.summary.medium} Med `),
              React.createElement(Text, { color: 'blue', bold: true }, `| ${scanResult.summary.low} Low `),
              React.createElement(Text, { color: 'gray' }, `| ${scanResult.summary.log} Info`)
            ),
            React.createElement(
              Box,
              null,
              React.createElement(Text, { color: theme.muted }, 'Max CVSS: '),
              React.createElement(
                Text,
                { color: getCvssSeverity(scanResult.summary.maxCvss).color, bold: true },
                `${scanResult.summary.maxCvss} (${scanResult.summary.overallSeverity})`
              )
            )
          ),

          // Two-column Split: Findings List (Left) + Finding Details (Right)
          React.createElement(
            Box,
            { flexDirection: 'row', flexGrow: 1 },

            // Findings List
            React.createElement(
              Box,
              { flexDirection: 'column', width: '55%', paddingRight: 1 },
              findings.map((f, idx) => {
                const isSelected = idx === selectedFindingIdx;
                const sev = getCvssSeverity(f.cvss);
                return React.createElement(
                  Box,
                  {
                    key: f.id,
                    paddingX: 1,
                    backgroundColor: isSelected ? theme.primary : undefined
                  },
                  React.createElement(
                    Text,
                    { color: isSelected ? 'black' : sev.color, bold: true },
                    `${sev.badge.padEnd(12)} `
                  ),
                  React.createElement(
                    Text,
                    { color: isSelected ? 'black' : theme.accent },
                    `${String(f.port).padEnd(5)} `
                  ),
                  React.createElement(
                    Text,
                    { color: isSelected ? 'black' : theme.text, bold: isSelected },
                    f.title.length > 34 ? f.title.slice(0, 31) + '...' : f.title
                  )
                );
              })
            ),

            // Finding Inspector Panel
            React.createElement(
              Box,
              {
                flexDirection: 'column',
                width: '45%',
                paddingLeft: 2,
                borderLeft: true,
                borderLeftColor: theme.border
              },
              selectedFinding
                ? React.createElement(
                    Box,
                    { flexDirection: 'column' },
                    React.createElement(Text, { bold: true, color: theme.accent }, selectedFinding.title),
                    React.createElement(
                      Box,
                      { marginY: 1, justifyContent: 'space-between' },
                      React.createElement(Text, { color: theme.secondary }, `CVE: ${selectedFinding.cve}`),
                      React.createElement(
                        Text,
                        { color: getCvssSeverity(selectedFinding.cvss).color, bold: true },
                        `CVSS: ${selectedFinding.cvss}`
                      )
                    ),
                    React.createElement(
                      Text,
                      { color: theme.muted },
                      `Port: ${selectedFinding.port}/${selectedFinding.protocol} (${selectedFinding.service})`
                    ),
                    React.createElement(
                      Box,
                      { marginY: 1, flexDirection: 'column' },
                      React.createElement(Text, { bold: true, color: theme.text }, 'Remediation:'),
                      React.createElement(Text, { color: theme.success }, selectedFinding.solution)
                    ),
                    React.createElement(
                      Text,
                      { color: theme.warning, dimColor: true },
                      '[Enter/v] Inspect Full Advisory & Pager'
                    )
                  )
                : React.createElement(
                    Text,
                    { color: theme.muted },
                    'Select a vulnerability finding to view remediation guidance.'
                  )
            )
          )
        )
      : !isScanning
        ? React.createElement(
            Box,
            { flexDirection: 'column', padding: 2, alignItems: 'center' },
            React.createElement(Text, { color: theme.muted }, `No active scan report for target ${targetHost}.`),
            React.createElement(
              Box,
              { marginTop: 1 },
              React.createElement(Text, { color: theme.success, bold: true }, 'Press [s] to launch OpenVAS vulnerability scan.')
            )
          )
        : null,

    // Modal finding detail inspector
    inspectingFinding
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            marginTop: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.warning
          },
          React.createElement(
            Box,
            { justifyContent: 'space-between', marginBottom: 1 },
            React.createElement(Text, { bold: true, color: theme.warning }, `Vulnerability Inspector: ${inspectingFinding.cve}`),
            React.createElement(Text, { color: theme.muted }, '[Enter/v] Full Pager | [Esc/q] Close')
          ),
          React.createElement(Text, { bold: true, color: theme.text }, inspectingFinding.title),
          React.createElement(
            Box,
            { marginY: 1 },
            React.createElement(Text, { color: theme.muted }, inspectingFinding.description)
          ),
          React.createElement(
            Box,
            { marginBottom: 1, flexDirection: 'column' },
            React.createElement(Text, { color: theme.success, bold: true }, 'Remediation:'),
            React.createElement(Text, { color: theme.text }, inspectingFinding.solution)
          )
        )
      : null,

    // Action Toolbar at Bottom
    React.createElement(
      Box,
      { marginTop: 1, justifyContent: 'space-between', borderStyle: 'single', borderColor: theme.border, paddingX: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.success, bold: true }, '[s] '),
        React.createElement(Text, { color: theme.text }, 'Start Scan  '),
        React.createElement(Text, { color: theme.primary, bold: true }, '[p] '),
        React.createElement(Text, { color: theme.text }, 'Profile  '),
        React.createElement(Text, { color: theme.accent, bold: true }, '[i] '),
        React.createElement(Text, { color: theme.text }, 'Target  '),
        React.createElement(Text, { color: theme.secondary, bold: true }, '[w] '),
        React.createElement(Text, { color: theme.text }, 'Web UI  '),
        React.createElement(Text, { color: theme.warning, bold: true }, '[c] '),
        React.createElement(Text, { color: theme.text }, 'Copy JSON')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.muted }, '[Tab] Hub | [q/Esc] Return')
      )
    )
  );
});
