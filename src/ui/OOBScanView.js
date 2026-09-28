import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { PulseIndicator } from './PulseIndicator.js';
import path from 'node:path';
import {
  listSavedOobScans,
  runOobScan,
  deleteSavedOobScan,
  readSavedOobScan,
  exportRakpHashes,
  checkOobscanInstalled,
  detectOobTargets,
  OOB_SCAN_PROFILES
} from '../engine/oobscan.js';
import { getVigilanteOobscansDir } from '../engine/config.js';
import { openInSystemPager } from '../engine/pods.js';
import { openInEditor } from '../utils/editor.js';
import { useClipboard } from './ClipboardManager.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

export const OOBScanView = memo(function OOBScanView({
  domain = 'vigilante.local',
  ip = '127.0.0.1',
  onNavigate = null
}) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0); // 0: New Scan, 1: Saved Scans, 2: BMC Inspector & Hashes
  const [scans, setScans] = useState([]);
  const [scanCursor, setScanCursor] = useState(0);
  const [bmcsCursor, setBmcsCursor] = useState(0);
  const [isScanning, setIsScanning] = useState(false);
  const [scanLogs, setScanLogs] = useState([]);
  const [targets, setTargets] = useState([]);
  const [selectedTargetIdx, setSelectedTargetIdx] = useState(0);
  const [selectedProfileIdx, setSelectedProfileIdx] = useState(0);
  const [feedback, setFeedback] = useState(null);
  const [oobscanInfo, setOobscanInfo] = useState({ installed: false, version: '' });

  // Custom Input State
  const [isInputMode, setIsInputMode] = useState(false);
  const [customInputText, setCustomInputText] = useState('');

  const { registerPanes } = useClipboard();

  useEffect(() => {
    checkOobscanInstalled().then(setOobscanInfo);
    const discovered = detectOobTargets({ ip, domain });
    setTargets(discovered);
  }, [ip, domain]);

  const loadScans = useCallback(async () => {
    try {
      const items = await listSavedOobScans();
      setScans(items);
    } catch (err) {
      logger.error('OOBSCAN_VIEW:LOAD', `Failed to load scans: ${err.message}`);
    }
  }, []);

  useEffect(() => {
    loadScans();
  }, [loadScans]);

  const currentTargetObj = targets[selectedTargetIdx] || { label: ip, value: ip, isCidr: false };
  const currentTarget = currentTargetObj.value;
  const currentProfile = OOB_SCAN_PROFILES[selectedProfileIdx] || OOB_SCAN_PROFILES[0];
  const activeScan = scans[scanCursor] || null;
  const activeBmc = activeScan?.bmcs?.[bmcsCursor] || null;
  const oobscansDir = getVigilanteOobscansDir();

  // Handle Scan Execution
  const handleStartScan = async () => {
    if (isScanning) return;
    if (!oobscanInfo.installed) {
      setFeedback({ type: 'error', message: 'oobscan binary is not installed in PATH. Please install it first.' });
      return;
    }

    setIsScanning(true);
    setScanLogs([`Starting ${currentProfile.name} on ${currentTarget}...`]);
    setFeedback(null);

    try {
      const res = await runOobScan({
        target: currentTarget,
        profile: currentProfile.id,
        onLog: (line) => {
          setScanLogs(prev => [...prev.slice(-30), line]);
        }
      });

      await loadScans();
      setActiveTab(1); // Jump to saved scans view
      setScanCursor(0);
      setFeedback({
        type: 'success',
        message: `Scan complete: ${res.parsed.totalBmcs} BMCs, ${res.parsed.totalRakpHashes} RAKP hashes captured!`
      });
    } catch (err) {
      setFeedback({ type: 'error', message: `Scan failed: ${err.message}` });
    } finally {
      setIsScanning(false);
    }
  };

  // Keyboard navigation
  useInput((input, key) => {
    // If in custom input mode
    if (isInputMode) {
      if (key.return) {
        if (customInputText.trim()) {
          const val = customInputText.trim();
          setTargets(prev => [
            { label: `Custom Target [${val}]`, value: val, isCidr: val.includes('/'), isLinkLocal: val.startsWith('ff02') },
            ...prev
          ]);
          setSelectedTargetIdx(0);
        }
        setIsInputMode(false);
        setCustomInputText('');
      } else if (key.escape) {
        setIsInputMode(false);
        setCustomInputText('');
      } else if (key.backspace || key.delete) {
        setCustomInputText(prev => prev.slice(0, -1));
      } else if (input && !key.ctrl && !key.meta) {
        setCustomInputText(prev => prev + input);
      }
      return;
    }

    if (key.tab) {
      setActiveTab(prev => (prev + 1) % 3);
      setFeedback(null);
      return;
    }

    if (input === '1') { setActiveTab(0); return; }
    if (input === '2') { setActiveTab(1); return; }
    if (input === '3') { setActiveTab(2); return; }

    if (input === 'q' || key.escape) {
      if (onNavigate) onNavigate('HUB');
      return;
    }

    if (input === 'r') {
      loadScans();
      checkOobscanInstalled().then(setOobscanInfo);
      setFeedback({ type: 'info', message: 'Refreshed OOB scans and binary status.' });
      return;
    }

    // Tab 0: New Scan Controls
    if (activeTab === 0) {
      if (input === 'i') {
        setIsInputMode(true);
        setCustomInputText('');
        return;
      }

      if (key.upArrow) {
        setSelectedTargetIdx(prev => Math.max(0, prev - 1));
      } else if (key.downArrow) {
        setSelectedTargetIdx(prev => Math.min(targets.length - 1, prev + 1));
      } else if (key.leftArrow) {
        setSelectedProfileIdx(prev => Math.max(0, prev - 1));
      } else if (key.rightArrow) {
        setSelectedProfileIdx(prev => Math.min(OOB_SCAN_PROFILES.length - 1, prev + 1));
      } else if (key.return) {
        handleStartScan();
      }
      return;
    }

    // Tab 1: Saved Scans Archive
    if (activeTab === 1) {
      if (key.upArrow) {
        setScanCursor(prev => Math.max(0, prev - 1));
        setBmcsCursor(0);
      } else if (key.downArrow) {
        setScanCursor(prev => Math.min(scans.length - 1, prev + 1));
        setBmcsCursor(0);
      } else if (key.return) {
        setActiveTab(2); // Jump into BMC inspector for this scan
      } else if (input === 'd' && activeScan) {
        deleteSavedOobScan(activeScan.filePath)
          .then(() => {
            loadScans();
            setFeedback({ type: 'info', message: `Deleted ${activeScan.filename}` });
          })
          .catch(err => setFeedback({ type: 'error', message: err.message }));
      } else if (input === 'p' && activeScan) {
        openInSystemPager(activeScan.filePath);
      } else if (input === 'e' && activeScan) {
        openInEditor(activeScan.filePath);
      } else if ((input === 'c' || input === 'y') && activeScan) {
        copyToClipboard(String(activeScan.summary || activeScan.target));
        setFeedback({ type: 'success', message: 'Copied scan summary to clipboard!' });
      }
      return;
    }

    // Tab 2: BMC Inspector & RAKP Vault
    if (activeTab === 2) {
      const bmcsList = activeScan?.bmcs || [];
      if (key.upArrow) {
        setBmcsCursor(prev => Math.max(0, prev - 1));
      } else if (key.downArrow) {
        setBmcsCursor(prev => Math.min(bmcsList.length - 1, prev + 1));
      } else if ((input === 'c' || input === 'y') && activeBmc) {
        const hashcatLine = activeBmc.rakp?.find(r => r.hashcat)?.hashcat;
        if (hashcatLine) {
          copyToClipboard(`hashcat -m 7300 '${hashcatLine}' rockyou.txt`);
          setFeedback({ type: 'success', message: 'Copied Hashcat -m 7300 command to clipboard!' });
        } else if (activeBmc.creds?.length > 0) {
          const cred = activeBmc.creds[0];
          copyToClipboard(`${cred.user}:${cred.pass}`);
          setFeedback({ type: 'success', message: `Copied credentials (${cred.user}:${cred.pass}) to clipboard!` });
        } else {
          copyToClipboard(activeBmc.host);
          setFeedback({ type: 'info', message: `Copied BMC host ${activeBmc.host} to clipboard!` });
        }
      } else if (input === 'h' && activeScan) {
        exportRakpHashes(activeScan.filePath)
          .then(res => {
            loadScans();
            setFeedback({ type: 'success', message: `Exported ${res.count} RAKP hashes to ${path.basename(res.hashcatFile)}` });
          })
          .catch(err => setFeedback({ type: 'error', message: err.message }));
      } else if (input === 'p' && activeScan) {
        openInSystemPager(activeScan.filePath);
      }
    }
  });

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, width: '100%' },

    // Header
    React.createElement(
      Box,
      {
        justifyContent: 'space-between',
        borderStyle: 'round',
        borderColor: theme.primary || 'cyan',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        { gap: 1, alignItems: 'center' },
        React.createElement(Text, { bold: true, color: theme.primary || 'cyan' }, '📡 OOBSCAN'),
        React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
        React.createElement(Text, { color: theme.text || 'white' }, 'BMC & Out-of-Band Hardware Security Audit')
      ),
      React.createElement(
        Box,
        { gap: 1, alignItems: 'center' },
        React.createElement(PulseIndicator, { active: isScanning }),
        oobscanInfo.installed
          ? React.createElement(Text, { color: theme.success || 'green' }, `✔ Binary: ${oobscanInfo.version}`)
          : React.createElement(Text, { color: theme.error || 'red' }, '✖ oobscan Not Installed'),
        React.createElement(Text, { color: theme.muted || 'gray' }, `(${scans.length} Scans Archived)`)
      )
    ),

    // Tabs
    React.createElement(
      Box,
      { gap: 2, marginBottom: 1 },
      React.createElement(
        Box,
        {
          borderStyle: activeTab === 0 ? 'bold' : 'single',
          borderColor: activeTab === 0 ? (theme.accent || 'yellow') : (theme.muted || 'gray'),
          paddingX: 1
        },
        React.createElement(
          Text,
          { bold: activeTab === 0, color: activeTab === 0 ? (theme.accent || 'yellow') : (theme.muted || 'gray') },
          '[1] New Scan & Targets'
        )
      ),
      React.createElement(
        Box,
        {
          borderStyle: activeTab === 1 ? 'bold' : 'single',
          borderColor: activeTab === 1 ? (theme.accent || 'yellow') : (theme.muted || 'gray'),
          paddingX: 1
        },
        React.createElement(
          Text,
          { bold: activeTab === 1, color: activeTab === 1 ? (theme.accent || 'yellow') : (theme.muted || 'gray') },
          `[2] Saved Scans (${scans.length})`
        )
      ),
      React.createElement(
        Box,
        {
          borderStyle: activeTab === 2 ? 'bold' : 'single',
          borderColor: activeTab === 2 ? (theme.accent || 'yellow') : (theme.muted || 'gray'),
          paddingX: 1
        },
        React.createElement(
          Text,
          { bold: activeTab === 2, color: activeTab === 2 ? (theme.accent || 'yellow') : (theme.muted || 'gray') },
          `[3] BMC Inspector & Hashes (${activeScan?.bmcs?.length || 0})`
        )
      )
    ),

    // Feedback Alert
    feedback
      ? React.createElement(
          Box,
          {
            borderStyle: 'single',
            borderColor: feedback.type === 'error' ? (theme.error || 'red') : (theme.success || 'green'),
            paddingX: 1,
            marginBottom: 1
          },
          React.createElement(
            Text,
            { color: feedback.type === 'error' ? (theme.error || 'red') : (theme.success || 'green') },
            feedback.message
          )
        )
      : null,

    // Custom Target Modal
    isInputMode
      ? React.createElement(
          Box,
          {
            borderStyle: 'double',
            borderColor: theme.warning || 'yellow',
            flexDirection: 'column',
            padding: 1,
            marginBottom: 1
          },
          React.createElement(
            Text,
            { bold: true, color: theme.warning || 'yellow' },
            '🎯 Enter Custom Target (IPv4, CIDR, or IPv6 Multicast Group):'
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(Text, { color: theme.accent || 'yellow' }, '> '),
            React.createElement(Text, { bold: true, color: 'white' }, customInputText),
            React.createElement(Text, { color: theme.muted || 'gray' }, '_')
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            React.createElement(
              Text,
              { color: theme.muted || 'gray' },
              'Examples: 10.0.100.0/24 | ff02::1%eth0 | 192.168.1.50 | (Press Enter to submit, Esc to cancel)'
            )
          )
        )
      : null,

    // TAB 0: NEW SCAN
    activeTab === 0
      ? React.createElement(
          Box,
          { flexDirection: 'column', gap: 1 },
          React.createElement(
            Box,
            { gap: 1 },
            // Targets List
            React.createElement(
              Box,
              {
                flexDirection: 'column',
                borderStyle: 'single',
                borderColor: theme.border || 'cyan',
                width: '50%',
                padding: 1
              },
              React.createElement(
                Box,
                { justifyContent: 'space-between', marginBottom: 1 },
                React.createElement(Text, { bold: true, color: theme.primary || 'cyan' }, '🎯 Target Network / Host'),
                React.createElement(Text, { color: theme.muted || 'gray' }, '[i] Custom Input')
              ),
              targets.map((t, idx) => {
                const isSel = idx === selectedTargetIdx;
                return React.createElement(
                  Box,
                  {
                    key: idx,
                    backgroundColor: isSel ? (theme.selectedBg || 'gray') : undefined,
                    paddingX: 1
                  },
                  React.createElement(
                    Text,
                    {
                      bold: isSel,
                      color: isSel ? (theme.selectedText || 'yellow') : (theme.text || 'white')
                    },
                    (isSel ? '▶ ' : '  ') + t.label
                  )
                );
              })
            ),
            // Profiles List
            React.createElement(
              Box,
              {
                flexDirection: 'column',
                borderStyle: 'single',
                borderColor: theme.border || 'cyan',
                width: '50%',
                padding: 1
              },
              React.createElement(Text, { bold: true, color: theme.primary || 'cyan', marginBottom: 1 }, '⚡ Scan Profile'),
              OOB_SCAN_PROFILES.map((p, idx) => {
                const isSel = idx === selectedProfileIdx;
                return React.createElement(
                  Box,
                  {
                    key: p.id,
                    flexDirection: 'column',
                    marginBottom: 1,
                    backgroundColor: isSel ? (theme.selectedBg || 'gray') : undefined,
                    paddingX: 1
                  },
                  React.createElement(
                    Text,
                    {
                      bold: isSel,
                      color: isSel ? (theme.selectedText || 'yellow') : (theme.text || 'white')
                    },
                    (isSel ? '▶ ' : '  ') + p.name
                  ),
                  React.createElement(Text, { color: theme.muted || 'gray', marginLeft: 2 }, p.description)
                );
              })
            )
          ),
          // Action Prompt
          React.createElement(
            Box,
            {
              borderStyle: 'round',
              borderColor: theme.accent || 'yellow',
              padding: 1,
              justifyContent: 'space-between',
              alignItems: 'center'
            },
            React.createElement(
              Box,
              { flexDirection: 'column' },
              React.createElement(
                Text,
                { bold: true, color: theme.text || 'white' },
                'Ready to scan: ',
                React.createElement(Text, { color: theme.accent || 'yellow' }, currentTarget)
              ),
              React.createElement(
                Text,
                { color: theme.muted || 'gray' },
                `Profile: ${currentProfile.name} (${currentProfile.args.join(' ')})`
              )
            ),
            React.createElement(
              Box,
              null,
              React.createElement(Text, { bold: true, color: theme.success || 'green' }, '[Press Enter to Start Scan]')
            )
          ),
          // Live Progress Logs
          (isScanning || scanLogs.length > 0)
            ? React.createElement(
                Box,
                {
                  flexDirection: 'column',
                  borderStyle: 'single',
                  borderColor: theme.border || 'cyan',
                  padding: 1,
                  height: 10
                },
                React.createElement(Text, { bold: true, color: theme.primary || 'cyan', marginBottom: 1 }, '📜 Real-time Scanner Output:'),
                scanLogs.slice(-8).map((log, i) => React.createElement(Text, { key: i, color: theme.text || 'white', wrap: 'truncate' }, log))
              )
            : null
        )
      : null,

    // TAB 1: SAVED SCANS ARCHIVE
    activeTab === 1
      ? React.createElement(
          Box,
          { flexDirection: 'column', gap: 1 },
          scans.length === 0
            ? React.createElement(
                Box,
                { borderStyle: 'single', borderColor: theme.border || 'cyan', padding: 2, justifyContent: 'center' },
                React.createElement(Text, { color: theme.muted || 'gray' }, `No saved OOB scans found in ${oobscansDir}. Press [1] to run a new scan.`)
              )
            : React.createElement(
                Box,
                { gap: 1 },
                // Scan List
                React.createElement(
                  Box,
                  {
                    flexDirection: 'column',
                    borderStyle: 'single',
                    borderColor: theme.border || 'cyan',
                    width: '55%',
                    padding: 1
                  },
                  React.createElement(Text, { bold: true, color: theme.primary || 'cyan', marginBottom: 1 }, `📁 Historical OOB Scans (${scans.length})`),
                  scans.map((s, idx) => {
                    const isSel = idx === scanCursor;
                    return React.createElement(
                      Box,
                      {
                        key: s.id,
                        flexDirection: 'column',
                        marginBottom: 1,
                        backgroundColor: isSel ? (theme.selectedBg || 'gray') : undefined,
                        paddingX: 1
                      },
                      React.createElement(
                        Box,
                        { justifyContent: 'space-between' },
                        React.createElement(
                          Text,
                          { bold: isSel, color: isSel ? (theme.selectedText || 'yellow') : (theme.text || 'white') },
                          (isSel ? '▶ ' : '  ') + s.target
                        ),
                        React.createElement(Text, { color: theme.muted || 'gray' }, new Date(s.mtime).toLocaleDateString())
                      ),
                      React.createElement(
                        Box,
                        { marginLeft: 2, gap: 2 },
                        React.createElement(Text, { color: theme.primary || 'cyan' }, `${s.totalBmcs} BMCs`),
                        s.totalRakpHashes > 0 ? React.createElement(Text, { color: 'yellow' }, `🔑 ${s.totalRakpHashes} RAKP Hashes`) : null,
                        s.totalCreds > 0 ? React.createElement(Text, { color: 'green' }, `🔓 ${s.totalCreds} Creds`) : null,
                        s.totalCves > 0 ? React.createElement(Text, { color: 'red' }, `🛡️ ${s.totalCves} CVEs`) : null
                      )
                    );
                  })
                ),
                // Selected Scan Preview
                React.createElement(
                  Box,
                  {
                    flexDirection: 'column',
                    borderStyle: 'single',
                    borderColor: theme.border || 'cyan',
                    width: '45%',
                    padding: 1
                  },
                  React.createElement(Text, { bold: true, color: theme.primary || 'cyan', marginBottom: 1 }, '🔍 Scan Summary'),
                  activeScan
                    ? React.createElement(
                        Box,
                        { flexDirection: 'column', gap: 1 },
                        React.createElement(
                          Text,
                          { bold: true, color: theme.text || 'white' },
                          'Target: ',
                          React.createElement(Text, { color: theme.accent || 'yellow' }, activeScan.target)
                        ),
                        React.createElement(Text, { color: theme.muted || 'gray' }, `File: ${activeScan.filename}`),
                        React.createElement(Text, { color: theme.muted || 'gray' }, `Timestamp: ${new Date(activeScan.mtime).toLocaleString()}`),
                        React.createElement(
                          Box,
                          { borderStyle: 'single', borderColor: theme.muted || 'gray', padding: 1, marginY: 1 },
                          React.createElement(Text, { color: theme.text || 'white' }, String(activeScan.summary))
                        ),
                        React.createElement(Text, { bold: true, color: theme.text || 'white' }, `Discovered BMCs (${activeScan.bmcs?.length || 0}):`),
                        (activeScan.bmcs || []).slice(0, 5).map((b, i) =>
                          React.createElement(
                            Text,
                            { key: i, color: theme.text || 'white' },
                            '• ',
                            React.createElement(Text, { bold: true, color: theme.primary || 'cyan' }, b.host),
                            ` — ${b.vendor} ${b.product}`
                          )
                        ),
                        React.createElement(
                          Box,
                          { marginTop: 1, gap: 2 },
                          React.createElement(Text, { color: theme.muted || 'gray' }, '[Enter] Inspect BMCs'),
                          React.createElement(Text, { color: theme.muted || 'gray' }, '[p] Pager'),
                          React.createElement(Text, { color: theme.muted || 'gray' }, '[e] Editor'),
                          React.createElement(Text, { color: theme.muted || 'gray' }, '[d] Delete')
                        )
                      )
                    : React.createElement(Text, { color: theme.muted || 'gray' }, 'No scan selected.')
                )
              )
        )
      : null,

    // TAB 2: BMC INSPECTOR & RAKP HASH VAULT
    activeTab === 2
      ? React.createElement(
          Box,
          { flexDirection: 'column', gap: 1 },
          !activeScan || !activeScan.bmcs || activeScan.bmcs.length === 0
            ? React.createElement(
                Box,
                { borderStyle: 'single', borderColor: theme.border || 'cyan', padding: 2, justifyContent: 'center' },
                React.createElement(Text, { color: theme.muted || 'gray' }, 'No BMCs discovered in this scan. Press [1] to launch a new sweep or [2] to select a scan.')
              )
            : React.createElement(
                Box,
                { gap: 1 },
                // BMC Hosts List
                React.createElement(
                  Box,
                  {
                    flexDirection: 'column',
                    borderStyle: 'single',
                    borderColor: theme.border || 'cyan',
                    width: '40%',
                    padding: 1
                  },
                  React.createElement(Text, { bold: true, color: theme.primary || 'cyan', marginBottom: 1 }, `🖥️ BMC Hardware Inventory (${activeScan.bmcs.length})`),
                  activeScan.bmcs.map((b, idx) => {
                    const isSel = idx === bmcsCursor;
                    return React.createElement(
                      Box,
                      {
                        key: idx,
                        flexDirection: 'column',
                        marginBottom: 1,
                        backgroundColor: isSel ? (theme.selectedBg || 'gray') : undefined,
                        paddingX: 1
                      },
                      React.createElement(
                        Text,
                        { bold: isSel, color: isSel ? (theme.selectedText || 'yellow') : (theme.text || 'white') },
                        (isSel ? '▶ ' : '  ') + b.host
                      ),
                      React.createElement(Text, { color: theme.muted || 'gray', marginLeft: 2 }, `${b.vendor} ${b.product}`),
                      React.createElement(
                        Box,
                        { marginLeft: 2, gap: 1 },
                        b.rakp?.length > 0 ? React.createElement(Text, { color: 'yellow' }, '🔑 RAKP') : null,
                        b.creds?.length > 0 ? React.createElement(Text, { color: 'green' }, '🔓 Creds') : null,
                        b.cves?.length > 0 ? React.createElement(Text, { color: 'red' }, `🛡️ ${b.cves.length} CVE`) : null
                      )
                    );
                  })
                ),
                // BMC Detail Inspection Card
                React.createElement(
                  Box,
                  {
                    flexDirection: 'column',
                    borderStyle: 'single',
                    borderColor: theme.border || 'cyan',
                    width: '60%',
                    padding: 1
                  },
                  activeBmc
                    ? React.createElement(
                        Box,
                        { flexDirection: 'column', gap: 1 },
                        React.createElement(
                          Box,
                          { justifyContent: 'space-between' },
                          React.createElement(Text, { bold: true, color: theme.primary || 'cyan' }, `Hardware: ${activeBmc.vendor} ${activeBmc.product}`),
                          React.createElement(Text, { color: theme.accent || 'yellow' }, activeBmc.host)
                        ),
                        activeBmc.firmware ? React.createElement(Text, { color: theme.muted || 'gray' }, `Firmware: ${activeBmc.firmware}`) : null,
                        activeBmc.guid ? React.createElement(Text, { color: theme.muted || 'gray' }, `System GUID: ${activeBmc.guid}`) : null,
                        activeBmc.serial ? React.createElement(Text, { color: theme.muted || 'gray' }, `Serial / Service Tag: ${activeBmc.serial}`) : null,

                        // Protocols Badge Grid
                        React.createElement(
                          Box,
                          { gap: 1, marginY: 1 },
                          React.createElement(Text, { bold: true, color: theme.text || 'white' }, 'Protocols:'),
                          (activeBmc.protocols || []).map((p, i) => React.createElement(Text, { key: i, color: theme.info || 'blue' }, `[${p.toUpperCase()}]`))
                        ),

                        // Security Findings & CVEs
                        (activeBmc.findings?.length > 0 || activeBmc.cves?.length > 0)
                          ? React.createElement(
                              Box,
                              { flexDirection: 'column', borderStyle: 'single', borderColor: 'red', padding: 1 },
                              React.createElement(Text, { bold: true, color: 'red' }, '🛡️ Security Exposures & Vulnerabilities:'),
                              activeBmc.cves?.map((cve, i) => React.createElement(Text, { key: i, color: 'red' }, `• Critical CVE: ${cve}`)),
                              activeBmc.findings?.map((f, i) => React.createElement(Text, { key: i, color: 'yellow' }, `• ${f.title || f}`))
                            )
                          : null,

                        // Default Credentials
                        activeBmc.creds?.length > 0
                          ? React.createElement(
                              Box,
                              { flexDirection: 'column', borderStyle: 'single', borderColor: 'green', padding: 1 },
                              React.createElement(Text, { bold: true, color: 'green' }, '🔓 Default / Weak Credentials Identified:'),
                              activeBmc.creds.map((c, i) => React.createElement(Text, { key: i, color: 'green' }, `• ${c.user}:${c.pass} (${c.protocol})`))
                            )
                          : null,

                        // RAKP Hash Vault
                        activeBmc.rakp?.length > 0
                          ? React.createElement(
                              Box,
                              { flexDirection: 'column', borderStyle: 'single', borderColor: 'yellow', padding: 1 },
                              React.createElement(Text, { bold: true, color: 'yellow' }, '🔑 Captured RAKP-2 Hashes (Hashcat -m 7300):'),
                              activeBmc.rakp.map((r, i) =>
                                React.createElement(
                                  Box,
                                  { key: i, flexDirection: 'column', marginY: 1 },
                                  React.createElement(
                                    Text,
                                    { color: theme.text || 'white' },
                                    'User: ',
                                    React.createElement(Text, { bold: true, color: theme.accent || 'yellow' }, r.user),
                                    ` (${r.cipher})`
                                  ),
                                  r.hashcat
                                    ? React.createElement(Text, { color: theme.muted || 'gray', wrap: 'truncate' }, `Hash: ${r.hashcat.slice(0, 60)}...`)
                                    : null
                                )
                              ),
                              React.createElement(Text, { color: theme.muted || 'gray' }, 'Press [c] or [y] to copy Hashcat crack command')
                            )
                          : null
                      )
                    : React.createElement(Text, { color: theme.muted || 'gray' }, 'No BMC selected.')
                )
              )
        )
      : null,

    // Footer Hotkeys Legend
    React.createElement(
      Box,
      {
        marginTop: 1,
        justifyContent: 'space-between',
        borderStyle: 'single',
        borderColor: theme.muted || 'gray',
        paddingX: 1
      },
      React.createElement(
        Box,
        { gap: 2 },
        React.createElement(Text, { color: theme.accent || 'yellow' }, '[Tab] Switch Tab'),
        React.createElement(Text, { color: theme.accent || 'yellow' }, '[Enter] Scan/Select'),
        React.createElement(Text, { color: theme.accent || 'yellow' }, '[i] Input Target'),
        React.createElement(Text, { color: theme.accent || 'yellow' }, '[c/y] Copy Hash'),
        React.createElement(Text, { color: theme.accent || 'yellow' }, '[h] Export Hashes'),
        React.createElement(Text, { color: theme.accent || 'yellow' }, '[p] Pager'),
        React.createElement(Text, { color: theme.accent || 'yellow' }, '[d] Delete')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.muted || 'gray' }, '[q/Esc] Operations Hub')
      )
    )
  );
});
