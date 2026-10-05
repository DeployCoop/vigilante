import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { PulseIndicator } from './PulseIndicator.js';
import { listHostDossiers, getHostDossier, buildHostDossier } from '../engine/dossier.js';
import { listPcapRecordings, replayPcap } from '../engine/traffic.js';
import { listBloodhoundIngests } from '../engine/bloodhound.js';
import { generateMitreCoverageMatrix } from '../engine/mitre.js';
import { useClipboard } from './ClipboardManager.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

export const VulnView = memo(function VulnView({
  domain = 'vigilante.local',
  ip = '127.0.0.1',
  onNavigate = null
}) {
  const theme = useTheme();
  const [activeTab, setActiveTab] = useState(0); // 0: Dossiers, 1: Vulnerabilities, 2: Traffic & PCAP, 3: Identity & Paths
  const [dossiers, setDossiers] = useState([]);
  const [dossierCursor, setDossierCursor] = useState(0);
  const [selectedDossier, setSelectedDossier] = useState(null);
  const [trafficPcaps, setTrafficPcaps] = useState([]);
  const [bhIngests, setBhIngests] = useState([]);
  const [mitreSummary, setMitreSummary] = useState(null);
  const [feedback, setFeedback] = useState(null);
  const [isLoading, setIsLoading] = useState(true);

  const { registerPanes } = useClipboard();

  const loadData = useCallback(async () => {
    setIsLoading(true);
    try {
      const hostList = await listHostDossiers();
      setDossiers(hostList);
      if (hostList.length > 0) {
        const full = await getHostDossier(hostList[0].target);
        setSelectedDossier(full);
      } else {
        // Build one for local IP if empty
        const initial = await buildHostDossier(ip);
        setDossiers([{
          target: ip,
          riskScore: initial.riskScore,
          riskTier: initial.riskTier,
          riskColor: initial.riskColor,
          openPortsCount: initial.network.openPorts.length,
          cvesCount: initial.vulnerabilities.cves.length,
          isBmc: initial.outOfBand.detected,
          updatedAt: initial.updatedAt
        }]);
        setSelectedDossier(initial);
      }

      const pcaps = await listPcapRecordings();
      setTrafficPcaps(pcaps);

      const ingests = await listBloodhoundIngests();
      setBhIngests(ingests);

      const mitre = generateMitreCoverageMatrix();
      setMitreSummary(mitre);
    } catch (err) {
      logger.error('VULN_VIEW:LOAD', `Failed to load vulnerability data: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [ip]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  // Handle selected dossier switch
  useEffect(() => {
    if (dossiers[dossierCursor]) {
      getHostDossier(dossiers[dossierCursor].target).then(setSelectedDossier);
    }
  }, [dossierCursor, dossiers]);

  useInput((input, key) => {
    // Escape or q to go back
    if (key.escape || input === 'q') {
      if (onNavigate) onNavigate('HUB');
      return;
    }

    // Tab switching
    if (key.tab || input === '\t') {
      setActiveTab(t => (t + 1) % 4);
      return;
    }
    if (input === '1') { setActiveTab(0); return; }
    if (input === '2') { setActiveTab(1); return; }
    if (input === '3') { setActiveTab(2); return; }
    if (input === '4') { setActiveTab(3); return; }

    // Navigation
    if (key.upArrow || input === 'k') {
      if (activeTab === 0) {
        setDossierCursor(c => (c > 0 ? c - 1 : dossiers.length - 1));
      }
      return;
    }
    if (key.downArrow || input === 'j') {
      if (activeTab === 0) {
        setDossierCursor(c => (c < dossiers.length - 1 ? c + 1 : 0));
      }
      return;
    }

    // Refresh dossier [r]
    if (input === 'r' || input === 'R') {
      setFeedback({ type: 'info', message: 'Re-compiling host dossier...' });
      if (selectedDossier) {
        buildHostDossier(selectedDossier.target).then(refreshed => {
          setSelectedDossier(refreshed);
          setFeedback({ type: 'success', message: `Refreshed dossier for ${refreshed.target}` });
        });
      }
      return;
    }

    // Copy details [c]
    if (input === 'c' || input === 'C') {
      if (selectedDossier) {
        copyToClipboard(JSON.stringify(selectedDossier, null, 2));
        setFeedback({ type: 'success', message: `Copied dossier for ${selectedDossier.target} to clipboard!` });
      }
      return;
    }
  });

  const renderTabs = () => {
    const tabs = [
      '1. 🧠 Host Dossiers',
      '2. 🛡️ Vulnerabilities',
      '3. 🚨 Live Traffic & PCAP',
      '4. 🕸️ Identity & Attack Paths'
    ];
    return React.createElement(
      Box,
      { flexDirection: 'row', marginBottom: 1, borderStyle: 'single', borderColor: theme.border || 'gray', paddingX: 1 },
      tabs.map((tab, idx) =>
        React.createElement(
          Box,
          { key: idx, marginRight: 2 },
          React.createElement(
            Text,
            {
              bold: activeTab === idx,
              color: activeTab === idx ? theme.highlight || 'cyan' : theme.dim || 'gray',
              inverse: activeTab === idx
            },
            ` ${tab} `
          )
        )
      )
    );
  };

  const renderDossierTab = () => {
    return React.createElement(
      Box,
      { flexDirection: 'row', width: '100%' },
      // Left Column: Host List
      React.createElement(
        Box,
        { flexDirection: 'column', width: '35%', borderStyle: 'round', borderColor: theme.border || 'gray', padding: 1, marginRight: 1 },
        React.createElement(Text, { bold: true, color: theme.highlight || 'cyan', underline: true }, `Target Hosts (${dossiers.length})`),
        dossiers.length === 0
          ? React.createElement(Text, { color: theme.dim || 'gray' }, 'No host dossiers recorded yet.')
          : dossiers.map((d, idx) => {
              const isSelected = idx === dossierCursor;
              return React.createElement(
                Box,
                { key: idx, flexDirection: 'row', justifyContent: 'space-between' },
                React.createElement(
                  Text,
                  { color: isSelected ? 'cyan' : 'white', bold: isSelected },
                  `${isSelected ? '▶ ' : '  '}${d.target}`
                ),
                React.createElement(
                  Text,
                  { color: d.riskColor || 'green', bold: true },
                  `${d.riskScore}/100 [${d.riskTier}]`
                )
              );
            })
      ),

      // Right Column: Detailed Dossier
      React.createElement(
        Box,
        { flexDirection: 'column', width: '65%', borderStyle: 'round', borderColor: theme.border || 'gray', padding: 1 },
        selectedDossier
          ? React.createElement(
              Box,
              { flexDirection: 'column' },
              React.createElement(
                Box,
                { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 1 },
                React.createElement(Text, { bold: true, color: 'white' }, 'HOST: ', React.createElement(Text, { color: 'cyan' }, selectedDossier.target)),
                React.createElement(Text, { bold: true, color: selectedDossier.riskColor || 'green' }, `COMPOSITE RISK: ${selectedDossier.riskScore}/100 [${selectedDossier.riskTier}]`)
              ),
              React.createElement(Text, { bold: true, color: 'yellow' }, 'Network & Services:'),
              React.createElement(Text, { color: 'gray' }, `Open Ports: ${selectedDossier.network?.openPorts?.join(', ') || 'None detected'}`),
              React.createElement(Text, { color: 'gray' }, `OS Guessed: ${selectedDossier.network?.osGuessed || 'Unknown'}`),

              React.createElement(
                Box,
                { marginTop: 1, flexDirection: 'column' },
                React.createElement(Text, { bold: true, color: 'yellow' }, 'Top Vulnerabilities & Exposures:'),
                selectedDossier.vulnerabilities?.cves?.length === 0
                  ? React.createElement(Text, { color: 'green' }, '✔ No active CVEs flagged.')
                  : selectedDossier.vulnerabilities.cves.slice(0, 5).map((cve, i) =>
                      React.createElement(
                        Text,
                        { key: i, color: cve.severity === 'critical' ? 'red' : 'yellow' },
                        `• [${String(cve.severity || 'high').toUpperCase()}] ${cve.id || cve.cveId}: ${cve.name || cve.package || 'Vulnerability'}`
                      )
                    )
              ),

              React.createElement(
                Box,
                { marginTop: 1, flexDirection: 'column' },
                React.createElement(Text, { bold: true, color: 'yellow' }, 'Remediations & Hardening Actions:'),
                selectedDossier.remediations?.length === 0
                  ? React.createElement(Text, { color: 'green' }, '✔ Host configuration optimal.')
                  : selectedDossier.remediations.slice(0, 4).map((rem, i) =>
                      React.createElement(Text, { key: i, color: 'cyan' }, `→ ${rem}`)
                    )
              ),

              React.createElement(
                Box,
                { marginTop: 1, flexDirection: 'row' },
                React.createElement(Text, { color: 'gray' }, 'MITRE ATT&CK: '),
                React.createElement(Text, { color: 'magenta' }, selectedDossier.mitreTechniques?.join(', ') || 'None mapped')
              )
            )
          : React.createElement(Text, { color: theme.dim || 'gray' }, 'Select a host to view intelligence dossier.')
      )
    );
  };

  const renderVulnTab = () => {
    const cves = selectedDossier?.vulnerabilities?.cves || [];
    const secrets = selectedDossier?.vulnerabilities?.secrets || [];
    const zapAlerts = selectedDossier?.vulnerabilities?.zapAlerts || [];

    return React.createElement(
      Box,
      { flexDirection: 'column', borderStyle: 'round', borderColor: theme.border || 'gray', padding: 1 },
      React.createElement(
        Text,
        { bold: true, color: theme.highlight || 'cyan', underline: true, marginBottom: 1 },
        `🛡️ Discovered Flaws & Vulnerabilities (${cves.length + secrets.length + zapAlerts.length})`
      ),
      cves.length === 0 && secrets.length === 0 && zapAlerts.length === 0
        ? React.createElement(Text, { color: 'green' }, '✔ Clean: No security vulnerabilities discovered for target host.')
        : React.createElement(
            Box,
            { flexDirection: 'column' },
            cves.map((c, i) =>
              React.createElement(
                Box,
                { key: i, flexDirection: 'row' },
                React.createElement(Text, { color: c.severity === 'critical' ? 'red' : 'yellow', bold: true }, `[${String(c.severity).toUpperCase()}]`),
                React.createElement(Text, { color: 'white' }, ` ${c.cveId || c.id} `),
                React.createElement(Text, { color: 'gray' }, `(${c.name || c.package || 'Flaw'})`)
              )
            ),
            secrets.map((s, i) =>
              React.createElement(
                Box,
                { key: `sec-${i}`, flexDirection: 'row' },
                React.createElement(Text, { color: 'red', bold: true }, '[SECRET EXPOSURE]'),
                React.createElement(Text, { color: 'white' }, ` ${s.title || s.category} `),
                React.createElement(Text, { color: 'gray' }, `in ${s.file || 'manifest'}`)
              )
            ),
            zapAlerts.map((z, i) =>
              React.createElement(
                Box,
                { key: `zap-${i}`, flexDirection: 'row' },
                React.createElement(Text, { color: z.risk === 'High' ? 'red' : 'yellow', bold: true }, `[DAST ${z.risk}]`),
                React.createElement(Text, { color: 'white' }, ` ${z.name} `),
                React.createElement(Text, { color: 'gray' }, `(${z.url || 'endpoint'})`)
              )
            )
          )
    );
  };

  const renderTrafficTab = () => {
    return React.createElement(
      Box,
      { flexDirection: 'column', borderStyle: 'round', borderColor: theme.border || 'gray', padding: 1 },
      React.createElement(
        Text,
        { bold: true, color: theme.highlight || 'cyan', underline: true, marginBottom: 1 },
        '🚨 Mirrored Traffic Capture & PCAP Dropzone'
      ),
      React.createElement(
        Text,
        { color: 'gray', marginBottom: 1 },
        'Suricata and Zeek monitor mirrored cluster traffic or analyze PCAP files dropped into the spool directory.'
      ),
      React.createElement(Text, { bold: true, color: 'yellow' }, `Staged PCAP Recordings (${trafficPcaps.length}):`),
      trafficPcaps.length === 0
        ? React.createElement(Text, { color: 'gray' }, 'No PCAP files currently in local dropzone. Use replayPcap() to drop files.')
        : trafficPcaps.map((p, i) =>
            React.createElement(
              Text,
              { key: i, color: 'cyan' },
              `• ${p.name} (${(p.sizeBytes / 1024).toFixed(1)} KB)`
            )
          )
    );
  };

  const renderIdentityTab = () => {
    return React.createElement(
      Box,
      { flexDirection: 'column', borderStyle: 'round', borderColor: theme.border || 'gray', padding: 1 },
      React.createElement(
        Text,
        { bold: true, color: theme.highlight || 'cyan', underline: true, marginBottom: 1 },
        '🕸️ BloodHound Identity Graph & Attack Paths'
      ),
      React.createElement(
        Text,
        { color: 'gray', marginBottom: 1 },
        'Correlates Active Directory security principles, AS-REP roasting, unconstrained delegation, and Flamingo captured credentials.'
      ),
      React.createElement(Text, { bold: true, color: 'yellow' }, `Ingested Identity Graph Records (${bhIngests.length}):`),
      bhIngests.length === 0
        ? React.createElement(Text, { color: 'gray' }, 'No BloodHound datasets ingested yet. Ingest SharpHound output to view attack paths.')
        : bhIngests.map((bh, i) =>
            React.createElement(
              Box,
              { key: i, flexDirection: 'column', marginBottom: 1 },
              React.createElement(Text, { color: 'cyan' }, `• Ingest ID: ${bh.id} (${bh.timestamp})`),
              React.createElement(
                Text,
                { color: 'gray' },
                `Users: ${bh.stats?.users || 0} | Computers: ${bh.stats?.computers || 0} | Attack Alerts: ${bh.stats?.attackPathAlerts || 0}`
              ),
              bh.stats?.tier0Compromises > 0
                ? React.createElement(
                    Text,
                    { color: 'red', bold: true },
                    `🚨 CRITICAL: ${bh.stats.tier0Compromises} Tier-0 / Domain Admin credential compromises detected!`
                  )
                : null
            )
          )
    );
  };

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%', padding: 1 },
    // Header
    React.createElement(
      Box,
      { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        { flexDirection: 'row' },
        React.createElement(Text, { bold: true, color: theme.highlight || 'cyan' }, '⚡ VIGILANTE VULNERABILITY & THREAT CENTER'),
        isLoading ? React.createElement(PulseIndicator, { label: ' Loading...' }) : null
      ),
      React.createElement(
        Text,
        { color: theme.dim || 'gray' },
        '[Tab/1-4] Switch Tabs | [r] Refresh | [c] Copy | [Esc/q] Hub'
      )
    ),

    // Tabs
    renderTabs(),

    // Feedback Alert
    feedback
      ? React.createElement(
          Box,
          { marginBottom: 1 },
          React.createElement(Text, { color: feedback.type === 'error' ? 'red' : 'green' }, feedback.message)
        )
      : null,

    // Tab Content
    activeTab === 0 ? renderDossierTab() : null,
    activeTab === 1 ? renderVulnTab() : null,
    activeTab === 2 ? renderTrafficTab() : null,
    activeTab === 3 ? renderIdentityTab() : null
  );
});
