import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { execa } from 'execa';
import { PulseIndicator } from './PulseIndicator.js';
import { useTheme } from './theme.js';
import { useClipboard } from './ClipboardManager.js';
import { copyToClipboard } from '../utils/clipboard.js';
import { openInSystemPager } from '../engine/pods.js';
import {
  CHALLENGE_CATEGORIES,
  CHALLENGE_TEMPLATES,
  generateDynamicFlag,
  spinUpChallenge,
  listActiveChallenges,
  deleteChallenge,
  toggleChallengeStatus,
  testChallengeConnection,
  getChallengeLogs
} from '../engine/kctf.js';
import { logger } from '../utils/logger.js';

export const KCTFView = memo(function KCTFView({
  domain = 'vigilante.local',
  clusterName = 'vigilante-dev',
  namespace = 'kctf',
  onNavigate = null
}) {
  const theme = useTheme();
  const { registerPanes } = useClipboard();

  // Navigation and active tabs: 'active' | 'library' | 'details' | 'logs' | 'spinup_custom'
  const [activeTab, setActiveTab] = useState('active');
  const [challenges, setChallenges] = useState([]);
  const [selectedChalIdx, setSelectedChalIdx] = useState(0);

  // Library tab state
  const [selectedCategoryIdx, setSelectedCategoryIdx] = useState(0); // 0 = All
  const [selectedTplIdx, setSelectedTplIdx] = useState(0);

  // Status & Operation state
  const [isLoading, setIsLoading] = useState(true);
  const [feedback, setFeedback] = useState(null);
  const [testResult, setTestResult] = useState(null);
  const [isTesting, setIsTesting] = useState(false);
  const [logContent, setLogContent] = useState(null);

  // Custom challenge form state
  const [customForm, setCustomForm] = useState({
    name: 'custom-chal',
    category: 'pwn',
    port: '31340',
    flag: '',
    pow: '0',
    activeField: 0
  });

  const webPortalUrl = `https://kctf.${domain}`;
  const ctfHostUrl = `https://ctf.${domain}`;

  // Filter templates by category
  const activeCategory = selectedCategoryIdx === 0
    ? null
    : CHALLENGE_CATEGORIES[selectedCategoryIdx - 1]?.id;

  const filteredTemplates = activeCategory
    ? CHALLENGE_TEMPLATES.filter(t => t.category === activeCategory)
    : CHALLENGE_TEMPLATES;

  // Refresh active challenges from cluster
  const refreshChallenges = useCallback(async () => {
    setIsLoading(true);
    try {
      const list = await listActiveChallenges({ namespace, clusterName, domain });
      setChallenges(list);
      if (selectedChalIdx >= list.length) {
        setSelectedChalIdx(Math.max(0, list.length - 1));
      }
    } catch (err) {
      logger.error('KCTF_VIEW:REFRESH', `Failed to list challenges: ${err.message}`);
    } finally {
      setIsLoading(false);
    }
  }, [namespace, clusterName, domain, selectedChalIdx]);

  useEffect(() => {
    refreshChallenges();
  }, [refreshChallenges]);

  // Register clipboard panes
  useEffect(() => {
    if (registerPanes) {
      registerPanes([
        {
          id: 'kctf-challenges',
          name: 'kCTF Active Challenges',
          getContent: () => JSON.stringify(challenges, null, 2)
        },
        {
          id: 'kctf-connection',
          name: 'Selected Challenge Connection',
          getContent: () => {
            const c = challenges[selectedChalIdx];
            return c ? c.connectionString : '';
          }
        }
      ]);
    }
  }, [challenges, selectedChalIdx, registerPanes]);

  // Action: Spin up challenge from template
  const handleSpinUpTemplate = async (template) => {
    if (!template) return;
    setFeedback(`🚀 Spinning up '${template.name}' (${template.category.toUpperCase()})...`);
    setIsLoading(true);

    const flag = generateDynamicFlag('kctf', template.id);
    const result = await spinUpChallenge({
      templateId: template.id,
      customName: template.id,
      customCategory: template.category,
      customPort: template.port,
      customFlag: flag,
      powDifficultySeconds: 0,
      namespace,
      clusterName
    });

    if (result.success) {
      setFeedback(`✔ Challenge '${result.name}' successfully deployed on port ${result.port}!`);
      await refreshChallenges();
      setActiveTab('active');
    } else {
      setFeedback(`✖ Failed to deploy challenge: ${result.error}`);
    }
    setIsLoading(false);
  };

  // Action: Test connectivity to selected challenge
  const handleTestConnection = async (chal) => {
    if (!chal) return;
    setIsTesting(true);
    setTestResult(null);
    setFeedback(`📡 Testing connection to ${chal.name} on port ${chal.port}...`);

    const res = await testChallengeConnection({
      host: '127.0.0.1',
      port: chal.port,
      timeoutMs: 2000,
      category: chal.category
    });

    setTestResult(res);
    setIsTesting(false);
    setFeedback(res.success
      ? `✔ [${chal.name}] ${res.message}`
      : `✖ [${chal.name}] ${res.message}`);
  };

  // Action: Inspect logs in system pager or inline
  const handleViewLogs = async (chal) => {
    if (!chal) return;
    setFeedback(`Fetching logs for ${chal.name}...`);
    const logs = await getChallengeLogs({ challengeName: chal.name, namespace, clusterName, lines: 60 });
    try {
      await openInSystemPager(logs, `kctf-${chal.name}.log`);
    } catch {
      setLogContent(logs);
      setActiveTab('logs');
    }
  };

  // Action: Delete selected challenge
  const handleDeleteChallenge = async (chal) => {
    if (!chal) return;
    setFeedback(`🗑️ Deleting challenge '${chal.name}'...`);
    setIsLoading(true);
    const res = await deleteChallenge({ challengeName: chal.name, namespace, clusterName });
    if (res.success) {
      setFeedback(`✔ Challenge '${chal.name}' deleted.`);
      await refreshChallenges();
    } else {
      setFeedback(`✖ Failed to delete: ${res.error}`);
    }
    setIsLoading(false);
  };

  // Action: Toggle challenge status
  const handleToggleChallenge = async (chal) => {
    if (!chal) return;
    const newStatus = !chal.deployed;
    setFeedback(`Updating challenge status to ${newStatus ? 'DEPLOYED' : 'PAUSED'}...`);
    const res = await toggleChallengeStatus({
      challengeName: chal.name,
      deployed: newStatus,
      namespace,
      clusterName
    });
    if (res.success) {
      setFeedback(`✔ Challenge '${chal.name}' is now ${newStatus ? 'Active' : 'Paused'}.`);
      await refreshChallenges();
    } else {
      setFeedback(`✖ Error updating status: ${res.error}`);
    }
  };

  // Action: Open web portal in default browser
  const handleOpenBrowser = async () => {
    const platform = process.platform;
    const cmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
    try {
      await execa(cmd, [webPortalUrl]);
      setFeedback(`🌐 Opened kCTF Web Portal in browser: ${webPortalUrl}`);
    } catch {
      setFeedback(`Web Portal URL: ${webPortalUrl}`);
    }
  };

  // Input Handling
  useInput((input, key) => {
    // Dismiss modals with Esc or q
    if (activeTab === 'details' || activeTab === 'logs') {
      if (key.escape || input === 'q' || input === 'Q') {
        setActiveTab('active');
        return;
      }
      return;
    }

    // Switch between Active and Library tabs with Tab key
    if (key.tab) {
      setActiveTab(curr => (curr === 'active' ? 'library' : 'active'));
      setFeedback(null);
      return;
    }

    // Global navigation
    if (input === 'q' || input === 'Q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
      return;
    }

    // Refresh
    if (input === 'r' || input === 'R') {
      refreshChallenges();
      setFeedback('Refreshed active challenge list.');
      return;
    }

    // Open Web Portal
    if (input === 'w' || input === 'W') {
      handleOpenBrowser();
      return;
    }

    // --- TAB: ACTIVE CHALLENGES ---
    if (activeTab === 'active') {
      if (key.upArrow || input === 'k') {
        setSelectedChalIdx(i => (i > 0 ? i - 1 : Math.max(0, challenges.length - 1)));
        setTestResult(null);
        return;
      }
      if (key.downArrow || input === 'j') {
        setSelectedChalIdx(i => (i < challenges.length - 1 ? i + 1 : 0));
        setTestResult(null);
        return;
      }

      const activeChal = challenges[selectedChalIdx];

      // Test connection
      if (input === 't' || input === 'T') {
        handleTestConnection(activeChal);
        return;
      }

      // View details
      if (key.return || input === 'v' || input === 'V') {
        if (activeChal) setActiveTab('details');
        return;
      }

      // View logs
      if (input === 'l' || input === 'L') {
        handleViewLogs(activeChal);
        return;
      }

      // Delete challenge
      if (input === 'd' || input === 'D') {
        handleDeleteChallenge(activeChal);
        return;
      }

      // Toggle deployed/paused
      if (input === 'x' || input === 'X') {
        handleToggleChallenge(activeChal);
        return;
      }

      // Copy connection string
      if (input === 'c' || input === 'y') {
        if (activeChal) {
          copyToClipboard(activeChal.connectionString);
          setFeedback(`📋 Copied: ${activeChal.connectionString}`);
        }
        return;
      }

      // Switch to library to spin up
      if (input === 's' || input === 'S' || input === 'n' || input === 'N') {
        setActiveTab('library');
        return;
      }
    }

    // --- TAB: CHALLENGE LIBRARY & SPIN-UP ---
    if (activeTab === 'library') {
      // Category switcher
      if (key.leftArrow || input === 'h') {
        setSelectedCategoryIdx(c => (c > 0 ? c - 1 : CHALLENGE_CATEGORIES.length));
        setSelectedTplIdx(0);
        return;
      }
      if (key.rightArrow || input === 'l') {
        setSelectedCategoryIdx(c => (c < CHALLENGE_CATEGORIES.length ? c + 1 : 0));
        setSelectedTplIdx(0);
        return;
      }

      // Template selection
      if (key.upArrow || input === 'k') {
        setSelectedTplIdx(i => (i > 0 ? i - 1 : Math.max(0, filteredTemplates.length - 1)));
        return;
      }
      if (key.downArrow || input === 'j') {
        setSelectedTplIdx(i => (i < filteredTemplates.length - 1 ? i + 1 : 0));
        return;
      }

      // Spin up selected template
      if (key.return || input === 's' || input === 'S') {
        const tpl = filteredTemplates[selectedTplIdx];
        handleSpinUpTemplate(tpl);
        return;
      }
    }
  });

  const activeChal = challenges[selectedChalIdx];
  const selectedTemplate = filteredTemplates[selectedTplIdx];

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%', paddingX: 1 },

    // 1. Header & Platform Status Banner
    React.createElement(
      Box,
      {
        flexDirection: 'row',
        justifyContent: 'space-between',
        borderStyle: 'round',
        borderColor: theme.primary || 'cyan',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        { flexDirection: 'column' },
        React.createElement(
          Text,
          { bold: true, color: theme.primary || 'cyan' },
          '🚩 kCTF CHALLENGE INFRASTRUCTURE & CYBER RANGE'
        ),
        React.createElement(
          Text,
          { color: theme.muted || 'gray', dimColor: true },
          `Google kCTF Isolated Sandboxes (nsjail, PoW & Ingress) · Cluster: ${clusterName} · Namespace: ${namespace}`
        )
      ),
      React.createElement(
        Box,
        { flexDirection: 'column', alignItems: 'flex-end' },
        React.createElement(
          Text,
          { bold: true, color: theme.success || 'green' },
          `● ${challenges.length} Active Challenges`
        ),
        React.createElement(
          Text,
          { color: theme.accent || 'blue' },
          `Portal: ${webPortalUrl}`
        )
      )
    ),

    // 2. Tabs Selector
    React.createElement(
      Box,
      { flexDirection: 'row', marginBottom: 1, gap: 2 },
      React.createElement(
        Box,
        {
          paddingX: 1,
          borderStyle: activeTab === 'active' ? 'bold' : 'single',
          borderColor: activeTab === 'active' ? (theme.primary || 'cyan') : (theme.muted || 'gray')
        },
        React.createElement(
          Text,
          { bold: activeTab === 'active', color: activeTab === 'active' ? (theme.primary || 'cyan') : (theme.muted || 'gray') },
          `[1] Active Challenges (${challenges.length})`
        )
      ),
      React.createElement(
        Box,
        {
          paddingX: 1,
          borderStyle: activeTab === 'library' ? 'bold' : 'single',
          borderColor: activeTab === 'library' ? (theme.accent || 'magenta') : (theme.muted || 'gray')
        },
        React.createElement(
          Text,
          { bold: activeTab === 'library', color: activeTab === 'library' ? (theme.accent || 'magenta') : (theme.muted || 'gray') },
          `[2] Challenge Library & Spin-Up (${CHALLENGE_TEMPLATES.length} Archetypes)`
        )
      ),
      React.createElement(
        Box,
        { marginLeft: 'auto', alignItems: 'center' },
        React.createElement(
          Text,
          { color: theme.warning || 'yellow' },
          'Press [Tab] to toggle view'
        )
      )
    ),

    // Feedback banner
    feedback
      ? React.createElement(
          Box,
          { marginBottom: 1, paddingX: 1, borderStyle: 'single', borderColor: theme.info || 'blue' },
          React.createElement(Text, { color: theme.info || 'blue', bold: true }, feedback)
        )
      : null,

    // --- TAB CONTENT 1: ACTIVE CHALLENGES ---
    activeTab === 'active'
      ? React.createElement(
          Box,
          { flexDirection: 'column', minHeight: 12 },
          challenges.length === 0
            ? React.createElement(
                Box,
                { padding: 2, borderStyle: 'round', borderColor: theme.muted || 'gray', flexDirection: 'column', alignItems: 'center' },
                React.createElement(Text, { bold: true, color: theme.warning || 'yellow' }, 'No challenges currently deployed in this namespace.'),
                React.createElement(Text, { color: theme.muted || 'gray', marginTop: 1 }, 'Press [Tab] or [s] to explore the Challenge Library and spin up your first challenge.')
              )
            : React.createElement(
                Box,
                { flexDirection: 'row', gap: 1 },
                // Left Column: Challenges Table
                React.createElement(
                  Box,
                  { flexDirection: 'column', flexGrow: 1, borderStyle: 'round', borderColor: theme.border || 'gray', paddingX: 1 },
                  React.createElement(
                    Box,
                    { flexDirection: 'row', borderBottom: true, borderColor: theme.muted || 'gray', paddingBottom: 0 },
                    React.createElement(Text, { bold: true, width: 4 }, '  #'),
                    React.createElement(Text, { bold: true, width: 14 }, 'Category'),
                    React.createElement(Text, { bold: true, width: 22 }, 'Challenge Name'),
                    React.createElement(Text, { bold: true, width: 10 }, 'Port'),
                    React.createElement(Text, { bold: true, width: 14 }, 'Status'),
                    React.createElement(Text, { bold: true, flexGrow: 1 }, 'Connection Command')
                  ),
                  challenges.map((c, idx) => {
                    const isSelected = idx === selectedChalIdx;
                    const catObj = CHALLENGE_CATEGORIES.find(cat => cat.id === c.category) || {};
                    const catBadge = `[${(c.category || 'misc').toUpperCase()}]`;
                    const statusColor = c.status === 'Ready'
                      ? (theme.success || 'green')
                      : c.status === 'Paused'
                      ? (theme.muted || 'gray')
                      : (theme.warning || 'yellow');

                    return React.createElement(
                      Box,
                      {
                        key: `${c.name}-${idx}`,
                        flexDirection: 'row',
                        paddingY: 0
                      },
                      React.createElement(
                        Text,
                        { color: isSelected ? (theme.primary || 'cyan') : (theme.muted || 'gray'), bold: isSelected, width: 4 },
                        isSelected ? '▶ ' : '  ',
                        `${idx + 1}`
                      ),
                      React.createElement(
                        Text,
                        { color: catObj.color || 'white', bold: isSelected, width: 14 },
                        catBadge
                      ),
                      React.createElement(
                        Text,
                        { color: isSelected ? (theme.primary || 'cyan') : 'white', bold: isSelected, width: 22 },
                        c.name
                      ),
                      React.createElement(
                        Text,
                        { color: theme.secondary || 'yellow', width: 10 },
                        `${c.port}/${c.protocol || 'TCP'}`
                      ),
                      React.createElement(
                        Text,
                        { color: statusColor, bold: isSelected, width: 14 },
                        c.status
                      ),
                      React.createElement(
                        Text,
                        { color: theme.accent || 'cyan', dimColor: !isSelected, flexGrow: 1 },
                        c.connectionString
                      )
                    );
                  })
                ),

                // Right Column: Selected Challenge Details Card
                activeChal
                  ? React.createElement(
                      Box,
                      {
                        flexDirection: 'column',
                        width: 44,
                        borderStyle: 'round',
                        borderColor: theme.accent || 'magenta',
                        paddingX: 1
                      },
                      React.createElement(
                        Text,
                        { bold: true, color: theme.accent || 'magenta' },
                        `🔍 ${activeChal.name.toUpperCase()}`
                      ),
                      React.createElement(
                        Box,
                        { marginTop: 1, flexDirection: 'column' },
                        React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Category: '), React.createElement(Text, { bold: true }, activeChal.category.toUpperCase())),
                        React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Port / Type: '), React.createElement(Text, { color: theme.secondary || 'yellow' }, `${activeChal.port} (${activeChal.protocol})`)),
                        React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Pod Name: '), React.createElement(Text, { dimColor: true }, activeChal.podName || 'Pending pod')),
                        React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Status: '), React.createElement(Text, { color: activeChal.status === 'Ready' ? 'green' : 'yellow', bold: true }, activeChal.status)),
                        React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Restarts: '), React.createElement(Text, null, `${activeChal.restarts}`)),
                        React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Flag: '), React.createElement(Text, { color: theme.success || 'green' }, activeChal.flag))
                      ),
                      React.createElement(
                        Box,
                        { marginTop: 1, flexDirection: 'column', borderTop: true, borderColor: theme.muted || 'gray', paddingTop: 1 },
                        React.createElement(Text, { bold: true, color: theme.info || 'blue' }, 'Quick Probe & Actions:'),
                        React.createElement(Text, { dimColor: true }, '• [t] Test TCP/HTTP Socket'),
                        React.createElement(Text, { dimColor: true }, '• [l] View Container Logs'),
                        React.createElement(Text, { dimColor: true }, '• [x] Pause / Resume Challenge'),
                        React.createElement(Text, { dimColor: true }, '• [c] Copy Connection Line'),
                        React.createElement(Text, { dimColor: true }, '• [d] Delete Challenge')
                      ),
                      testResult
                        ? React.createElement(
                            Box,
                            { marginTop: 1, padding: 1, borderStyle: 'single', borderColor: testResult.success ? 'green' : 'red' },
                            React.createElement(Text, { color: testResult.success ? 'green' : 'red', bold: true }, testResult.message)
                          )
                        : null
                    )
                  : null
              )
        )
      : null,

    // --- TAB CONTENT 2: CHALLENGE LIBRARY & SPIN-UP ---
    activeTab === 'library'
      ? React.createElement(
          Box,
          { flexDirection: 'column', minHeight: 12 },
          // Category Pills
          React.createElement(
            Box,
            { flexDirection: 'row', marginBottom: 1, gap: 1 },
            React.createElement(
              Box,
              {
                paddingX: 1,
                borderStyle: selectedCategoryIdx === 0 ? 'bold' : 'single',
                borderColor: selectedCategoryIdx === 0 ? (theme.primary || 'cyan') : (theme.muted || 'gray')
              },
              React.createElement(Text, { bold: selectedCategoryIdx === 0, color: selectedCategoryIdx === 0 ? (theme.primary || 'cyan') : 'white' }, 'All Categories')
            ),
            CHALLENGE_CATEGORIES.map((cat, idx) => {
              const isCatSelected = selectedCategoryIdx === idx + 1;
              return React.createElement(
                Box,
                {
                  key: cat.id,
                  paddingX: 1,
                  borderStyle: isCatSelected ? 'bold' : 'single',
                  borderColor: isCatSelected ? (cat.color || 'cyan') : (theme.muted || 'gray')
                },
                React.createElement(
                  Text,
                  { bold: isCatSelected, color: isCatSelected ? (cat.color || 'cyan') : 'white' },
                  `${cat.icon} ${cat.name}`
                )
              );
            })
          ),

          // Templates list + Template preview
          React.createElement(
            Box,
            { flexDirection: 'row', gap: 1 },
            // Left: Templates table
            React.createElement(
              Box,
              { flexDirection: 'column', flexGrow: 1, borderStyle: 'round', borderColor: theme.border || 'gray', paddingX: 1 },
              React.createElement(
                Box,
                { flexDirection: 'row', borderBottom: true, borderColor: theme.muted || 'gray' },
                React.createElement(Text, { bold: true, width: 4 }, '  #'),
                React.createElement(Text, { bold: true, width: 14 }, 'Category'),
                React.createElement(Text, { bold: true, width: 26 }, 'Template Name'),
                React.createElement(Text, { bold: true, width: 12 }, 'Difficulty'),
                React.createElement(Text, { bold: true, width: 10 }, 'Port'),
                React.createElement(Text, { bold: true, flexGrow: 1 }, 'Description')
              ),
              filteredTemplates.map((t, idx) => {
                const isSelected = idx === selectedTplIdx;
                const catObj = CHALLENGE_CATEGORIES.find(c => c.id === t.category) || {};
                const diffColor = t.difficulty === 'Easy'
                  ? (theme.success || 'green')
                  : t.difficulty === 'Medium'
                  ? (theme.warning || 'yellow')
                  : (theme.error || 'red');

                return React.createElement(
                  Box,
                  { key: t.id, flexDirection: 'row', paddingY: 0 },
                  React.createElement(
                    Text,
                    { color: isSelected ? (theme.primary || 'cyan') : (theme.muted || 'gray'), bold: isSelected, width: 4 },
                    isSelected ? '▶ ' : '  ',
                    `${idx + 1}`
                  ),
                  React.createElement(
                    Text,
                    { color: catObj.color || 'white', bold: isSelected, width: 14 },
                    `[${t.category.toUpperCase()}]`
                  ),
                  React.createElement(
                    Text,
                    { color: isSelected ? (theme.primary || 'cyan') : 'white', bold: isSelected, width: 26 },
                    t.name
                  ),
                  React.createElement(
                    Text,
                    { color: diffColor, width: 12 },
                    t.difficulty
                  ),
                  React.createElement(
                    Text,
                    { color: theme.secondary || 'yellow', width: 10 },
                    `${t.port}/${t.protocol}`
                  ),
                  React.createElement(
                    Text,
                    { color: theme.muted || 'gray', dimColor: !isSelected, flexGrow: 1 },
                    t.description
                  )
                );
              })
            ),

            // Right: Template Details & Instant Spin-Up Panel
            selectedTemplate
              ? React.createElement(
                  Box,
                  {
                    flexDirection: 'column',
                    width: 44,
                    borderStyle: 'round',
                    borderColor: theme.success || 'green',
                    paddingX: 1
                  },
                  React.createElement(
                    Text,
                    { bold: true, color: theme.success || 'green' },
                    `🚀 READY TO SPIN UP`
                  ),
                  React.createElement(
                    Box,
                    { marginTop: 1, flexDirection: 'column' },
                    React.createElement(Text, { bold: true }, selectedTemplate.name),
                    React.createElement(Text, { color: theme.muted || 'gray' }, selectedTemplate.description),
                    React.createElement(Text, { marginTop: 1 }, React.createElement(Text, { color: theme.muted || 'gray' }, 'Port: '), React.createElement(Text, { color: theme.secondary || 'yellow' }, `${selectedTemplate.port}`)),
                    React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Difficulty: '), React.createElement(Text, { bold: true }, selectedTemplate.difficulty)),
                    React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Sandbox: '), React.createElement(Text, { color: 'cyan' }, selectedTemplate.category === 'pwn' ? 'nsjail / isolated' : 'Standard Container')),
                    React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Default Flag: '), React.createElement(Text, { color: theme.success || 'green', dimColor: true }, selectedTemplate.defaultFlag))
                  ),
                  React.createElement(
                    Box,
                    { marginTop: 1, flexDirection: 'column', borderTop: true, borderColor: theme.muted || 'gray', paddingTop: 1 },
                    React.createElement(Text, { bold: true, color: theme.warning || 'yellow' }, 'Author Hint:'),
                    React.createElement(Text, { dimColor: true }, selectedTemplate.hints?.[0] || 'No hints recorded.')
                  ),
                  React.createElement(
                    Box,
                    { marginTop: 1, padding: 1, borderStyle: 'single', borderColor: theme.success || 'green', alignItems: 'center' },
                    React.createElement(
                      Text,
                      { bold: true, color: theme.success || 'green' },
                      'Press [Enter] or [s] to Deploy'
                    )
                  )
                )
              : null
          )
        )
      : null,

    // --- MODAL: DETAILED INSPECTION ---
    activeTab === 'details' && activeChal
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            borderStyle: 'double',
            borderColor: theme.primary || 'cyan',
            padding: 1,
            marginTop: 1
          },
          React.createElement(
            Text,
            { bold: true, color: theme.primary || 'cyan' },
            `🔎 DETAILED CHALLENGE INSPECTION: ${activeChal.name.toUpperCase()}`
          ),
          React.createElement(
            Box,
            { flexDirection: 'column', marginTop: 1 },
            React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Category: '), React.createElement(Text, { bold: true }, activeChal.category.toUpperCase())),
            React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Status: '), React.createElement(Text, { color: activeChal.status === 'Ready' ? 'green' : 'yellow', bold: true }, activeChal.status)),
            React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Network Port: '), React.createElement(Text, { color: 'yellow' }, `${activeChal.port}/${activeChal.protocol}`)),
            React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Connection Command: '), React.createElement(Text, { color: 'cyan', bold: true }, activeChal.connectionString)),
            React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Active Flag: '), React.createElement(Text, { color: 'green', bold: true }, activeChal.flag)),
            React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Pod Identifier: '), React.createElement(Text, null, activeChal.podName || 'N/A')),
            React.createElement(Text, null, React.createElement(Text, { color: theme.muted || 'gray' }, 'Created: '), React.createElement(Text, null, activeChal.createdAt))
          ),
          React.createElement(
            Box,
            { marginTop: 1, borderTop: true, borderColor: theme.muted || 'gray', paddingTop: 1 },
            React.createElement(Text, { color: theme.warning || 'yellow' }, 'Press [Esc] or [q] to return to Active Challenges view.')
          )
        )
      : null,

    // --- MODAL: CONTAINER LOGS ---
    activeTab === 'logs'
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            borderStyle: 'round',
            borderColor: theme.warning || 'yellow',
            padding: 1,
            marginTop: 1
          },
          React.createElement(
            Text,
            { bold: true, color: theme.warning || 'yellow' },
            `📋 POD LOG STREAM: ${activeChal ? activeChal.name : 'Unknown'}`
          ),
          React.createElement(
            Box,
            { marginY: 1, flexDirection: 'column' },
            React.createElement(Text, { dimColor: true }, logContent || 'No logs available.')
          ),
          React.createElement(
            Text,
            { color: theme.muted || 'gray' },
            'Press [Esc] or [q] to dismiss logs.'
          )
        )
      : null,

    // 4. Footer & Action Legend
    React.createElement(
      Box,
      {
        flexDirection: 'row',
        marginTop: 1,
        borderStyle: 'single',
        borderColor: theme.muted || 'gray',
        paddingX: 1,
        gap: 1
      },
      activeTab === 'active'
        ? React.createElement(
            React.Fragment,
            null,
            React.createElement(Text, { bold: true, color: theme.success || 'green' }, '[s/Tab]'),
            React.createElement(Text, null, 'Spin Up New'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.primary || 'cyan' }, '[t]'),
            React.createElement(Text, null, 'Test Probe'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.info || 'blue' }, '[l]'),
            React.createElement(Text, null, 'Logs'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.warning || 'yellow' }, '[x]'),
            React.createElement(Text, null, 'Pause/Resume'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.error || 'red' }, '[d]'),
            React.createElement(Text, null, 'Delete'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.secondary || 'magenta' }, '[c]'),
            React.createElement(Text, null, 'Copy String'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.warning || 'yellow' }, '[w]'),
            React.createElement(Text, null, 'Web Portal'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.muted || 'gray' }, '[q]'),
            React.createElement(Text, null, 'Hub')
          )
        : React.createElement(
            React.Fragment,
            null,
            React.createElement(Text, { bold: true, color: theme.success || 'green' }, '[Enter/s]'),
            React.createElement(Text, null, 'Deploy Selected'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.accent || 'magenta' }, '[←/→]'),
            React.createElement(Text, null, 'Category Filter'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.primary || 'cyan' }, '[↑/↓]'),
            React.createElement(Text, null, 'Choose Template'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.warning || 'yellow' }, '[Tab]'),
            React.createElement(Text, null, 'Active Challenges'),
            React.createElement(Text, { color: theme.muted || 'gray' }, '│'),
            React.createElement(Text, { bold: true, color: theme.muted || 'gray' }, '[q]'),
            React.createElement(Text, null, 'Hub')
          )
    )
  );
});
