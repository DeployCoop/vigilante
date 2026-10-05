import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { useTheme } from './theme.js';
import { generateKspmScorecard, saveKspmReport } from '../engine/kspm.js';
import { copyToClipboard } from '../utils/clipboard.js';

export const KspmView = memo(function KspmView({
  namespace = 'default',
  clusterName = 'vigilante-dev',
  onNavigate = null
}) {
  const theme = useTheme();
  const [scorecard, setScorecard] = useState(null);
  const [cursor, setCursor] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [feedback, setFeedback] = useState(null);

  const loadScorecard = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await generateKspmScorecard({ namespace: namespace === 'default' ? null : namespace });
      setScorecard(data);
    } catch (err) {
      setFeedback({ type: 'error', message: `Failed to evaluate KSPM: ${err.message}` });
    } finally {
      setIsLoading(false);
    }
  }, [namespace]);

  useEffect(() => {
    loadScorecard();
  }, [loadScorecard]);

  useInput(async (input, key) => {
    if (key.escape || input === 'q') {
      if (onNavigate) onNavigate('HUB');
      return;
    }

    if (key.upArrow || input === 'k') {
      if (scorecard && scorecard.findings.length > 0) {
        setCursor(c => Math.max(0, c - 1));
      }
      return;
    }

    if (key.downArrow || input === 'j') {
      if (scorecard && scorecard.findings.length > 0) {
        setCursor(c => Math.min(scorecard.findings.length - 1, c + 1));
      }
      return;
    }

    // Refresh [r]
    if (input === 'r' || input === 'R') {
      setFeedback({ type: 'info', message: 'Re-evaluating cluster posture...' });
      await loadScorecard();
      setFeedback({ type: 'success', message: '✔ Posture scorecard refreshed!' });
      return;
    }

    // Export signed report [e]
    if (input === 'e' || input === 'E') {
      if (scorecard) {
        try {
          const report = await saveKspmReport(scorecard);
          setFeedback({ type: 'success', message: `✔ Saved signed report to: ${report.reportPath}` });
        } catch (err) {
          setFeedback({ type: 'error', message: `Export failed: ${err.message}` });
        }
      }
      return;
    }

    // Copy JSON [c]
    if (input === 'c' || input === 'C') {
      if (scorecard) {
        copyToClipboard(JSON.stringify(scorecard, null, 2));
        setFeedback({ type: 'success', message: '✔ Copied KSPM scorecard JSON to clipboard!' });
      }
      return;
    }
  });

  const getGradeColor = (grade) => {
    if (grade?.startsWith('A')) return 'green';
    if (grade?.startsWith('B')) return 'cyan';
    if (grade?.startsWith('C')) return 'yellow';
    return 'red';
  };

  const getSevColor = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'red';
      case 'HIGH': return 'yellow';
      case 'MEDIUM': return 'cyan';
      default: return 'gray';
    }
  };

  if (isLoading || !scorecard) {
    return React.createElement(
      Box,
      { padding: 2, borderStyle: 'round', borderColor: 'cyan' },
      React.createElement(Text, { color: 'cyan', bold: true }, '⏳ Evaluating Kubernetes Security Posture & CIS Benchmarks...')
    );
  }

  const selectedFinding = scorecard.findings[cursor] || null;

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%' },

    // Header banner
    React.createElement(
      Box,
      {
        justifyContent: 'space-between',
        borderStyle: 'double',
        borderColor: 'cyan',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: 'cyan' }, '🛡️  KUBERNETES SECURITY POSTURE MANAGEMENT (KSPM) '),
        React.createElement(Text, { color: 'gray' }, '| CIS Benchmarks & Pod Security Standards (PSS)')
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'gray' }, 'Grade: '),
        React.createElement(Text, { color: getGradeColor(scorecard.grade), bold: true }, `[${scorecard.grade}] `),
        React.createElement(Text, { color: 'white', bold: true }, `(${scorecard.overallScore}/100)`)
      )
    ),

    // Hotkey bar
    React.createElement(
      Box,
      { flexDirection: 'row', justifyContent: 'space-between', paddingX: 1, marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'green', bold: true }, '[r] '),
        React.createElement(Text, { color: 'white' }, 'Refresh  '),
        React.createElement(Text, { color: 'yellow', bold: true }, '[e] '),
        React.createElement(Text, { color: 'white' }, 'Export Signed Report  '),
        React.createElement(Text, { color: 'blue', bold: true }, '[c] '),
        React.createElement(Text, { color: 'white' }, 'Copy JSON  '),
        React.createElement(Text, { color: 'gray', bold: true }, '[q/Esc] '),
        React.createElement(Text, { color: 'white' }, 'Hub')
      ),
      React.createElement(
        Text,
        { color: 'gray' },
        `Workloads Scanned: ${scorecard.workloadCount} | Violations: ${scorecard.findings.length}`
      )
    ),

    // Feedback toast
    feedback
      ? React.createElement(
          Box,
          {
            paddingX: 1,
            marginBottom: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'error' ? 'red' : 'green'
          },
          React.createElement(
            Text,
            { color: feedback.type === 'error' ? 'red' : 'green', bold: true },
            feedback.message
          )
        )
      : null,

    // Main 2-column view
    React.createElement(
      Box,
      { flexDirection: 'row', width: '100%' },

      // Left Column: Violations List
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'round',
          borderColor: 'cyan',
          padding: 1,
          marginRight: 1
        },
        React.createElement(
          Text,
          { bold: true, color: 'cyan', underline: true, marginBottom: 1 },
          `Identified Violations (${scorecard.findings.length})`
        ),
        scorecard.findings.length === 0
          ? React.createElement(Text, { color: 'green' }, '✔ No posture violations detected. Cluster is hardened!')
          : scorecard.findings.slice(0, 10).map((f, idx) => {
              const isSelected = idx === cursor;
              return React.createElement(
                Box,
                { key: idx, flexDirection: 'column', marginBottom: 1 },
                React.createElement(
                  Box,
                  { flexDirection: 'row', justifyContent: 'space-between' },
                  React.createElement(
                    Text,
                    { color: isSelected ? 'cyan' : 'white', bold: isSelected },
                    `${isSelected ? '▶ ' : '  '}${f.title}`
                  ),
                  React.createElement(
                    Text,
                    { color: getSevColor(f.severity), bold: true },
                    `[${f.severity}]`
                  )
                ),
                React.createElement(
                  Text,
                  { color: 'gray', marginLeft: 2 },
                  `Resource: ${f.resource} | Rule: ${f.ruleId}`
                )
              );
            })
      ),

      // Right Column: Remediation & Benchmark Details
      React.createElement(
        Box,
        {
          flexDirection: 'column',
          width: '50%',
          borderStyle: 'round',
          borderColor: 'gray',
          padding: 1
        },
        selectedFinding
          ? React.createElement(
              Box,
              { flexDirection: 'column' },
              React.createElement(
                Text,
                { bold: true, color: 'yellow', marginBottom: 1 },
                `🔎 Violation Details: ${selectedFinding.title}`
              ),
              React.createElement(
                Text,
                { color: 'white', marginBottom: 1 },
                selectedFinding.description
              ),
              React.createElement(
                Text,
                { color: 'gray', marginBottom: 1 },
                `Target Workload: ${selectedFinding.resource} (Namespace: ${selectedFinding.namespace})`
              ),
              React.createElement(
                Box,
                {
                  flexDirection: 'column',
                  borderStyle: 'single',
                  borderColor: 'green',
                  padding: 1,
                  marginTop: 1
                },
                React.createElement(Text, { bold: true, color: 'green' }, '💡 Remediation Guidance:'),
                React.createElement(Text, { color: 'white' }, selectedFinding.remediation)
              )
            )
          : React.createElement(
              Box,
              { flexDirection: 'column' },
              React.createElement(Text, { color: 'gray' }, 'Select a violation on the left to view CIS benchmark and remediation details.')
            )
      )
    )
  );
});
