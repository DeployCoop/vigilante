import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import { useTheme } from './theme.js';
import { runPipelineAudit, generateSarifReport } from '../engine/audit.js';
import { copyToClipboard } from '../utils/clipboard.js';

export const AuditView = memo(function AuditView({
  targetPath = '.',
  onNavigate = null
}) {
  const theme = useTheme();
  const [auditResult, setAuditResult] = useState(null);
  const [cursor, setCursor] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const [feedback, setFeedback] = useState(null);

  const runAudit = useCallback(async () => {
    setIsLoading(true);
    try {
      const res = await runPipelineAudit(targetPath, { failOn: 'HIGH' });
      setAuditResult(res);
    } catch (err) {
      setFeedback({ type: 'error', message: `Audit error: ${err.message}` });
    } finally {
      setIsLoading(false);
    }
  }, [targetPath]);

  useEffect(() => {
    runAudit();
  }, [runAudit]);

  useInput(async (input, key) => {
    if (key.escape || input === 'q') {
      if (onNavigate) onNavigate('HUB');
      return;
    }

    if (key.upArrow || input === 'k') {
      if (auditResult && auditResult.findings.length > 0) {
        setCursor(c => Math.max(0, c - 1));
      }
      return;
    }

    if (key.downArrow || input === 'j') {
      if (auditResult && auditResult.findings.length > 0) {
        setCursor(c => Math.min(auditResult.findings.length - 1, c + 1));
      }
      return;
    }

    // Refresh audit [r]
    if (input === 'r' || input === 'R') {
      setFeedback({ type: 'info', message: 'Re-running shift-left audit...' });
      await runAudit();
      setFeedback({ type: 'success', message: '✔ Shift-left audit re-executed!' });
      return;
    }

    // Copy SARIF [s]
    if (input === 's' || input === 'S') {
      if (auditResult) {
        const sarif = generateSarifReport(auditResult.findings);
        copyToClipboard(JSON.stringify(sarif, null, 2));
        setFeedback({ type: 'success', message: '✔ Copied SARIF v2.1.0 JSON to clipboard!' });
      }
      return;
    }

    // Copy JSON [c]
    if (input === 'c' || input === 'C') {
      if (auditResult) {
        copyToClipboard(JSON.stringify(auditResult, null, 2));
        setFeedback({ type: 'success', message: '✔ Copied audit result JSON to clipboard!' });
      }
      return;
    }
  });

  const getSevColor = (sev) => {
    switch (sev) {
      case 'CRITICAL': return 'red';
      case 'HIGH': return 'yellow';
      case 'MEDIUM': return 'cyan';
      default: return 'gray';
    }
  };

  if (isLoading || !auditResult) {
    return React.createElement(
      Box,
      { padding: 2, borderStyle: 'round', borderColor: 'cyan' },
      React.createElement(Text, { color: 'cyan', bold: true }, `⏳ Running shift-left security scan on '${targetPath}'...`)
    );
  }

  const selectedFinding = auditResult.findings[cursor] || null;

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%' },

    // Header
    React.createElement(
      Box,
      {
        justifyContent: 'space-between',
        borderStyle: 'double',
        borderColor: auditResult.failed ? 'red' : 'green',
        paddingX: 1,
        marginBottom: 1
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { bold: true, color: 'cyan' }, '🛡️  VIGILANTE SHIFT-LEFT SECURITY AUDIT '),
        React.createElement(Text, { color: 'gray' }, `| Target: ${targetPath}`)
      ),
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'gray' }, 'Status: '),
        React.createElement(
          Text,
          { color: auditResult.failed ? 'red' : 'green', bold: true },
          auditResult.failed ? '✖ GATE FAILED' : '✔ GATE PASSED'
        )
      )
    ),

    // Hotkey & summary bar
    React.createElement(
      Box,
      { flexDirection: 'row', justifyContent: 'space-between', paddingX: 1, marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'green', bold: true }, '[r] '),
        React.createElement(Text, { color: 'white' }, 'Re-scan  '),
        React.createElement(Text, { color: 'yellow', bold: true }, '[s] '),
        React.createElement(Text, { color: 'white' }, 'Copy SARIF  '),
        React.createElement(Text, { color: 'blue', bold: true }, '[c] '),
        React.createElement(Text, { color: 'white' }, 'Copy JSON  '),
        React.createElement(Text, { color: 'gray', bold: true }, '[q/Esc] '),
        React.createElement(Text, { color: 'white' }, 'Hub')
      ),
      React.createElement(
        Text,
        { color: 'gray' },
        `Files Scanned: ${auditResult.filesScanned} | Violations: ${auditResult.findings.length} (Crit: ${auditResult.summary.CRITICAL}, High: ${auditResult.summary.HIGH})`
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

    // 2-column findings layout
    React.createElement(
      Box,
      { flexDirection: 'row', width: '100%' },

      // Left Column: Findings List
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
          `Audit Findings (${auditResult.findings.length})`
        ),
        auditResult.findings.length === 0
          ? React.createElement(Text, { color: 'green' }, '✔ No security violations detected in manifests or Dockerfiles!')
          : auditResult.findings.slice(0, 10).map((f, idx) => {
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
                  `${f.file}${f.line ? `:${f.line}` : ''} | Rule: ${f.ruleId}`
                )
              );
            })
      ),

      // Right Column: Violation Details & Remediation
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
                `🔎 ${selectedFinding.title} (${selectedFinding.ruleId})`
              ),
              React.createElement(
                Text,
                { color: 'white', marginBottom: 1 },
                selectedFinding.description
              ),
              React.createElement(
                Text,
                { color: 'gray', marginBottom: 1 },
                `Location: ${selectedFinding.file}${selectedFinding.line ? ` line ${selectedFinding.line}` : ''}`
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
                React.createElement(Text, { bold: true, color: 'green' }, '💡 Remediation Advice:'),
                React.createElement(Text, { color: 'white' }, selectedFinding.remediation)
              )
            )
          : React.createElement(
              Box,
              { flexDirection: 'column' },
              React.createElement(Text, { color: 'gray' }, 'Select an audit finding to inspect rule definition and remediation advice.')
            )
      )
    )
  );
});
