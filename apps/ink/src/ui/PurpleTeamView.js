import React, { useState } from 'react';
import { Box, Text } from 'ink';
import { WARGAME_SCENARIOS, runPurpleTeamSimulation, calculatePurpleScorecard } from '../engine/purpleteam.js';
import { useTheme } from './theme.js';

export function PurpleTeamView({ onBack }) {
  const theme = useTheme();
  const [running, setRunning] = useState(false);
  const [selectedScenario, setSelectedScenario] = useState('lateral-smb-exfil');
  const [lastRun, setLastRun] = useState(null);
  const [scorecard, setScorecard] = useState(null);

  const startSimulation = async (scenKey) => {
    setRunning(true);
    try {
      const res = await runPurpleTeamSimulation(scenKey);
      const sc = calculatePurpleScorecard(res);
      setLastRun(res);
      setScorecard(sc);
    } catch (err) {
      console.error(err);
    } finally {
      setRunning(false);
    }
  };

  return React.createElement(
    Box,
    { flexDirection: 'column', width: '100%', height: '100%', padding: 1 },
    React.createElement(
      Box,
      { borderStyle: 'round', borderColor: theme.colors.primary, paddingX: 1, marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.header, bold: true }, '⚔️ Vigilante Autonomous Purple Team Arena')
    ),
    React.createElement(
      Box,
      { marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.muted }, 'Multi-Agent Adversarial Simulation: Red Adversary vs. Blue ReAct SOC & SOAR')
    ),
    React.createElement(
      Box,
      { borderStyle: 'single', borderColor: theme.colors.border, padding: 1, flexDirection: 'column', marginBottom: 1 },
      React.createElement(Text, { color: theme.colors.accent, bold: true }, 'Available Adversary Scenarios:'),
      Object.entries(WARGAME_SCENARIOS).map(([key, s]) =>
        React.createElement(
          Box,
          { key, marginY: 0 },
          React.createElement(Text, { color: selectedScenario === key ? theme.colors.selectedText : theme.colors.text }, `${selectedScenario === key ? '▶ ' : '  '}${s.name} (${s.adversaryGroup})`)
        )
      )
    ),
    running
      ? React.createElement(
          Box,
          { padding: 1 },
          React.createElement(Text, { color: theme.colors.accent, bold: true }, '⚡ Adversarial simulation executing in sandboxed range...')
        )
      : scorecard
        ? React.createElement(
            Box,
            { borderStyle: 'double', borderColor: theme.colors.success, flexDirection: 'column', padding: 1 },
            React.createElement(
              Box,
              { justifyContent: 'space-between' },
              React.createElement(Text, { color: theme.colors.success, bold: true }, `🏆 Defense Verdict: Grade [${scorecard.grade}] (${scorecard.score}/100)`),
              React.createElement(Text, { color: theme.colors.warning, bold: true }, `Verdict: ${scorecard.contained ? 'CONTAINED' : 'EXFILTRATED'}`)
            ),
            React.createElement(
              Box,
              { marginTop: 1 },
              React.createElement(Text, { color: theme.colors.info }, `MTTD: ${scorecard.mttdSec}s  |  MTTR: ${scorecard.mttrSec}s  |  Containment: Step ${scorecard.containmentStep}`)
            ),
            React.createElement(
              Box,
              { marginTop: 1, flexDirection: 'column' },
              scorecard.recommendations.map((rec, i) =>
                React.createElement(Text, { key: i, color: theme.colors.muted }, `• ${rec}`)
              )
            )
          )
        : React.createElement(
            Box,
            { padding: 1 },
            React.createElement(Text, { color: theme.colors.muted }, 'Press [s] to trigger automated simulation wargame.')
          ),
    React.createElement(
      Box,
      { marginTop: 1, borderStyle: 'single', borderColor: theme.colors.border, paddingX: 1 },
      React.createElement(Text, { color: theme.colors.muted }, '[Esc/q] Back to Hub  |  [s] Start Simulation  |  [1/2] Switch Scenario')
    )
  );
}
