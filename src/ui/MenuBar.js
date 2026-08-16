import React from 'react';
import { Box, Text } from 'ink';
import { useTheme } from './theme.js';

/**
 * Persistent Action Menu Bar component
 * Displays all available interactive keyboard shortcuts
 */
export const MenuBar = ({ isRunning = false, activeView = 'RUNNING' }) => {
  const theme = useTheme();

  if (isRunning) {
    return React.createElement(
      Box,
      {
        marginTop: 1,
        paddingX: 1,
        borderStyle: 'round',
        borderColor: theme.warning,
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.warning, bold: true }, '⏳ Running Task in Progress... '),
        React.createElement(Text, { color: theme.muted }, '| Press [Ctrl+C] or [q] to abort')
      ),
      React.createElement(
        Text,
        { color: theme.accent, dimColor: true },
        '🖱️  Click any pane to copy to clipboard'
      )
    );
  }

  const items = [
    { key: 'u', label: 'Up (Deploy)', color: theme.success },
    { key: 'd', label: 'Down (Teardown)', color: theme.error },
    { key: 's', label: 'Status', color: theme.info },
    { key: 'p', label: 'Pods (Live)', color: theme.primary },
    { key: 'n', label: 'Nmap (Scan)', color: theme.accent },
    { key: 'x', label: 'XML Map', color: theme.secondary },
    { key: 't', label: 'Threat-Sim', color: theme.secondary },
    { key: 'h', label: 'Hostr (DNS)', color: theme.accent },
    { key: 'v', label: 'Values (Helm)', color: theme.accent },
    { key: 'm', label: 'Modules', color: theme.text },
    { key: 'q', label: 'Quit', color: theme.muted }
  ];

  return React.createElement(
    Box,
    {
      marginTop: 1,
      flexDirection: 'column',
      paddingX: 1,
      paddingY: 0,
      borderStyle: 'round',
      borderColor: theme.border
    },
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 0 },
      React.createElement(
        Text,
        { color: theme.text, bold: true },
        '🎮 Action Menu (Press key anytime):'
      ),
      React.createElement(
        Text,
        { color: theme.accent, dimColor: true },
        '🖱️  Click pane or press [1-6] to copy'
      )
    ),
    React.createElement(
      Box,
      { flexWrap: 'wrap', marginTop: 0 },
      items.map((item, idx) =>
        React.createElement(
          Box,
          { key: item.key, marginRight: 2 },
          React.createElement(
            Text,
            { color: item.color, bold: true },
            `[${item.key}] `
          ),
          React.createElement(
            Text,
            { color: theme.text },
            item.label
          )
        )
      )
    )
  );
};
