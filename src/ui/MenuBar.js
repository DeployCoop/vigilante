import React from 'react';
import { Box, Text } from 'ink';

/**
 * Persistent Action Menu Bar component
 * Displays all available interactive keyboard shortcuts
 */
export const MenuBar = ({ isRunning = false, activeView = 'RUNNING' }) => {
  if (isRunning) {
    return React.createElement(
      Box,
      {
        marginTop: 1,
        paddingX: 1,
        borderStyle: 'round',
        borderColor: 'yellow',
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'yellow', bold: true }, '⏳ Running Task in Progress... '),
        React.createElement(Text, { color: 'gray' }, '| Press [Ctrl+C] or [q] to abort')
      ),
      React.createElement(
        Text,
        { color: 'cyan', dimColor: true },
        '🖱️  Click any pane to copy to clipboard'
      )
    );
  }

  const items = [
    { key: 'u', label: 'Up (Deploy)', color: 'green' },
    { key: 'd', label: 'Down (Teardown)', color: 'red' },
    { key: 's', label: 'Status', color: 'blue' },
    { key: 't', label: 'Threat-Sim', color: 'magenta' },
    { key: 'h', label: 'Hostr (DNS)', color: 'cyan' },
    { key: 'v', label: 'Values (Helm)', color: 'yellow' },
    { key: 'm', label: 'Modules', color: 'white' },
    { key: 'q', label: 'Quit', color: 'gray' }
  ];

  return React.createElement(
    Box,
    {
      marginTop: 1,
      flexDirection: 'column',
      paddingX: 1,
      paddingY: 0,
      borderStyle: 'round',
      borderColor: 'gray'
    },
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 0 },
      React.createElement(
        Text,
        { color: 'white', bold: true },
        '🎮 Action Menu (Press key anytime):'
      ),
      React.createElement(
        Text,
        { color: 'cyan', dimColor: true },
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
            { color: 'white' },
            item.label
          )
        )
      )
    )
  );
};
