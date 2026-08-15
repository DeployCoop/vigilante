import React from 'react';
import { Box, Text } from 'ink';

export const Header = ({ command = 'up', domain = 'vigilante.local' }) => {
  return React.createElement(
    Box,
    { flexDirection: 'column', marginBottom: 1 },
    React.createElement(
      Box,
      { borderStyle: 'round', borderColor: 'cyan', paddingX: 2, paddingY: 0, flexDirection: 'column' },
      React.createElement(
        Text,
        { bold: true, color: 'cyan' },
        '██╗   ██╗██╗ ██████╗ ██╗██╗      █████╗ ███╗   ██╗████████╗███████╗'
      ),
      React.createElement(
        Text,
        { bold: true, color: 'cyan' },
        '██║   ██║██║██╔════╝ ██║██║     ██╔══██╗████╗  ██║╚══██╔══╝██╔════╝'
      ),
      React.createElement(
        Text,
        { bold: true, color: 'blue' },
        '██║   ██║██║██║  ███╗██║██║     ███████║██╔██╗ ██║   ██║   █████╗  '
      ),
      React.createElement(
        Text,
        { bold: true, color: 'blue' },
        '╚██╗ ██╔╝██║██║   ██║██║██║     ██╔══██║██║╚██╗██║   ██║   ██╔══╝  '
      ),
      React.createElement(
        Text,
        { bold: true, color: 'magenta' },
        ' ╚████╔╝ ██║╚██████╔╝██║███████╗██║  ██║██║ ╚████║   ██║   ███████╗'
      ),
      React.createElement(
        Text,
        { bold: true, color: 'magenta' },
        '  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝'
      ),
      React.createElement(
        Box,
        { marginTop: 1, justifyContent: 'space-between' },
        React.createElement(
          Text,
          { color: 'yellow', bold: true },
          '🦇 Local Threat Analysis & SIEM Sandbox'
        ),
        React.createElement(
          Text,
          { color: 'gray' },
          `Command: [${command}] | Domain: ${domain}`
        )
      )
    )
  );
};
