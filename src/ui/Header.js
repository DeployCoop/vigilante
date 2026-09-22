import React, { memo } from 'react';
import { Box, Text } from 'ink';
import { useTheme } from './theme.js';

export const Header = memo(function Header({ command = 'up', domain = 'vigilante.local', namespace = null }) {
  const theme = useTheme();

  return React.createElement(
    Box,
    { flexDirection: 'column', marginBottom: 1 },
    React.createElement(
      Box,
      { borderStyle: 'round', borderColor: theme.border, paddingX: 2, paddingY: 0, flexDirection: 'column' },
      React.createElement(
        Text,
        { bold: true, color: theme.header || theme.primary },
        '██╗   ██╗██╗ ██████╗ ██╗██╗      █████╗ ███╗   ██╗████████╗███████╗'
      ),
      React.createElement(
        Text,
        { bold: true, color: theme.header || theme.primary },
        '██║   ██║██║██╔════╝ ██║██║     ██╔══██╗████╗  ██║╚══██╔══╝██╔════╝'
      ),
      React.createElement(
        Text,
        { bold: true, color: theme.primary },
        '██║   ██║██║██║  ███╗██║██║     ███████║██╔██╗ ██║   ██║   █████╗  '
      ),
      React.createElement(
        Text,
        { bold: true, color: theme.primary },
        '╚██╗ ██╔╝██║██║   ██║██║██║     ██╔══██║██║╚██╗██║   ██║   ██╔══╝  '
      ),
      React.createElement(
        Text,
        { bold: true, color: theme.banner || theme.secondary },
        ' ╚████╔╝ ██║╚██████╔╝██║███████╗██║  ██║██║ ╚████║   ██║   ███████╗'
      ),
      React.createElement(
        Text,
        { bold: true, color: theme.banner || theme.secondary },
        '  ╚═══╝  ╚═╝ ╚═════╝ ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝'
      ),
      React.createElement(
        Box,
        { marginTop: 1, justifyContent: 'space-between' },
        React.createElement(
          Text,
          { color: theme.accent, bold: true },
          '🦇 Local Threat Analysis & SIEM Sandbox'
        ),
        React.createElement(
          Text,
          { color: theme.muted },
          `Command: [${command}] | Domain: ${domain}${namespace ? ` | NS: ${namespace}` : ''}`
        )
      )
    )
  );
});
