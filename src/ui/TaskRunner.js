import React, { useEffect } from 'react';
import { Box, Text } from 'ink';
import Spinner from 'ink-spinner';
import { useClipboard } from './ClipboardManager.js';

export const TaskRunner = ({ tasks = [], logs = [], maxLogs = 6 }) => {
  const visibleLogs = logs.slice(-maxLogs);
  const { registerPanes } = useClipboard();

  useEffect(() => {
    const runnerPanes = [];
    const tasksHeight = tasks.length + 2;

    runnerPanes.push({
      id: 'tasks',
      title: 'Tasks List',
      startRow: 6,
      endRow: 6 + tasksHeight,
      getText: () => tasks.map(t => `[${t.status}] ${t.label}${t.detail ? ' (' + t.detail + ')' : ''}${t.error ? ' - Error: ' + t.error : ''}`).join('\n')
    });

    if (visibleLogs.length > 0) {
      runnerPanes.push({
        id: 'logs',
        title: 'Execution Logs Stream',
        startRow: 7 + tasksHeight,
        endRow: 7 + tasksHeight + visibleLogs.length + 3,
        getText: () => logs.map(l => typeof l === 'string' ? l : l.message || JSON.stringify(l)).join('\n')
      });
    }

    registerPanes(runnerPanes);
  }, [tasks, logs, registerPanes]);

  return React.createElement(
    Box,
    { flexDirection: 'column', marginY: 1 },
    React.createElement(
      Box,
      { flexDirection: 'column', marginBottom: 1 },
      tasks.map((task) => {
        let icon;
        let textColor = 'gray';

        if (task.status === 'running') {
          icon = React.createElement(Spinner, { type: 'dots' });
          textColor = 'yellow';
        } else if (task.status === 'done') {
          icon = React.createElement(Text, { color: 'green', bold: true }, '✔');
          textColor = 'green';
        } else if (task.status === 'error') {
          icon = React.createElement(Text, { color: 'red', bold: true }, '✖');
          textColor = 'red';
        } else {
          icon = React.createElement(Text, { color: 'gray' }, '○');
          textColor = 'gray';
        }

        return React.createElement(
          Box,
          { key: task.id, flexDirection: 'column', marginY: 0 },
          React.createElement(
            Box,
            null,
            React.createElement(Box, { width: 3 }, icon),
            React.createElement(
              Text,
              { color: textColor, bold: task.status === 'running' || task.status === 'done' },
              task.label
            )
          ),
          task.detail && task.status === 'running'
            ? React.createElement(
                Box,
                { marginLeft: 3 },
                React.createElement(Text, { color: 'gray', italic: true }, `→ ${task.detail}`)
              )
            : null,
          task.error
            ? React.createElement(
                Box,
                { marginLeft: 3 },
                React.createElement(Text, { color: 'red' }, `Error: ${task.error}`)
              )
            : null
        );
      })
    ),

    visibleLogs.length > 0
      ? React.createElement(
          Box,
          {
            flexDirection: 'column',
            borderStyle: 'single',
            borderColor: 'gray',
            paddingX: 1,
            paddingY: 0,
            marginTop: 1
          },
          React.createElement(
            Text,
            { color: 'gray', dimColor: true, bold: true },
            '📋 Execution Stream'
          ),
          visibleLogs.map((log, idx) =>
            React.createElement(
              Text,
              { key: idx, color: 'gray', wrap: 'truncate-end' },
              typeof log === 'string' ? log : log.message
            )
          )
        )
      : null
  );
};
