import React, { useState, useEffect, useCallback } from 'react';
import { Box, Text, useInput } from 'ink';
import path from 'node:path';
import fs from 'node:fs';
import { listChartValues, exportStarterValues } from '../engine/helm.js';
import { openInEditor, ensureOverrideFileExists } from '../utils/editor.js';
import { useClipboard } from './ClipboardManager.js';
import { logger } from '../utils/logger.js';

export const ValuesView = ({
  domain = 'vigilante.local',
  customValuesDir = null,
  onNavigate = null
}) => {
  const [items, setItems] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [feedback, setFeedback] = useState(null);
  const [editorName, setEditorName] = useState(
    process.env.VISUAL || process.env.EDITOR || (process.platform === 'win32' ? 'notepad' : 'nano')
  );
  const { registerPanes } = useClipboard();

  const loadChartItems = useCallback(async () => {
    try {
      const charts = await listChartValues({ customValuesDir });
      const cwd = process.cwd();
      const mapped = charts.map((c) => {
        const defaultOverrideRel = path.join(customValuesDir || 'values', c.moduleId, `${c.chartName}.yaml`);
        const defaultOverrideAbs = path.resolve(cwd, defaultOverrideRel);
        const exists = fs.existsSync(c.userOverridePath || defaultOverrideAbs);
        return {
          ...c,
          targetOverridePath: c.userOverridePath || defaultOverrideAbs,
          targetOverrideRel: path.relative(cwd, c.userOverridePath || defaultOverrideAbs),
          hasOverride: exists,
          description: getChartDescription(c.moduleId, c.chartName)
        };
      });
      setItems(mapped);
    } catch (err) {
      logger.error('VALUES:LOAD', `Failed to load chart items: ${err.message}`, err);
    }
  }, [customValuesDir]);

  useEffect(() => {
    loadChartItems();
  }, [loadChartItems]);

  // Register clipboard pane for copying configuration summary
  useEffect(() => {
    registerPanes([
      {
        id: 'values-summary',
        title: 'Helm Values & Charts Overview',
        startRow: 6,
        endRow: 35,
        getText: () => {
          return items
            .map((item) => `• ${item.moduleId} / ${item.chartName}\n  Status: ${item.hasOverride ? 'Active Override (' + item.targetOverrideRel + ')' : 'Default Template'}\n  Template: ${item.defaultPath}`)
            .join('\n\n');
        }
      }
    ]);
  }, [items, registerPanes]);

  // Total selectable items = chart items + 1 action item (Export All)
  const totalOptions = items.length + 1;
  const isExportAction = cursor === items.length;

  const handleEdit = async (item) => {
    if (!item) return;
    try {
      setFeedback({ type: 'info', text: `Opening ${item.targetOverrideRel} in $EDITOR (${editorName})...` });
      logger.info('VALUES:EDIT', `User triggered edit for ${item.chartName}`);

      await ensureOverrideFileExists(item.targetOverridePath, item.defaultPath, {
        domain,
        tlsSecretName: `${item.moduleId}-tls`,
        namespace: item.moduleId
      });

      const res = openInEditor(item.targetOverridePath);
      await loadChartItems();

      if (res.success) {
        setFeedback({
          type: 'success',
          text: `✔ Finished editing ${item.targetOverrideRel} with ${res.editor}. Changes ready for 'vigilante up'!`
        });
      } else if (res.error) {
        setFeedback({ type: 'error', text: `✖ Editor error: ${res.error}` });
      }
    } catch (err) {
      logger.error('VALUES:EDIT:ERROR', err.message, err);
      setFeedback({ type: 'error', text: `✖ Failed to open editor: ${err.message}` });
    }
  };

  const handleExportAll = async () => {
    try {
      const targetDir = customValuesDir || './values';
      setFeedback({ type: 'info', text: `Exporting starter templates to '${targetDir}'...` });
      logger.info('VALUES:EXPORT', `Exporting all templates to ${targetDir}`);

      const exported = await exportStarterValues({
        targetDir,
        domain
      });
      await loadChartItems();
      setFeedback({
        type: 'success',
        text: `✔ Exported ${exported.length} starter YAML files to '${targetDir}'!`
      });
    } catch (err) {
      logger.error('VALUES:EXPORT:ERROR', err.message, err);
      setFeedback({ type: 'error', text: `✖ Export failed: ${err.message}` });
    }
  };

  // Keyboard navigation & editor trigger
  useInput(async (input, key) => {
    logger.debug('VALUES:KEY', `Key in ValuesView: input="${input}", key=${JSON.stringify(key)}`);
    const keyChar = (input || '').toLowerCase();

    if (key.upArrow || keyChar === 'k') {
      setCursor(c => (c > 0 ? c - 1 : totalOptions - 1));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setCursor(c => (c < totalOptions - 1 ? c + 1 : 0));
      return;
    }

    // [e] or [E] or [Enter] -> Trigger Edit / Action
    if (keyChar === 'e' || key.return) {
      if (isExportAction) {
        await handleExportAll();
      } else {
        const item = items[cursor];
        if (item) {
          await handleEdit(item);
        }
      }
      return;
    }

    // [x] -> Quick export all
    if (keyChar === 'x') {
      await handleExportAll();
      return;
    }

    // Navigation delegates
    if (keyChar === 's' && onNavigate) {
      logger.info('VALUES:NAV', 'User navigated to [s] Status');
      onNavigate('status');
      return;
    }
    if (keyChar === 'u' && onNavigate) {
      logger.info('VALUES:NAV', 'User navigated to [u] Up');
      onNavigate('up');
      return;
    }
    if (keyChar === 'd' && onNavigate) {
      logger.info('VALUES:NAV', 'User navigated to [d] Down');
      onNavigate('down');
      return;
    }
    if (keyChar === 't' && onNavigate) {
      logger.info('VALUES:NAV', 'User navigated to [t] Threat Sim');
      onNavigate('threat-sim');
      return;
    }
    if (keyChar === 'h' && onNavigate) {
      logger.info('VALUES:NAV', 'User navigated to [h] Hostr');
      onNavigate('hostr');
      return;
    }
    if (keyChar === 'm' && onNavigate) {
      logger.info('VALUES:NAV', 'User navigated to [m] Modules');
      onNavigate('modules');
      return;
    }

    // [q] or [Esc] -> Return / Exit
    if (keyChar === 'q' || key.escape) {
      logger.info('VALUES:NAV', 'User pressed [q/Esc] -> Returning to Dashboard / Exit');
      if (onNavigate) {
        onNavigate('dashboard');
      }
      return;
    }
  });

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: 'yellow' },
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Text,
        { bold: true, color: 'yellow' },
        '⚙️  HELM VALUES & CHART CONFIGURATION MANAGER'
      ),
      React.createElement(
        Text,
        { color: 'cyan' },
        `$EDITOR: ${editorName}`
      )
    ),
    React.createElement(
      Text,
      { color: 'gray', marginBottom: 1 },
      'Select a chart with ↑/↓ and press [e] or [Enter] to open in $EDITOR. Custom overrides are applied automatically during deploy.'
    ),

    // Feedback Toast inside view
    feedback
      ? React.createElement(
          Box,
          {
            marginY: 1,
            paddingX: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'success' ? 'green' : feedback.type === 'error' ? 'red' : 'cyan'
          },
          React.createElement(
            Text,
            { color: feedback.type === 'success' ? 'green' : feedback.type === 'error' ? 'red' : 'cyan', bold: true },
            feedback.text
          )
        )
      : null,

    // Chart selector list
    items.map((item, index) => {
      const isFocused = index === cursor;
      return React.createElement(
        Box,
        {
          key: `${item.moduleId}-${item.chartName}`,
          flexDirection: 'column',
          marginY: 0,
          paddingY: 0
        },
        React.createElement(
          Box,
          null,
          React.createElement(
            Text,
            { color: isFocused ? 'yellow' : 'gray', bold: isFocused },
            isFocused ? '❯ ' : '  '
          ),
          React.createElement(
            Text,
            { color: item.hasOverride ? 'green' : 'gray', bold: true },
            item.hasOverride ? '[✔ OVERRIDE ACTIVE] ' : '[○ DEFAULTS] '
          ),
          React.createElement(
            Text,
            { bold: true, color: isFocused ? 'yellow' : 'white' },
            `${item.moduleId} / ${item.chartName}`
          ),
          React.createElement(
            Text,
            { color: 'gray', marginLeft: 2 },
            `→ ${item.targetOverrideRel}`
          )
        ),
        React.createElement(
          Box,
          { marginLeft: 4, marginBottom: 1 },
          React.createElement(
            Text,
            { color: isFocused ? 'white' : 'gray' },
            item.description
          )
        )
      );
    }),

    // Action Item: Export All Starter Templates
    React.createElement(
      Box,
      { marginTop: 0, flexDirection: 'row' },
      React.createElement(
        Text,
        { color: isExportAction ? 'yellow' : 'gray', bold: isExportAction },
        isExportAction ? '❯ ' : '  '
      ),
      React.createElement(
        Text,
        { bold: true, color: isExportAction ? 'yellow' : 'cyan' },
        '📦 [x] Export All Starter Values Templates to ./values/'
      )
    ),

    // Footer Help Hints
    React.createElement(
      Box,
      {
        marginTop: 1,
        paddingTop: 1,
        borderStyle: 'single',
        borderColor: 'gray',
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: 'yellow', bold: true }, '[e]/[Enter] '),
        React.createElement(Text, { color: 'white' }, `Edit in ${editorName}  `),
        React.createElement(Text, { color: 'cyan', bold: true }, '[x] '),
        React.createElement(Text, { color: 'white' }, 'Export All  '),
        React.createElement(Text, { color: 'gray' }, '| [s] Status  [u] Up  [q] Return')
      ),
      React.createElement(
        Text,
        { color: 'gray', dimColor: true },
        'Use ↑/↓ or j/k to navigate'
      )
    )
  );
};

function getChartDescription(moduleId, chartName) {
  if (chartName === 'opensearch') {
    return 'OpenSearch SIEM core cluster (JVM heap, singleNode, memory & CPU resources)';
  }
  if (chartName === 'opensearch-dashboards') {
    return 'OpenSearch Dashboards UI (Ingress TLS host, plugins, and web resources)';
  }
  return `Customizable Helm values for ${moduleId}/${chartName}`;
}
