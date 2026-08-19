import React, { useState, useEffect, useCallback, memo } from 'react';
import { Box, Text, useInput } from 'ink';
import path from 'node:path';
import fs from 'node:fs';
import { listChartValues, exportStarterValues } from '../engine/helm.js';
import { openInEditor, ensureOverrideFileExists } from '../utils/editor.js';
import { getVigilanteConfigFile, getVigilanteValuesDir, ensureVigilanteConfig } from '../engine/config.js';
import { useClipboard } from './ClipboardManager.js';
import { useTheme } from './theme.js';
import { logger } from '../utils/logger.js';

export const ValuesView = memo(function ValuesView({
  domain = 'vigilante.local',
  customValuesDir = null,
  onNavigate = null
}) => {
  const theme = useTheme();
  const [items, setItems] = useState([]);
  const [cursor, setCursor] = useState(0);
  const [feedback, setFeedback] = useState(null);
  const [editorName] = useState(
    process.env.VISUAL || process.env.EDITOR || (process.platform === 'win32' ? 'notepad' : 'nano')
  );
  const { registerPanes } = useClipboard();

  const loadChartItems = useCallback(async () => {
    try {
      await ensureVigilanteConfig();
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
          const configFile = getVigilanteConfigFile();
          const xdgDir = getVigilanteValuesDir();
          const lines = [
            `Global Config File: ${configFile}`,
            `XDG Values Directory: ${xdgDir}`,
            '',
            ...items.map(
              (item) =>
                `• ${item.moduleId} / ${item.chartName}\n  Status: ${item.hasOverride ? 'Active Override (' + item.targetOverrideRel + ')' : 'Default Template'}\n  Template: ${item.defaultPath}\n  XDG Path: ${item.xdgPath || 'N/A'}`
            )
          ];
          return lines.join('\n\n');
        }
      }
    ]);
  }, [items, registerPanes]);

  // Total selectable items = chart items + 3 action items (Global Config, Export Local, Export XDG)
  const isConfigAction = cursor === items.length;
  const isExportLocalAction = cursor === items.length + 1;
  const isExportXdgAction = cursor === items.length + 2;
  const totalOptions = items.length + 3;

  const handleEditChart = async (item) => {
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

  const handleEditConfig = async () => {
    try {
      await ensureVigilanteConfig();
      const configFile = getVigilanteConfigFile();
      setFeedback({ type: 'info', text: `Opening ${configFile} in $EDITOR (${editorName})...` });
      logger.info('CONFIG:EDIT', `User triggered edit for config.yaml`);

      const res = openInEditor(configFile);
      await loadChartItems();

      if (res.success) {
        setFeedback({
          type: 'success',
          text: `✔ Saved ${configFile}! Theme & configuration updated.`
        });
      } else if (res.error) {
        setFeedback({ type: 'error', text: `✖ Editor error: ${res.error}` });
      }
    } catch (err) {
      logger.error('CONFIG:EDIT:ERROR', err.message, err);
      setFeedback({ type: 'error', text: `✖ Failed to edit config.yaml: ${err.message}` });
    }
  };

  const handleExportLocal = async () => {
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

  const handleExportXdg = async () => {
    try {
      const xdgDir = getVigilanteValuesDir();
      setFeedback({ type: 'info', text: `Exporting global starter templates to '${xdgDir}'...` });
      logger.info('VALUES:EXPORT:XDG', `Exporting all templates to ${xdgDir}`);

      const exported = await exportStarterValues({
        useXdg: true,
        domain
      });
      await loadChartItems();
      setFeedback({
        type: 'success',
        text: `✔ Exported ${exported.length} global starter YAML files to '${xdgDir}'!`
      });
    } catch (err) {
      logger.error('VALUES:EXPORT:XDG:ERROR', err.message, err);
      setFeedback({ type: 'error', text: `✖ Global export failed: ${err.message}` });
    }
  };

  // Keyboard navigation & editor trigger
  useInput(async (input, key) => {
    logger.debug('VALUES:KEY', `Key in ValuesView: input="${input}", key=${JSON.stringify(key)}`);
    const keyChar = (input || '').toLowerCase();

    if (key.upArrow || keyChar === 'k') {
      setCursor((c) => (c > 0 ? c - 1 : totalOptions - 1));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setCursor((c) => (c < totalOptions - 1 ? c + 1 : 0));
      return;
    }

    // [e] or [Enter] -> Trigger Selected Action
    if (keyChar === 'e' || key.return) {
      if (isConfigAction) {
        await handleEditConfig();
      } else if (isExportLocalAction) {
        await handleExportLocal();
      } else if (isExportXdgAction) {
        await handleExportXdg();
      } else {
        const item = items[cursor];
        if (item) {
          await handleEditChart(item);
        }
      }
      return;
    }

    // [c] -> Quick edit config.yaml
    if (keyChar === 'c') {
      await handleEditConfig();
      return;
    }

    // [x] -> Quick export local
    if (keyChar === 'x') {
      await handleExportLocal();
      return;
    }

    // [g] -> Quick export to XDG
    if (keyChar === 'g') {
      await handleExportXdg();
      return;
    }

    // Navigation delegates
    if (keyChar === 's' && onNavigate) {
      onNavigate('status');
      return;
    }
    if (keyChar === 'u' && onNavigate) {
      onNavigate('up');
      return;
    }
    if (keyChar === 'd' && onNavigate) {
      onNavigate('down');
      return;
    }
    if (keyChar === 't' && onNavigate) {
      onNavigate('threat-sim');
      return;
    }
    if (keyChar === 'h' && onNavigate) {
      onNavigate('hostr');
      return;
    }
    if (keyChar === 'm' && onNavigate) {
      onNavigate('modules');
      return;
    }
    if (keyChar === 'p' && onNavigate) {
      onNavigate('pods');
      return;
    }

    // [q] or [Esc] -> Return / Exit
    if (keyChar === 'q' || key.escape) {
      if (onNavigate) {
        onNavigate('dashboard');
      }
      return;
    }
  });

  return React.createElement(
    Box,
    { flexDirection: 'column', padding: 1, borderStyle: 'round', borderColor: theme.border },
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Text,
        { bold: true, color: theme.header || theme.accent },
        '⚙️  HELM VALUES & XDG CONFIGURATION MANAGER'
      ),
      React.createElement(
        Text,
        { color: theme.primary },
        `$EDITOR: ${editorName}`
      )
    ),
    React.createElement(
      Text,
      { color: theme.muted, marginBottom: 1 },
      'Select a chart or config file with ↑/↓ and press [e]/[Enter] to open in $EDITOR.'
    ),

    // Feedback Toast inside view
    feedback
      ? React.createElement(
          Box,
          {
            marginY: 1,
            paddingX: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'success' ? theme.success : feedback.type === 'error' ? theme.error : theme.info
          },
          React.createElement(
            Text,
            {
              color: feedback.type === 'success' ? theme.success : feedback.type === 'error' ? theme.error : theme.info,
              bold: true
            },
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
            { color: isFocused ? theme.accent : theme.muted, bold: isFocused },
            isFocused ? '❯ ' : '  '
          ),
          React.createElement(
            Text,
            { color: item.hasOverride ? theme.success : theme.muted, bold: true },
            item.hasOverride ? '[✔ OVERRIDE ACTIVE] ' : '[○ DEFAULTS] '
          ),
          React.createElement(
            Text,
            { bold: true, color: isFocused ? theme.accent : theme.text },
            `${item.moduleId} / ${item.chartName}`
          ),
          React.createElement(
            Text,
            { color: theme.muted, marginLeft: 2 },
            `→ ${item.targetOverrideRel}`
          )
        ),
        React.createElement(
          Box,
          { marginLeft: 4, marginBottom: 1 },
          React.createElement(
            Text,
            { color: isFocused ? theme.text : theme.muted },
            item.description
          )
        )
      );
    }),

    // Action 1: Edit Global config.yaml
    React.createElement(
      Box,
      { marginTop: 0, flexDirection: 'row' },
      React.createElement(
        Text,
        { color: isConfigAction ? theme.accent : theme.muted, bold: isConfigAction },
        isConfigAction ? '❯ ' : '  '
      ),
      React.createElement(
        Text,
        { bold: true, color: isConfigAction ? theme.accent : theme.primary },
        `⚙️  [c] Edit Global Config ($XDG_CONFIG_HOME/vigilante/config.yaml)`
      )
    ),

    // Action 2: Export All Local Starter Templates
    React.createElement(
      Box,
      { marginTop: 0, flexDirection: 'row' },
      React.createElement(
        Text,
        { color: isExportLocalAction ? theme.accent : theme.muted, bold: isExportLocalAction },
        isExportLocalAction ? '❯ ' : '  '
      ),
      React.createElement(
        Text,
        { bold: true, color: isExportLocalAction ? theme.accent : theme.primary },
        '📦 [x] Export Starter Values to Workspace (./values/)'
      )
    ),

    // Action 3: Export All Global XDG Starter Templates
    React.createElement(
      Box,
      { marginTop: 0, flexDirection: 'row' },
      React.createElement(
        Text,
        { color: isExportXdgAction ? theme.accent : theme.muted, bold: isExportXdgAction },
        isExportXdgAction ? '❯ ' : '  '
      ),
      React.createElement(
        Text,
        { bold: true, color: isExportXdgAction ? theme.accent : theme.secondary },
        '🌐 [g] Export Global Values to XDG ($XDG_CONFIG_HOME/vigilante/values/)'
      )
    ),

    // Footer Help Hints
    React.createElement(
      Box,
      {
        marginTop: 1,
        paddingTop: 1,
        borderStyle: 'single',
        borderColor: theme.muted,
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.accent, bold: true }, '[e]/[Enter] '),
        React.createElement(Text, { color: theme.text }, `Edit  `),
        React.createElement(Text, { color: theme.primary, bold: true }, '[c] '),
        React.createElement(Text, { color: theme.text }, 'Config  '),
        React.createElement(Text, { color: theme.info, bold: true }, '[x] '),
        React.createElement(Text, { color: theme.text }, 'Local Values  '),
        React.createElement(Text, { color: theme.secondary, bold: true }, '[g] '),
        React.createElement(Text, { color: theme.text }, 'XDG Values  '),
        React.createElement(Text, { color: theme.muted }, '| [s] Status  [q] Return')
      ),
      React.createElement(
        Text,
        { color: theme.muted, dimColor: true },
        'Use ↑/↓ or j/k to navigate'
      )
    )
  );
});

function getChartDescription(moduleId, chartName) {
  if (chartName === 'vigil') {
    return 'Vigil AI-Native SOC (Backend API, daemon orchestrator, LLM & agent workers, Postgres, Redis)';
  }
  if (chartName === 'opensearch') {
    return 'OpenSearch SIEM core cluster (JVM heap, singleNode, memory & CPU resources)';
  }
  if (chartName === 'opensearch-dashboards') {
    return 'OpenSearch Dashboards UI (Ingress TLS host, plugins, and web resources)';
  }
  return `Customizable Helm values for ${moduleId}/${chartName}`;
}
