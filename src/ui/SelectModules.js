import React, { useState, useEffect } from 'react';
import { Box, Text, useInput } from 'ink';
import { useTheme } from './theme.js';
import {
  getVigilLocalChartPath,
  setVigilLocalChartPath,
  validateVigilLocalChartPathSync,
  resolvePathWithHome
} from '../engine/config.js';
import { logger } from '../utils/logger.js';

export const SelectModules = ({
  modules = [],
  onConfirm,
  onNamespaceChange = null,
  onNavigate = null,
  initialSelected = [],
  namespace = 'default'
}) => {
  const theme = useTheme();
  const [cursor, setCursor] = useState(0);
  const [currentNamespace, setCurrentNamespace] = useState(namespace || 'default');
  const [isEditingNamespace, setIsEditingNamespace] = useState(false);
  const [namespaceInput, setNamespaceInput] = useState(namespace || 'default');

  const [isEditingVigilPath, setIsEditingVigilPath] = useState(false);
  const [vigilChartPath, setVigilChartPath] = useState(() => getVigilLocalChartPath());
  const [vigilPathInput, setVigilPathInput] = useState(() => getVigilLocalChartPath());
  const [feedback, setFeedback] = useState(null);

  const [selected, setSelected] = useState(() => {
    if (initialSelected && initialSelected.length > 0) {
      return new Set(initialSelected);
    }
    // Default select modules that are defaultEnabled
    return new Set(modules.filter(m => m.defaultEnabled).map(m => m.id));
  });

  // Sync if parent updates namespace prop
  useEffect(() => {
    if (namespace && namespace !== currentNamespace && !isEditingNamespace) {
      setCurrentNamespace(namespace);
      setNamespaceInput(namespace);
    }
  }, [namespace]);

  useInput((input, key) => {
    // Mode A: Editing Target Namespace Prompt
    if (isEditingNamespace) {
      if (key.return) {
        // Confirm new namespace
        const cleanNs = namespaceInput.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-') || 'default';
        setCurrentNamespace(cleanNs);
        setIsEditingNamespace(false);
        setFeedback({
          type: 'success',
          text: `✔ Target namespace switched to '${cleanNs}'.`
        });
        if (onNamespaceChange) {
          onNamespaceChange(cleanNs);
        }
        return;
      }

      if (key.escape) {
        // Cancel namespace editing
        setNamespaceInput(currentNamespace);
        setIsEditingNamespace(false);
        return;
      }

      if (key.backspace || key.delete) {
        setNamespaceInput(prev => prev.slice(0, -1));
        return;
      }

      // Append alphanumeric and hyphen characters
      if (input && input.length === 1 && /[a-zA-Z0-9_-]/.test(input)) {
        setNamespaceInput(prev => prev + input);
        return;
      }

      return;
    }

    // Mode B: Editing Local Vigil Development Helm Chart Path
    if (isEditingVigilPath) {
      if (key.return) {
        const cleanPath = (vigilPathInput || '').trim();
        if (!cleanPath) {
          setFeedback({
            type: 'error',
            text: '✖ Local Vigil chart path cannot be empty.'
          });
          return;
        }

        const resolved = resolvePathWithHome(cleanPath);
        setVigilLocalChartPath(resolved).then(() => {
          setVigilChartPath(resolved);
          setIsEditingVigilPath(false);
          const validation = validateVigilLocalChartPathSync(resolved);
          if (validation.valid) {
            setFeedback({
              type: 'success',
              text: `✔ Local Vigil chart path updated to '${resolved}' (Chart.yaml verified). Saved to config.yaml.`
            });
          } else if (validation.dirExists) {
            setFeedback({
              type: 'warning',
              text: `⚠ Local Vigil chart path saved to '${resolved}', but Chart.yaml was not found in directory.`
            });
          } else {
            setFeedback({
              type: 'warning',
              text: `⚠ Local Vigil chart path saved to '${resolved}', but directory does not currently exist.`
            });
          }
        }).catch(err => {
          logger.error('SELECT_MODULES:PATH', `Failed to save chart path: ${err.message}`, err);
          setFeedback({
            type: 'error',
            text: `✖ Failed to save chart path: ${err.message}`
          });
        });
        return;
      }

      if (key.escape) {
        setVigilPathInput(vigilChartPath);
        setIsEditingVigilPath(false);
        return;
      }

      if (key.backspace || key.delete) {
        setVigilPathInput(prev => prev.slice(0, -1));
        return;
      }

      if (input && input.length === 1 && !key.ctrl && !key.meta) {
        setVigilPathInput(prev => prev + input);
        return;
      }

      return;
    }

    // Mode C: Normal Select Modules Navigation
    if (key.tab) {
      if (onNavigate) {
        onNavigate('menu');
      }
      return;
    }

    const keyChar = (input || '').toLowerCase();

    // [n] or [N] -> Open Target Namespace Switcher
    if (keyChar === 'n') {
      setIsEditingNamespace(true);
      setNamespaceInput(currentNamespace);
      setFeedback(null);
      return;
    }

    // [p] or [P] -> Trigger Local Vigil Chart Path Editor Prompt
    if (keyChar === 'p') {
      const currentPath = getVigilLocalChartPath();
      setVigilChartPath(currentPath);
      setVigilPathInput(currentPath);
      setIsEditingVigilPath(true);
      setFeedback(null);
      return;
    }

    if (key.upArrow || keyChar === 'k') {
      setCursor(c => (c > 0 ? c - 1 : modules.length - 1));
      return;
    }

    if (key.downArrow || keyChar === 'j') {
      setCursor(c => (c < modules.length - 1 ? c + 1 : 0));
      return;
    }

    if (input === ' ') {
      // Toggle current module
      const currentMod = modules[cursor];
      if (currentMod) {
        setSelected(prev => {
          const next = new Set(prev);
          if (next.has(currentMod.id)) {
            next.delete(currentMod.id);
          } else {
            next.add(currentMod.id);
          }
          return next;
        });
      }
      return;
    }

    if (key.return) {
      // Confirm selection
      if (onConfirm) {
        onConfirm(Array.from(selected), currentNamespace);
      }
    }
  });

  return React.createElement(
    Box,
    { flexDirection: 'column', marginY: 1, borderStyle: 'round', borderColor: theme.border || 'cyan', padding: 1 },

    // Header
    React.createElement(
      Box,
      { justifyContent: 'space-between', marginBottom: 1 },
      React.createElement(
        Box,
        null,
        React.createElement(
          Text,
          { bold: true, color: theme.header || theme.primary },
          '📦 SELECT SECURITY PACKAGES TO DEPLOY '
        ),
        React.createElement(
          Text,
          { color: theme.warning || 'yellow', bold: true },
          `[Target NS: ${currentNamespace}]`
        )
      ),
      React.createElement(
        Text,
        { color: theme.accent || 'cyan' },
        `${selected.size} of ${modules.length} Selected`
      )
    ),

    // Path Editor Prompt (when user hits 'p')
    isEditingVigilPath
      ? React.createElement(
          Box,
          {
            marginY: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.secondary || 'magenta',
            flexDirection: 'column'
          },
          React.createElement(
            Box,
            null,
            React.createElement(
              Text,
              { color: theme.secondary || 'magenta', bold: true },
              '📁 Set Local Development Vigil Helm Chart Path: '
            ),
            React.createElement(
              Text,
              { color: theme.accent || 'cyan', bold: true, underline: true },
              vigilPathInput
            ),
            React.createElement(
              Text,
              { color: theme.primary || 'green' },
              ' █'
            )
          ),
          React.createElement(
            Box,
            { marginTop: 1 },
            (() => {
              const val = validateVigilLocalChartPathSync(vigilPathInput);
              if (val.valid) {
                return React.createElement(
                  Text,
                  { color: theme.success || 'green', bold: true },
                  `✔ Valid Helm Chart: Chart.yaml verified at ${val.resolvedPath}`
                );
              }
              if (val.dirExists) {
                return React.createElement(
                  Text,
                  { color: theme.warning || 'yellow' },
                  `⚠ Directory exists, but Chart.yaml was not found at ${val.resolvedPath}`
                );
              }
              return React.createElement(
                Text,
                { color: theme.muted || 'gray' },
                `○ Path: ${val.resolvedPath} (Directory not found yet)`
              );
            })()
          ),
          React.createElement(
            Text,
            { color: theme.muted || 'gray', marginTop: 1 },
            'Type the directory path containing Chart.yaml. Press [Enter] to save to config.yaml, or [Esc] to cancel.'
          )
        )
      : isEditingNamespace
      ? React.createElement(
          Box,
          {
            marginY: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.warning || 'yellow',
            flexDirection: 'column'
          },
          React.createElement(
            Box,
            null,
            React.createElement(
              Text,
              { color: theme.warning || 'yellow', bold: true },
              '🏷️  Set Target Kubernetes Namespace: '
            ),
            React.createElement(
              Text,
              { color: theme.accent || 'cyan', bold: true, underline: true },
              namespaceInput
            ),
            React.createElement(
              Text,
              { color: theme.primary || 'green' },
              ' █'
            )
          ),
          React.createElement(
            Text,
            { color: theme.muted || 'gray', marginTop: 1 },
            'Type the target namespace name and press [Enter] to confirm, or [Esc] to cancel.'
          )
        )
      : React.createElement(
          Box,
          { justifyContent: 'space-between', marginBottom: 1 },
          React.createElement(
            Text,
            { color: theme.muted || 'gray' },
            'Use ↑/↓ to navigate, [Space] to toggle, [p] to set local Vigil path, [n] to change NS, [Enter] to deploy.'
          ),
          React.createElement(
            Box,
            null,
            React.createElement(
              Text,
              { color: theme.secondary || 'magenta', marginRight: 2 },
              '[p] Vigil Path'
            ),
            React.createElement(
              Text,
              { color: theme.warning || 'yellow' },
              '[n] Switch NS'
            )
          )
        ),

    // Feedback message
    feedback
      ? React.createElement(
          Box,
          {
            marginY: 1,
            paddingX: 1,
            borderStyle: 'single',
            borderColor: feedback.type === 'success' ? (theme.success || 'green') : feedback.type === 'error' ? (theme.error || 'red') : (theme.accent || 'cyan')
          },
          React.createElement(
            Text,
            { color: feedback.type === 'success' ? (theme.success || 'green') : feedback.type === 'error' ? (theme.error || 'red') : (theme.accent || 'cyan'), bold: true },
            feedback.text
          )
        )
      : null,

    // Modules list
    modules.map((mod, index) => {
      const isFocused = index === cursor;
      const isChecked = selected.has(mod.id);

      return React.createElement(
        Box,
        { key: mod.id, flexDirection: 'column', marginY: 0 },
        React.createElement(
          Box,
          null,
          React.createElement(
            Text,
            { color: isFocused ? (theme.accent || 'cyan') : (theme.muted || 'gray'), bold: isFocused },
            isFocused ? '❯ ' : '  '
          ),
          React.createElement(
            Text,
            { color: isChecked ? (theme.success || 'green') : (theme.muted || 'gray'), bold: isChecked },
            isChecked ? '[✔] ' : '[ ] '
          ),
          React.createElement(
            Text,
            { bold: true, color: isFocused ? (theme.accent || 'yellow') : isChecked ? (theme.text || 'white') : (theme.muted || 'gray') },
            mod.name
          ),
          React.createElement(
            Text,
            { color: theme.secondary || 'magenta', marginLeft: 1 },
            `(${mod.category})`
          )
        ),
        React.createElement(
          Box,
          { marginLeft: 6 },
          React.createElement(
            Text,
            { color: isFocused ? (theme.text || 'white') : (theme.muted || 'gray') },
            mod.description
          )
        ),
        mod.id === 'vigil-local' || mod.chartPath
          ? React.createElement(
              Box,
              { marginLeft: 6, marginTop: 0, flexDirection: 'column' },
              React.createElement(
                Box,
                null,
                React.createElement(
                  Text,
                  { color: theme.secondary || 'magenta', bold: true },
                  '↳ Local Chart Path: '
                ),
                React.createElement(
                  Text,
                  { color: theme.accent || 'cyan' },
                  vigilChartPath
                ),
                React.createElement(
                  Text,
                  {
                    color: validateVigilLocalChartPathSync(vigilChartPath).valid
                      ? (theme.success || 'green')
                      : (theme.warning || 'yellow'),
                    marginLeft: 1,
                    bold: true
                  },
                  validateVigilLocalChartPathSync(vigilChartPath).valid
                    ? '[✔ Chart.yaml Found]'
                    : '[⚠ Chart.yaml Missing]'
                ),
                isFocused
                  ? React.createElement(
                      Text,
                      { color: theme.warning || 'yellow', marginLeft: 1 },
                      '(Press [p] to edit path)'
                    )
                  : null
              )
            )
          : null
      );
    }),

    // Confirmation action banner
    React.createElement(
      Box,
      {
        marginTop: 1,
        paddingTop: 1,
        borderStyle: 'single',
        borderColor: theme.border || 'gray',
        justifyContent: 'space-between'
      },
      React.createElement(
        Box,
        null,
        React.createElement(Text, { color: theme.accent || 'cyan', bold: true }, '[Space] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Toggle  '),
        React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, '[n] '),
        React.createElement(Text, { color: theme.text || 'white' }, `Namespace (${currentNamespace})  `),
        React.createElement(Text, { color: theme.secondary || 'magenta', bold: true }, '[p] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Vigil Path  '),
        React.createElement(Text, { color: theme.accent || 'blue', bold: true }, '[Tab] '),
        React.createElement(Text, { color: theme.text || 'white' }, 'Menu Hub  '),
        React.createElement(Text, { color: theme.success || 'green', bold: true }, '[Enter] '),
        React.createElement(Text, { color: theme.text || 'white' }, `Deploy to '${currentNamespace}'`)
      ),
      React.createElement(
        Text,
        { color: theme.muted || 'gray', dimColor: true },
        'Use ↑/↓ to navigate'
      )
    )
  );
};

