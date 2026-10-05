import React, { useState, useEffect } from 'react';
import { Box, Text, useInput } from 'ink';
import { globalModuleRegistry } from '../modules/registry.js';
import { useTheme } from './theme.js';

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
  const [isEditingPath, setIsEditingPath] = useState(false);
  const [chartPathInput, setChartPathInput] = useState('');
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
    // Mode A: Editing Local Chart Path Prompt (for vigil-local)
    if (isEditingPath) {
      if (key.return) {
        const trimmed = chartPathInput.trim();
        setIsEditingPath(false);
        if (trimmed) {
          const vigilMod = globalModuleRegistry.get('vigil-local');
          if (vigilMod && typeof vigilMod.setChartPath === 'function') {
            vigilMod.setChartPath(trimmed).then((res) => {
              if (res.exists) {
                setFeedback({
                  type: 'success',
                  text: `✔ Local Vigil Helm chart path updated to '${res.path}' (Chart.yaml verified).`
                });
              } else {
                setFeedback({
                  type: 'warning',
                  text: `⚠ Local Vigil Helm chart path updated to '${res.path}' (Warning: Chart.yaml not found at location).`
                });
              }
            }).catch((err) => {
              setFeedback({
                type: 'error',
                text: `✖ Failed to update chart path: ${err.message}`
              });
            });
          }
        }
        return;
      }

      if (key.escape) {
        setIsEditingPath(false);
        return;
      }

      if (key.backspace || key.delete) {
        setChartPathInput(prev => prev.slice(0, -1));
        return;
      }

      // Append characters for path entry
      if (input && input.length === 1 && !key.ctrl && !key.meta) {
        setChartPathInput(prev => prev + input);
        return;
      }

      return;
    }

    // Mode B: Editing Target Namespace Prompt
    if (isEditingNamespace) {
      if (key.return) {
        // Confirm new namespace
        const cleanNs = namespaceInput.trim().toLowerCase().replace(/[^a-z0-9-]/g, '-') || 'default';
        setCurrentNamespace(cleanNs);
        setIsEditingNamespace(false);
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

    // Mode C: Normal Select Modules Navigation
    if (key.tab) {
      if (onNavigate) {
        onNavigate('menu');
      }
      return;
    }

    const keyChar = (input || '').toLowerCase();

    // [p] or [P] -> Trigger Local Vigil Chart Path Prompt if focused on vigil-local
    if (keyChar === 'p') {
      const currentMod = modules[cursor];
      if (currentMod && currentMod.id === 'vigil-local') {
        const vigilMod = globalModuleRegistry.get('vigil-local');
        const curPath = vigilMod?.getChartPath ? vigilMod.getChartPath() : '';
        setChartPathInput(curPath);
        setIsEditingPath(true);
        setFeedback(null);
        return;
      }
    }

    // [n] or [N] -> Open Target Namespace Switcher
    if (keyChar === 'n') {
      setIsEditingNamespace(true);
      setNamespaceInput(currentNamespace);
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

  const isCurrentVigilLocal = modules[cursor]?.id === 'vigil-local';

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

    // Local Chart Path Editor Prompt (when user hits 'p' on vigil-local)
    isEditingPath
      ? React.createElement(
          Box,
          {
            marginY: 1,
            padding: 1,
            borderStyle: 'double',
            borderColor: theme.accent || 'cyan',
            flexDirection: 'column'
          },
          React.createElement(
            Box,
            null,
            React.createElement(
              Text,
              { color: theme.accent || 'cyan', bold: true },
              '📁 Set Local Vigil Helm Chart Path: '
            ),
            React.createElement(
              Text,
              { color: theme.warning || 'yellow', bold: true, underline: true },
              chartPathInput
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
            'Type or paste the local chart directory path and press [Enter] to confirm, or [Esc] to cancel.'
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
              isCurrentVigilLocal
                ? 'Use ↑/↓ to navigate, [Space] to toggle, [p] to edit local chart path, [n] for namespace, [Enter] to deploy.'
                : 'Use ↑/↓ to navigate, [Space] to toggle, [n] to change target namespace, [Enter] to deploy.'
            ),
            React.createElement(
              Text,
              { color: theme.warning || 'yellow' },
              isCurrentVigilLocal ? 'Press [p] to edit chart path' : 'Press [n] to switch namespace'
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
            borderColor: feedback.type === 'success' ? (theme.success || 'green') : feedback.type === 'error' ? (theme.error || 'red') : (theme.warning || 'yellow')
          },
          React.createElement(
            Text,
            { color: feedback.type === 'success' ? (theme.success || 'green') : feedback.type === 'error' ? (theme.error || 'red') : (theme.warning || 'yellow'), bold: true },
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
        )
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
        isCurrentVigilLocal
          ? React.createElement(
              React.Fragment,
              null,
              React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, '[p] '),
              React.createElement(Text, { color: theme.text || 'white' }, 'Chart Path  ')
            )
          : null,
        React.createElement(Text, { color: theme.warning || 'yellow', bold: true }, '[n] '),
        React.createElement(Text, { color: theme.text || 'white' }, `Namespace (${currentNamespace})  `),
        React.createElement(Text, { color: theme.secondary || 'magenta', bold: true }, '[Tab] '),
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
