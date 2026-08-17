import React, { useState, useEffect } from 'react';
import { Box, Text, useInput } from 'ink';
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

    // Mode B: Normal Select Modules Navigation
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

    // Namespace Editor Prompt (when user hits 'N')
    isEditingNamespace
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
            'Use ↑/↓ to navigate, [Space] to toggle, [n] to change target namespace, [Enter] to deploy.'
          ),
          React.createElement(
            Text,
            { color: theme.warning || 'yellow' },
            'Press [n] to switch namespace'
          )
        ),

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
