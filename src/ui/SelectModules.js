import React, { useState } from 'react';
import { Box, Text, useInput } from 'ink';

export const SelectModules = ({ modules = [], onConfirm, initialSelected = [] }) => {
  const [cursor, setCursor] = useState(0);
  const [selected, setSelected] = useState(() => {
    if (initialSelected.length > 0) {
      return new Set(initialSelected);
    }
    // Default select modules that are defaultEnabled
    return new Set(modules.filter(m => m.defaultEnabled).map(m => m.id));
  });

  useInput((input, key) => {
    if (key.upArrow) {
      setCursor(c => (c > 0 ? c - 1 : modules.length - 1));
    } else if (key.downArrow) {
      setCursor(c => (c < modules.length - 1 ? c + 1 : 0));
    } else if (input === ' ') {
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
    } else if (key.return) {
      // Confirm selection
      if (onConfirm) {
        onConfirm(Array.from(selected));
      }
    }
  });

  return React.createElement(
    Box,
    { flexDirection: 'column', marginY: 1, borderStyle: 'round', borderColor: 'blue', padding: 1 },
    React.createElement(
      Text,
      { bold: true, color: 'cyan' },
      '📦 Select Security Packages to Deploy:'
    ),
    React.createElement(
      Text,
      { color: 'gray', marginBottom: 1 },
      'Use ↑/↓ arrows to navigate, [Space] to toggle, [Enter] to confirm.'
    ),
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
            { color: isFocused ? 'cyan' : 'gray', bold: isFocused },
            isFocused ? '❯ ' : '  '
          ),
          React.createElement(
            Text,
            { color: isChecked ? 'green' : 'gray', bold: isChecked },
            isChecked ? '[✔] ' : '[ ] '
          ),
          React.createElement(
            Text,
            { bold: true, color: isFocused ? 'yellow' : isChecked ? 'white' : 'gray' },
            mod.name
          ),
          React.createElement(
            Text,
            { color: 'magenta' },
            ` (${mod.category})`
          )
        ),
        React.createElement(
          Box,
          { marginLeft: 6 },
          React.createElement(
            Text,
            { color: 'gray' },
            mod.description
          )
        )
      );
    }),
    React.createElement(
      Box,
      { marginTop: 1 },
      React.createElement(
        Text,
        { color: 'green', bold: true },
        `Press [Enter] to deploy ${selected.size} selected package(s)`
      )
    )
  );
};
