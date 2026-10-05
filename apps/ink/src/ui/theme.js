import React, { createContext, useContext, useMemo } from 'react';
import { loadConfig } from '../engine/config.js';

export const THEMES = {
  default: {
    primary: 'cyan',
    secondary: 'magenta',
    accent: 'yellow',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    info: 'blue',
    muted: 'gray',
    border: 'cyan',
    text: 'white',
    header: 'cyan',
    selectedBg: 'gray',
    selectedText: 'yellow',
    banner: 'magenta'
  },
  cyberpunk: {
    primary: 'yellow',
    secondary: 'magenta',
    accent: 'cyan',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    info: 'cyan',
    muted: 'gray',
    border: 'magenta',
    text: 'white',
    header: 'yellow',
    selectedBg: 'magenta',
    selectedText: 'black',
    banner: 'yellow'
  },
  dracula: {
    primary: 'magenta',
    secondary: 'cyan',
    accent: 'green',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    info: 'cyan',
    muted: 'gray',
    border: 'magenta',
    text: 'white',
    header: 'magenta',
    selectedBg: 'gray',
    selectedText: 'magenta',
    banner: 'magenta'
  },
  nord: {
    primary: 'blue',
    secondary: 'cyan',
    accent: 'yellow',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    info: 'cyan',
    muted: 'gray',
    border: 'blue',
    text: 'white',
    header: 'cyan',
    selectedBg: 'gray',
    selectedText: 'cyan',
    banner: 'blue'
  },
  matrix: {
    primary: 'green',
    secondary: 'green',
    accent: 'green',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    info: 'green',
    muted: 'gray',
    border: 'green',
    text: 'green',
    header: 'green',
    selectedBg: 'gray',
    selectedText: 'green',
    banner: 'green'
  },
  monokai: {
    primary: 'yellow',
    secondary: 'red',
    accent: 'magenta',
    success: 'green',
    warning: 'yellow',
    error: 'red',
    info: 'cyan',
    muted: 'gray',
    border: 'yellow',
    text: 'white',
    header: 'yellow',
    selectedBg: 'gray',
    selectedText: 'yellow',
    banner: 'red'
  }
};

/**
 * Resolve theme colors by merging chosen named theme with custom color overrides
 * @param {Object} [customConfig]
 * @returns {Object} Theme color map
 */
export function resolveTheme(customConfig = null) {
  const config = customConfig || loadConfig();
  const themeName = (config.theme?.name || 'default').toLowerCase();
  const baseTheme = THEMES[themeName] || THEMES.default;
  const userColors = config.theme?.colors || {};

  return {
    name: themeName,
    ...baseTheme,
    ...userColors
  };
}

const ThemeContext = createContext(resolveTheme());

export const ThemeProvider = ({ children, customConfig = null }) => {
  const theme = useMemo(() => resolveTheme(customConfig), [customConfig]);

  return React.createElement(
    ThemeContext.Provider,
    { value: theme },
    children
  );
};

export const useTheme = () => {
  return useContext(ThemeContext);
};

export function getTheme() {
  return resolveTheme();
}
