import React, { useState, useEffect, useCallback, useRef, createContext, useContext } from 'react';
import { Box, Text, useInput } from 'ink';
import { copyToClipboard } from '../utils/clipboard.js';

export const ClipboardContext = createContext({
  copiedToast: null,
  copyPane: () => {},
  registerPanes: () => {}
});

export const useClipboard = () => useContext(ClipboardContext);

/**
 * Strip ANSI escape codes for clean text copying
 */
export function stripAnsi(str) {
  if (typeof str !== 'string') return '';
  return str.replace(/\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])/g, '');
}

/**
 * Clipboard Provider that manages mouse click tracking and copy notifications
 */
export const ClipboardProvider = ({ children, isInteractive = true }) => {
  const [copiedToast, setCopiedToast] = useState(null);
  const panesRef = useRef([]);

  // Clear toast after timeout
  useEffect(() => {
    if (!copiedToast) return;
    const timer = setTimeout(() => {
      setCopiedToast(null);
    }, 2500);
    return () => clearTimeout(timer);
  }, [copiedToast]);

  const copyPane = useCallback(async (paneOrText, title = 'Selection') => {
    let textToCopy = '';
    let paneTitle = title;

    if (typeof paneOrText === 'string') {
      textToCopy = paneOrText;
    } else if (paneOrText && typeof paneOrText.getText === 'function') {
      textToCopy = paneOrText.getText();
      paneTitle = paneOrText.title || title;
    } else if (paneOrText && paneOrText.text) {
      textToCopy = paneOrText.text;
      paneTitle = paneOrText.title || title;
    }

    const cleanText = stripAnsi(textToCopy).trim();
    if (!cleanText) return;

    await copyToClipboard(cleanText);
    setCopiedToast({
      title: paneTitle,
      text: cleanText.length > 40 ? cleanText.substring(0, 37) + '...' : cleanText,
      timestamp: Date.now()
    });
  }, []);

  const registerPanes = useCallback((newPanes) => {
    panesRef.current = newPanes || [];
  }, []);

  // Enable/disable SGR mouse tracking in interactive terminal mode
  useEffect(() => {
    if (!isInteractive || !process.stdin.isTTY || !process.stdout.isTTY) {
      return;
    }

    // Enable normal tracking (1000) and SGR extended mode (1006)
    try {
      process.stdout.write('\x1b[?1000h\x1b[?1006h');
    } catch {
      // Ignore
    }

    const handleData = (chunk) => {
      const str = chunk.toString();
      // Match SGR mouse sequence: \x1b[<button;col;rowM (press) or m (release)
      const regex = /\x1b\[<(\d+);(\d+);(\d+)([Mm])/g;
      let match;

      while ((match = regex.exec(str)) !== null) {
        const button = parseInt(match[1], 10);
        const col = parseInt(match[2], 10);
        const row = parseInt(match[3], 10);
        const type = match[4];

        // Left button down event
        if (button === 0 && type === 'M') {
          const currentPanes = panesRef.current || [];
          if (currentPanes.length === 0) return;

          let matched = false;
          for (const pane of currentPanes) {
            if (pane.startRow && pane.endRow) {
              if (row >= pane.startRow && row <= pane.endRow) {
                copyPane(pane);
                matched = true;
                break;
              }
            }
          }

          // Fallback: If click was outside strict row bounds, prioritize active error/logs/focused pane
          if (!matched) {
            const prioritizedPane = currentPanes.find(p => p.id === 'fatal-error' || p.id === 'logs' || p.id === 'tasks') || currentPanes[0];
            if (prioritizedPane) {
              copyPane(prioritizedPane);
            }
          }
        }
      }
    };

    process.stdin.on('data', handleData);

    const cleanup = () => {
      try {
        process.stdin.removeListener('data', handleData);
        if (process.stdout.isTTY) {
          process.stdout.write('\x1b[?1000l\x1b[?1006l');
        }
      } catch {
        // Ignore
      }
    };

    process.on('exit', cleanup);

    return () => {
      cleanup();
      process.removeListener('exit', cleanup);
    };
  }, [isInteractive, copyPane]);

  // Keyboard shortcut support: Press number keys 1-9 or 'c' to copy corresponding pane
  useInput((input, key) => {
    if (!isInteractive) return;

    const currentPanes = panesRef.current || [];
    if (currentPanes.length === 0) return;

    // Number key 1-9
    const num = parseInt(input, 10);
    if (!isNaN(num) && num >= 1 && num <= currentPanes.length) {
      const targetPane = currentPanes[num - 1];
      if (targetPane) {
        copyPane(targetPane);
      }
    } else if (input === 'c' && !key.ctrl) {
      // Copy highest priority pane (error, logs, endpoints, or first)
      const primaryPane = currentPanes.find(p => p.id === 'fatal-error' || p.id === 'logs' || p.id === 'all' || p.id === 'endpoints') || currentPanes[0];
      if (primaryPane) {
        copyPane(primaryPane);
      }
    }
  });

  return React.createElement(
    ClipboardContext.Provider,
    { value: { copiedToast, copyPane, registerPanes } },
    children
  );
};

/**
 * Toast Notification banner shown when a pane is copied
 */
export const ToastBanner = ({ toast }) => {
  if (!toast) return null;

  return React.createElement(
    Box,
    {
      marginTop: 1,
      paddingX: 2,
      paddingY: 0,
      borderStyle: 'round',
      borderColor: 'green',
      backgroundColor: 'black'
    },
    React.createElement(
      Text,
      { color: 'green', bold: true },
      '📋 Copied to Clipboard: '
    ),
    React.createElement(
      Text,
      { color: 'cyan', bold: true },
      `[${toast.title}] `
    ),
    React.createElement(
      Text,
      { color: 'gray' },
      toast.text
    )
  );
};
