import { spawnSync } from 'node:child_process';
import { logger } from './logger.js';

/**
 * Execute an interactive terminal callback while safely suspending and restoring Ink TTY raw mode
 * @param {Function} callback
 */
export function runInteractiveTerminal(callback) {
  const wasRaw = process.stdin.isRaw;

  // 1. Temporarily release TTY control to child process
  if (process.stdin.setRawMode) {
    process.stdin.setRawMode(false);
  }
  // Turn off SGR mouse tracking and clear screen for interactive app
  process.stdout.write('\x1b[?1000l\x1b[?1006l\x1b[2J\x1b[H');

  try {
    callback();
  } catch (err) {
    logger.error('TERMINAL:EXEC', `Interactive terminal execution error: ${err.message}`, err);
  } finally {
    // 2. Restore TTY state for Ink
    process.stdout.write('\x1b[2J\x1b[H');
    if (process.stdin.setRawMode && wasRaw) {
      process.stdin.setRawMode(true);
    }
    if (process.stdin.resume) {
      process.stdin.resume();
    }
    // Re-enable SGR mouse tracking
    process.stdout.write('\x1b[?1000h\x1b[?1006h');
  }
}
