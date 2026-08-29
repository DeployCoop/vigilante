/**
 * Terminal Screen Buffer & Cursor Lifecycle Manager
 * Provides alternate screen buffer, cursor hiding, and safe signal cleanup to eliminate terminal flicker.
 */

let isAlternateScreenActive = false;
let isCursorHidden = false;
let isLifecycleRegistered = false;

/**
 * Check if output is an interactive TTY
 * @returns {boolean}
 */
export function isInteractiveTty() {
  return Boolean(process.stdout && process.stdout.isTTY && !process.env.CI);
}

/**
 * Enter the terminal's alternate screen buffer (smcup) and clear screen
 */
export function enterAlternateScreen() {
  if (!isInteractiveTty() || isAlternateScreenActive) return;
  try {
    // \x1b[?1049h : Enter alternate screen buffer
    // \x1b[?25l   : Hide terminal cursor to prevent jumping cursor artifacts
    // \x1b[H      : Move cursor to home position (0, 0)
    process.stdout.write('\x1b[?1049h\x1b[?25l\x1b[H');
    isAlternateScreenActive = true;
    isCursorHidden = true;
  } catch {
    // Ignore in non-standard streams
  }
}

/**
 * Leave the alternate screen buffer (rmcup) and restore cursor
 */
export function leaveAlternateScreen() {
  if (!isInteractiveTty() || !isAlternateScreenActive) return;
  try {
    // \x1b[?25h   : Show terminal cursor
    // \x1b[?1049l : Exit alternate screen buffer back to primary scrollback
    process.stdout.write('\x1b[?25h\x1b[?1049l');
    isAlternateScreenActive = false;
    isCursorHidden = false;
  } catch {
    // Ignore in non-standard streams
  }
}

/**
 * Explicitly hide terminal cursor
 */
export function hideCursor() {
  if (!isInteractiveTty() || isCursorHidden) return;
  try {
    process.stdout.write('\x1b[?25l');
    isCursorHidden = true;
  } catch {
    // Ignore
  }
}

/**
 * Explicitly show terminal cursor
 */
export function showCursor() {
  if (!isInteractiveTty() || !isCursorHidden) return;
  try {
    process.stdout.write('\x1b[?25h');
    isCursorHidden = false;
  } catch {
    // Ignore
  }
}

/**
 * Register exit hooks to guarantee terminal screen and cursor are always restored
 */
export function setupTerminalLifecycle() {
  if (isLifecycleRegistered) return;
  isLifecycleRegistered = true;

  const cleanup = () => {
    leaveAlternateScreen();
    showCursor();
  };

  process.on('exit', cleanup);
  process.on('SIGINT', () => {
    cleanup();
    process.exit(130);
  });
  process.on('SIGTERM', () => {
    cleanup();
    process.exit(143);
  });
  process.on('uncaughtException', (err) => {
    cleanup();
    console.error('Fatal unhandled error:', err);
    process.exit(1);
  });
}
