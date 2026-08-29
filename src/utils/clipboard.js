import { spawn } from 'node:child_process';

/**
 * Safely execute a clipboard CLI tool with stdin piping and ENOENT protection
 */
function trySpawnCopy(binary, args, text) {
  return new Promise((resolve) => {
    try {
      const child = spawn(binary, args, { stdio: ['pipe', 'ignore', 'ignore'], detached: true });
      let hasError = false;

      child.on('error', () => {
        hasError = true;
        resolve(false);
      });

      child.stdin.on('error', () => {
        hasError = true;
        resolve(false);
      });

      child.stdin.end(text, () => {
        if (!hasError) {
          child.unref();
          resolve(true);
        }
      });
    } catch {
      resolve(false);
    }
  });
}

/**
 * Copy text to system clipboard using native utilities and OSC 52 escape sequences
 * @param {string} text - Text to copy
 * @returns {Promise<boolean>}
 */
export async function copyToClipboard(text) {
  if (!text || typeof text !== 'string') return false;

  let success = false;

  // 1. Send OSC 52 ANSI escape sequence to stdout
  // Modern terminals (Kitty, Alacritty, iTerm2, WezTerm, Foot, Windows Terminal, Ghostty, etc.)
  // support this directly without needing external binaries.
  try {
    if (process.stdout && process.stdout.isTTY) {
      const base64 = Buffer.from(text, 'utf8').toString('base64');
      process.stdout.write(`\x1b]52;c;${base64}\x07`);
      success = true;
    }
  } catch {
    // Ignore OSC 52 write error
  }

  // 2. Native OS clipboard CLI fallbacks
  const isLinux = process.platform === 'linux';
  const isMac = process.platform === 'darwin';
  const isWin = process.platform === 'win32';

  if (isLinux) {
    // Try wl-copy (Wayland)
    if (process.env.WAYLAND_DISPLAY || !process.env.DISPLAY) {
      const wlRes = await trySpawnCopy('wl-copy', [], text);
      if (wlRes) success = true;
    }

    // Try xclip / xsel (X11 or XWayland)
    if (!success || process.env.DISPLAY) {
      const xclipRes = await trySpawnCopy('xclip', ['-selection', 'clipboard'], text);
      if (xclipRes) {
        success = true;
      } else {
        const xselRes = await trySpawnCopy('xsel', ['--clipboard', '--input'], text);
        if (xselRes) success = true;
      }
    }
  } else if (isMac) {
    const macRes = await trySpawnCopy('pbcopy', [], text);
    if (macRes) success = true;
  } else if (isWin) {
    const winRes = await trySpawnCopy('clip.exe', [], text);
    if (winRes) success = true;
  }

  return success;
}
