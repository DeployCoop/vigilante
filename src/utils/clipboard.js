import { spawn } from 'node:child_process';

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

  try {
    if (isLinux) {
      if (process.env.WAYLAND_DISPLAY) {
        const child = spawn('wl-copy', [text], { stdio: 'ignore', detached: true });
        child.unref();
        success = true;
      } else if (process.env.DISPLAY) {
        const child = spawn('xclip', ['-selection', 'clipboard'], { stdio: ['pipe', 'ignore', 'ignore'], detached: true });
        child.stdin.end(text);
        child.unref();
        success = true;
      }
    } else if (isMac) {
      const child = spawn('pbcopy', [], { stdio: ['pipe', 'ignore', 'ignore'], detached: true });
      child.stdin.end(text);
      child.unref();
      success = true;
    } else if (isWin) {
      const child = spawn('clip.exe', [], { stdio: ['pipe', 'ignore', 'ignore'], detached: true });
      child.stdin.end(text);
      child.unref();
      success = true;
    }
  } catch {
    // Fallback to OSC 52 result
  }

  return success;
}
