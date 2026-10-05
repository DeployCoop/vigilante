import { spawnSync } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { logger } from './logger.js';
import { renderTemplate } from '../engine/helm.js';

/**
 * Ensure an override file exists before opening it in the editor.
 * If missing, copies and renders the default starter template.
 * @param {string} targetOverridePath - Path to user override file
 * @param {string} defaultTemplatePath - Path to default template
 * @param {Object} context - Template render variables (domain, etc.)
 */
export async function ensureOverrideFileExists(targetOverridePath, defaultTemplatePath, context = {}) {
  try {
    await fs.access(targetOverridePath);
    return false; // Already existed
  } catch {
    // Does not exist, create parent dir and write rendered starter
    const dir = path.dirname(targetOverridePath);
    await fs.mkdir(dir, { recursive: true });

    let content = '# Custom Helm Values Override\n';
    try {
      const raw = await fs.readFile(defaultTemplatePath, 'utf8');
      content = renderTemplate(raw, context);
    } catch (err) {
      logger.warn('EDITOR', `Could not read default template at ${defaultTemplatePath}: ${err.message}`);
    }

    await fs.writeFile(targetOverridePath, content, 'utf8');
    logger.info('EDITOR', `Initialized starter override file at ${targetOverridePath}`);
    return true; // Newly created
  }
}

/**
 * Open a file in the user's configured $EDITOR or $VISUAL (defaulting to nano or vi)
 * Handles terminal TTY suspension and restoration seamlessly.
 * @param {string} filePath - Path to file to edit
 * @returns {{ success: boolean, editor: string, error?: string }}
 */
export function openInEditor(filePath) {
  const editor = process.env.VISUAL || process.env.EDITOR || (process.platform === 'win32' ? 'notepad' : 'nano');
  logger.info('EDITOR', `Launching editor: ${editor} "${filePath}"`);

  const wasRaw = process.stdin.isRaw;

  // 1. Temporarily release TTY control to the editor
  if (process.stdin.setRawMode) {
    process.stdin.setRawMode(false);
  }
  // Turn off SGR mouse tracking and clear screen for editor
  process.stdout.write('\x1b[?1000l\x1b[?1006l\x1b[2J\x1b[H');

  try {
    const parts = editor.trim().split(/\s+/);
    const bin = parts[0];
    const args = [...parts.slice(1), filePath];
    const result = spawnSync(bin, args, {
      stdio: 'inherit'
    });

    logger.info('EDITOR:EXIT', `Editor "${editor}" finished with status ${result.status}`);
    return {
      success: result.status === 0,
      editor,
      status: result.status
    };
  } catch (err) {
    logger.error('EDITOR:FAIL', `Failed to spawn editor "${editor}": ${err.message}`, err);
    return {
      success: false,
      editor,
      error: err.message
    };
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
