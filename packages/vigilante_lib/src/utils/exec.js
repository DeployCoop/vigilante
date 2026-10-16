import { execa } from 'execa';
import fs from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import path from 'node:path';
import { logger } from './logger.js';

/**
 * Execute a command with options and formatted errors
 */
export async function exec(file, args = [], options = {}) {
  const commandStr = [file, ...args].join(' ');
  logger.debug('EXEC', `Running: ${commandStr}`);
  try {
    const result = await execa(file, args, {
      ...options,
      all: true
    });
    logger.debug('EXEC:DONE', `Command succeeded: ${commandStr}`);
    return result;
  } catch (error) {
    const enhancedError = new Error(`Command failed: ${commandStr}\n${error.stderr || error.stdout || error.message}`);
    enhancedError.exitCode = error.exitCode;
    enhancedError.originalError = error;
    logger.error('EXEC:FAIL', `Command failed: ${commandStr}`, enhancedError);
    throw enhancedError;
  }
}

/**
 * Execute a command with line-by-line output streaming
 */
export async function execStream(file, args = [], { onLog, ...options } = {}) {
  const commandStr = [file, ...args].join(' ');
  logger.debug('EXEC:STREAM', `Starting stream: ${commandStr}`);
  try {
    const subprocess = execa(file, args, {
      ...options,
      all: true
    });

    if (onLog && subprocess.all) {
      subprocess.all.on('data', (chunk) => {
        const text = chunk.toString().trim();
        if (text) {
          const lines = text.split('\n');
          for (const line of lines) {
            const cleanLine = line.trim();
            if (cleanLine) {
              logger.debug('EXEC:OUTPUT', cleanLine);
              onLog(cleanLine);
            }
          }
        }
      });
    }

    const res = await subprocess;
    logger.debug('EXEC:STREAM:DONE', `Stream completed: ${commandStr}`);
    return res;
  } catch (error) {
    const detail = error.stderr || error.stdout || error.all || error.shortMessage || error.message;
    const enhancedError = new Error(`Command failed: ${commandStr}\n${detail}`);
    enhancedError.exitCode = error.exitCode;
    enhancedError.originalError = error;
    logger.error('EXEC:STREAM:FAIL', `Stream failed: ${commandStr}`, enhancedError);
    throw enhancedError;
  }
}

/**
 * Check if a command is available in PATH.
 * Falls back to scanning PATH directly: minimal environments may not
 * ship a `which` binary, and depending on it made every prerequisite
 * report "missing" there.
 */
export async function commandExists(command) {
  try {
    await execa('which', [command]);
    return true;
  } catch {
    // fall through to the PATH scan
  }
  const extensions = process.platform === 'win32'
    ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').map(e => e.toLowerCase())
    : [''];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of extensions) {
      try {
        await fs.access(path.join(dir, command + ext), fsConstants.X_OK);
        return true;
      } catch {
        // not in this dir
      }
    }
  }
  return false;
}

/**
 * Execute a shell command string with piping support
 */
export async function execShell(commandString, options = {}) {
  return execa(commandString, { shell: true, ...options });
}
