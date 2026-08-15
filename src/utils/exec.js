import { execa } from 'execa';
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
 * Check if a command is available in PATH
 */
export async function commandExists(command) {
  try {
    await execa('which', [command]);
    return true;
  } catch {
    return false;
  }
}

/**
 * Execute a shell command string with piping support
 */
export async function execShell(commandString, options = {}) {
  return execa(commandString, { shell: true, ...options });
}
