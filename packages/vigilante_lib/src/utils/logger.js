import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const LOG_FILE_PATH = path.join(os.tmpdir(), '.vigilante.log');

/**
 * Append a formatted log entry to /tmp/.vigilante.log
 * @param {string} level - 'DEBUG' | 'INFO' | 'WARN' | 'ERROR'
 * @param {string} tag - Component or action tag, e.g. 'UI:KEY' or 'CLUSTER'
 * @param {string} message - Primary log text
 * @param {any} [details] - Optional extra metadata or error object
 */
export function writeDebugLog(level, tag, message, details = null) {
  try {
    const timestamp = new Date().toISOString();
    let entry = `[${timestamp}] [${level.padEnd(5)}] [${tag}] ${message}`;

    if (details !== null && details !== undefined) {
      if (details instanceof Error) {
        entry += `\n  Stack: ${details.stack || details.message}`;
      } else if (typeof details === 'object') {
        try {
          entry += `\n  Data: ${JSON.stringify(details)}`;
        } catch {
          entry += `\n  Data: [Circular or unstringifiable object]`;
        }
      } else {
        entry += `\n  Details: ${details}`;
      }
    }

    entry += '\n';

    // Synchronous append so logs are never lost on immediate exit or crash
    fs.appendFileSync(LOG_FILE_PATH, entry, 'utf8');
  } catch {
    // Fail-safe: silently continue if logging fails
  }
}

export const logger = {
  debug: (tag, message, details) => writeDebugLog('DEBUG', tag, message, details),
  info: (tag, message, details) => writeDebugLog('INFO', tag, message, details),
  warn: (tag, message, details) => writeDebugLog('WARN', tag, message, details),
  error: (tag, message, details) => writeDebugLog('ERROR', tag, message, details),
  getLogPath: () => LOG_FILE_PATH
};
