/**
 * WebAssembly (Wasm) Extensible Detection & Containment Engine
 * Executes user-authored and community detection rules in a sandboxed, memory-safe runtime.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteWasmDir } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Minimal valid WebAssembly binary exporting `detect_threat(port: i32, rate: i32) -> i32`
 */
export const DEFAULT_DETECTOR_WASM_BYTES = new Uint8Array([
  0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
  0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01, 0x7f,
  0x03, 0x02, 0x01, 0x00,
  0x07, 0x11, 0x01, 0x0d, 0x64, 0x65, 0x74, 0x65, 0x63, 0x74, 0x5f, 0x74, 0x68, 0x72, 0x65, 0x61, 0x74, 0x00, 0x00,
  0x0a, 0x09, 0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a, 0x0b
]);

/**
 * Load and instantiate a WebAssembly detector module
 * @param {Buffer|Uint8Array|string} wasmSource Buffer, Uint8Array, or file path to .wasm
 * @param {Object} [imports={}] Custom host imports
 * @returns {Promise<{ instance: WebAssembly.Instance, module: WebAssembly.Module, exports: Object }>}
 */
export async function loadWasmPlugin(wasmSource, imports = {}) {
  let bytes;
  if (typeof wasmSource === 'string') {
    bytes = await fs.readFile(wasmSource);
  } else if (Buffer.isBuffer(wasmSource)) {
    bytes = wasmSource;
  } else if (wasmSource instanceof Uint8Array) {
    bytes = wasmSource;
  } else {
    bytes = DEFAULT_DETECTOR_WASM_BYTES;
  }

  const defaultImports = {
    env: {
      memory: new WebAssembly.Memory({ initial: 1, maximum: 10 }),
      abort: () => {
        logger.error('WASM', 'Wasm plugin triggered abort()');
      }
    },
    ...imports
  };

  const { instance, module } = await WebAssembly.instantiate(bytes, defaultImports);
  logger.info('WASM', `Loaded WebAssembly plugin (Exports: ${Object.keys(instance.exports).join(', ')})`);

  return {
    instance,
    module,
    exports: instance.exports
  };
}

/**
 * Execute detection function inside Wasm plugin
 * @param {Object} plugin Loaded plugin ({ exports })
 * @param {Object} event Security event { port, rate, ... }
 * @returns {Object} Verdict and calculated score
 */
export function executeWasmDetector(plugin, event = {}) {
  const detectFn = plugin.exports.detect_threat || plugin.exports.analyze || plugin.exports.evaluate;
  if (typeof detectFn !== 'function') {
    throw new Error('Wasm plugin does not export a valid detector function (detect_threat/analyze/evaluate)');
  }

  const port = Number(event.destPort || event.port || 80);
  const rate = Number(event.rate || event.count || 1);

  // Invoke sandboxed Wasm function
  const rawScore = detectFn(port, rate);

  let verdict = 'CLEAN';
  let severity = 'LOW';

  if (rawScore > 1000) {
    verdict = 'CRITICAL_ANOMALY';
    severity = 'CRITICAL';
  } else if (rawScore > 400) {
    verdict = 'SUSPICIOUS_ACTIVITY';
    severity = 'HIGH';
  }

  return {
    rawScore,
    verdict,
    severity,
    port,
    rate,
    timestamp: new Date().toISOString()
  };
}

/**
 * List all installed WebAssembly plugins from $XDG_CONFIG_HOME/vigilante/wasm/
 * @returns {Promise<Array<Object>>}
 */
export async function listWasmPlugins() {
  const wasmDir = getVigilanteWasmDir();
  try {
    const files = await fs.readdir(wasmDir);
    const plugins = [];
    for (const file of files) {
      if (file.endsWith('.wasm')) {
        const fullPath = path.join(wasmDir, file);
        const stat = await fs.stat(fullPath);
        plugins.push({
          name: file.replace('.wasm', ''),
          fileName: file,
          filePath: fullPath,
          sizeBytes: stat.size,
          installedAt: stat.mtime.toISOString()
        });
      }
    }
    return plugins;
  } catch {
    return [];
  }
}

/**
 * Install a WebAssembly plugin to the persistent plugins directory
 * @param {string} pluginName 
 * @param {Buffer|Uint8Array} wasmBytes 
 * @returns {Promise<string>} Installed file path
 */
export async function installWasmPlugin(pluginName, wasmBytes = DEFAULT_DETECTOR_WASM_BYTES) {
  const wasmDir = getVigilanteWasmDir();
  await fs.mkdir(wasmDir, { recursive: true });
  const fileName = pluginName.endsWith('.wasm') ? pluginName : `${pluginName}.wasm`;
  const targetPath = path.join(wasmDir, fileName);

  await fs.writeFile(targetPath, wasmBytes);
  logger.info('WASM', `Installed WebAssembly plugin: ${targetPath}`);
  return targetPath;
}
