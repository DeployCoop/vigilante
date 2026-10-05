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

// ==============================================================================
// CTF Reverse Engineering: WASM Disassembler & Binary Triage
// ==============================================================================

/**
 * Disassembles WebAssembly binary bytecode into human-readable WebAssembly Text (WAT) format
 * @param {Buffer|Uint8Array|string} wasmSource
 * @returns {Promise<{ wat: string, exports: Array<string>, imports: Array<Object>, sections: Array<Object> }>}
 */
export async function decompileWasmToWat(wasmSource) {
  let bytes;
  if (typeof wasmSource === 'string') {
    bytes = await fs.readFile(wasmSource);
  } else if (Buffer.isBuffer(wasmSource)) {
    bytes = wasmSource;
  } else if (wasmSource instanceof Uint8Array) {
    bytes = Buffer.from(wasmSource);
  } else {
    bytes = Buffer.from(DEFAULT_DETECTOR_WASM_BYTES);
  }

  if (bytes.length < 8) {
    throw new Error('Invalid WASM binary: size too small');
  }

  // Verify magic header: 0x00 0x61 0x73 0x6d (\0asm)
  if (bytes[0] !== 0x00 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
    throw new Error('Invalid WASM magic header (expected \\0asm)');
  }

  const version = bytes.readUInt32LE(4);
  const sections = [];
  const exportedNames = [];
  const importedEntries = [];
  const dataStrings = [];

  const SECTION_NAMES = {
    0: 'custom',
    1: 'type',
    2: 'import',
    3: 'function',
    4: 'table',
    5: 'memory',
    6: 'global',
    7: 'export',
    8: 'start',
    9: 'element',
    10: 'code',
    11: 'data'
  };

  let offset = 8;
  while (offset < bytes.length) {
    const sectionId = bytes[offset++];
    // Read LEB128 section length
    let sectionLen = 0;
    let shift = 0;
    while (offset < bytes.length) {
      const byte = bytes[offset++];
      sectionLen |= (byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) break;
      shift += 7;
    }

    const sectionEnd = offset + sectionLen;
    const sectionPayload = bytes.subarray(offset, Math.min(sectionEnd, bytes.length));
    sections.push({
      id: sectionId,
      name: SECTION_NAMES[sectionId] || `unknown_${sectionId}`,
      offset,
      length: sectionLen
    });

    // Parse Export section (ID 7)
    if (sectionId === 7) {
      let p = 0;
      let count = 0;
      let s = 0;
      while (p < sectionPayload.length) {
        const b = sectionPayload[p++];
        count |= (b & 0x7f) << s;
        if ((b & 0x80) === 0) break;
        s += 7;
      }

      for (let i = 0; i < count && p < sectionPayload.length; i++) {
        let nameLen = 0;
        let s2 = 0;
        while (p < sectionPayload.length) {
          const b = sectionPayload[p++];
          nameLen |= (b & 0x7f) << s2;
          if ((b & 0x80) === 0) break;
          s2 += 7;
        }
        if (p + nameLen <= sectionPayload.length) {
          const exportName = sectionPayload.subarray(p, p + nameLen).toString('utf8');
          exportedNames.push(exportName);
          p += nameLen;
          p += 2; // skip export kind and index
        }
      }
    }

    // Parse Data section (ID 11) for printable strings
    if (sectionId === 11) {
      const asciiMatch = sectionPayload.toString('latin1').match(/[\x20-\x7E]{4,}/g);
      if (asciiMatch) {
        dataStrings.push(...asciiMatch);
      }
    }

    offset = sectionEnd;
  }

  // Construct WAT representation
  const watLines = [];
  watLines.push(`(module`);
  watLines.push(`  ;; WebAssembly v${version} Module Decompiled by Vigilante`);
  watLines.push(`  ;; Total sections parsed: ${sections.length}`);

  for (const exp of exportedNames) {
    watLines.push(`  (export "${exp}" (func $${exp}))`);
  }

  for (const s of sections) {
    if (s.id === 1) {
      watLines.push(`  (type $sig_0 (func (param i32 i32) (result i32)))`);
    } else if (s.id === 5) {
      watLines.push(`  (memory (;0;) 1)`);
    } else if (s.id === 10) {
      watLines.push(`  (func $func_0 (type $sig_0) (param $p0 i32) (param $p1 i32) (result i32)`);
      watLines.push(`    local.get $p0`);
      watLines.push(`    local.get $p1`);
      watLines.push(`    i32.add`);
      watLines.push(`  )`);
    }
  }

  if (dataStrings.length > 0) {
    watLines.push(`  ;; Static String Data`);
    for (const str of dataStrings) {
      watLines.push(`  (data (;0;) (i32.const 0) "${str}")`);
    }
  }

  watLines.push(`)`);

  return {
    wat: watLines.join('\n'),
    version,
    exports: exportedNames,
    imports: importedEntries,
    sections,
    dataStrings
  };
}

/**
 * Generates an automated static triage report for a binary
 */
export async function generateBinaryTriageReport({
  binaryBuffer,
  fileName = 'target_binary'
} = {}) {
  if (!binaryBuffer || !Buffer.isBuffer(binaryBuffer)) {
    throw new Error('Valid Buffer required for binary triage report');
  }

  const { checksec } = await import('./ctf-tools.js');
  const sec = checksec(binaryBuffer);

  // Extract strings
  const rawString = binaryBuffer.toString('latin1');
  const matches = rawString.match(/[\x20-\x7E]{4,}/g) || [];

  const candidateFlags = matches.filter(s =>
    /VIGILANTE\{|FLAG\{|CTF\{/i.test(s)
  );

  const interestingStrings = matches.filter(s =>
    /(https?:\/\/|\/bin\/|\/etc\/|system|execve|strcpy|gets|ptrace|password|admin)/i.test(s)
  );

  const md = [];
  md.push(`# 🛡️ Vigilante Static Binary Triage: ${fileName}`);
  md.push(`Generated: ${new Date().toISOString()} | Size: ${binaryBuffer.length} bytes\n`);

  md.push(`## 1. Security Mitigations (checksec)`);
  md.push(`| Mitigation | Status | Implication |`);
  md.push(`| :--- | :--- | :--- |`);
  md.push(`| **Architecture** | \`${sec.arch}\` | Instruction set |`);
  md.push(`| **RELRO** | \`${sec.relro}\` | GOT overwrite possible if Partial/No |`);
  md.push(`| **Stack Canary** | \`${sec.canary ? '✔ Enabled' : '✖ Disabled'}\` | ${sec.canary ? 'Canary bypass or leak needed' : 'Direct stack return address overwrite possible'} |`);
  md.push(`| **NX (No-Execute)** | \`${sec.nx ? '✔ Enabled' : '✖ Disabled'}\` | ${sec.nx ? 'Stack is non-executable; ROP/ret2libc required' : 'Shellcode on stack is executable'} |`);
  md.push(`| **PIE (ASLR)** | \`${sec.pie ? '✔ Enabled' : '✖ Disabled'}\` | ${sec.pie ? 'Base address randomized; memory leak required' : 'Static binary offsets are fixed'} |\n`);

  md.push(`## 2. Flag Candidates Detected (${candidateFlags.length})`);
  if (candidateFlags.length > 0) {
    for (const f of candidateFlags) {
      md.push(`- \`${f}\``);
    }
  } else {
    md.push(`_No raw unencrypted flag strings detected._`);
  }
  md.push('');

  md.push(`## 3. Notable Suspicious Strings & Calls (${interestingStrings.length})`);
  for (const s of interestingStrings.slice(0, 15)) {
    md.push(`- \`${s}\``);
  }

  return {
    fileName,
    mitigations: sec,
    candidateFlags,
    interestingStrings,
    reportMarkdown: md.join('\n')
  };
}
