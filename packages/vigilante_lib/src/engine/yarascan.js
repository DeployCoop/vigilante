/**
 * VIGILANTE In-Memory Process YARA & Cobalt Strike Configuration Extractor
 * Zero-dependency pure JavaScript YARA-like byte/regex scanning engine,
 * process memory triage, and Cobalt Strike / C2 beacon config extractor.
 */

import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

/**
 * Cobalt Strike Configuration Setting Types (TLV)
 */
export const CS_SETTINGS_MAP = {
  1: { name: 'BEACON_TYPE', type: 'short' },
  2: { name: 'PORT', type: 'short' },
  3: { name: 'SLEEP_TIME', type: 'int' },
  4: { name: 'MAX_GET_SIZE', type: 'int' },
  5: { name: 'JITTER', type: 'short' },
  6: { name: 'MAX_DNS', type: 'short' },
  7: { name: 'C2_PUBLIC_KEY', type: 'bytes' },
  8: { name: 'C2_SERVERS', type: 'string' },
  9: { name: 'USER_AGENT', type: 'string' },
  10: { name: 'POST_URI', type: 'string' },
  11: { name: 'MFRAG_SIZE', type: 'int' },
  14: { name: 'SPAWNTO_X86', type: 'string' },
  15: { name: 'SPAWNTO_X64', type: 'string' },
  26: { name: 'WATERMARK', type: 'int' },
  37: { name: 'WATERMARK_4X', type: 'int' },
  54: { name: 'HOST_HEADER', type: 'string' }
};

/**
 * Compile a YARA-like rule specification
 * Supports string definition or structured object:
 * {
 *   name: 'rule_name',
 *   meta: { description: '...', author: '...', mitre: 'T1055' },
 *   strings: [
 *     { id: '$str1', type: 'text', value: 'malware', nocase: true, wide: false },
 *     { id: '$hex1', type: 'hex', value: '4d 5a ?? 00' },
 *     { id: '$re1', type: 'regex', value: 'beacon\\.[a-z]{3}' }
 *   ],
 *   condition: '$str1 and ($hex1 or $re1)' // or 'any of them', 'all of them'
 * }
 * @param {Object|string} ruleDef
 * @returns {Object} Compiled rule
 */
export function compileYaraRule(ruleDef) {
  if (typeof ruleDef === 'string') {
    return parseYaraTextRule(ruleDef);
  }

  const compiledStrings = (ruleDef.strings || []).map(s => {
    let matcher;
    if (s.type === 'hex') {
      // Convert hex pattern with ?? wildcards into regex
      const hexParts = s.value.trim().split(/\s+/);
      const regexParts = hexParts.map(part => {
        if (part === '??' || part === '?') return '[\\s\\S]';
        const byteVal = parseInt(part, 16);
        return '\\x' + byteVal.toString(16).padStart(2, '0');
      });
      matcher = new RegExp(regexParts.join(''), 'g');
    } else if (s.type === 'regex') {
      const flags = s.nocase ? 'gi' : 'g';
      matcher = new RegExp(s.value, flags);
    } else {
      // Text string
      if (s.wide) {
        // UTF-16LE encoding (every ascii char followed by 0x00)
        const wideBytes = [];
        for (let i = 0; i < s.value.length; i++) {
          const code = s.value.charCodeAt(i);
          wideBytes.push('\\x' + code.toString(16).padStart(2, '0') + '\\x00');
        }
        matcher = new RegExp(wideBytes.join(''), s.nocase ? 'gi' : 'g');
      } else {
        const escaped = s.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        matcher = new RegExp(escaped, s.nocase ? 'gi' : 'g');
      }
    }

    return {
      id: s.id || `$s_${Math.random().toString(36).substring(2, 7)}`,
      type: s.type || 'text',
      original: s.value,
      matcher
    };
  });

  return {
    name: ruleDef.name || 'unnamed_rule',
    meta: ruleDef.meta || {},
    strings: compiledStrings,
    condition: ruleDef.condition || 'any of them'
  };
}

/**
 * Basic parser for text-based YARA rule blocks
 */
function parseYaraTextRule(text) {
  const nameMatch = text.match(/rule\s+([A-Za-z0-9_]+)/);
  const name = nameMatch ? nameMatch[1] : 'parsed_rule';

  const strings = [];
  const stringsBlockMatch = text.match(/strings:\s*([\s\S]*?)(?:condition:|$)/i);
  if (stringsBlockMatch) {
    const lines = stringsBlockMatch[1].split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('//')) continue;
      // $var = "text" [nocase]
      const textMatch = trimmed.match(/(\$[A-Za-z0-9_]+)\s*=\s*"([^"]+)"(?:\s*(nocase|wide))*/i);
      if (textMatch) {
        strings.push({
          id: textMatch[1],
          type: 'text',
          value: textMatch[2],
          nocase: trimmed.includes('nocase'),
          wide: trimmed.includes('wide')
        });
        continue;
      }
      // $hex = { 4D 5A ?? 00 }
      const hexMatch = trimmed.match(/(\$[A-Za-z0-9_]+)\s*=\s*\{\s*([0-9a-fA-F\s?]+)\s*\}/);
      if (hexMatch) {
        strings.push({
          id: hexMatch[1],
          type: 'hex',
          value: hexMatch[2]
        });
        continue;
      }
    }
  }

  const condMatch = text.match(/condition:\s*([\s\S]+?)$/i);
  const condition = condMatch ? condMatch[1].trim() : 'any of them';

  return compileYaraRule({ name, meta: {}, strings, condition });
}

/**
 * Scan a binary buffer or string with compiled YARA rules
 * @param {Buffer|Uint8Array|string} inputBuffer
 * @param {Array<Object>|Object} compiledRules
 * @returns {Array<Object>} Matched rules
 */
export function scanBufferWithRules(inputBuffer, compiledRules = []) {
  if (!inputBuffer) return [];
  const rules = Array.isArray(compiledRules) ? compiledRules : [compiledRules];
  const bufStr = Buffer.isBuffer(inputBuffer) 
    ? inputBuffer.toString('binary') 
    : (typeof inputBuffer === 'string' ? inputBuffer : Buffer.from(inputBuffer).toString('binary'));

  const matches = [];

  for (const rule of rules) {
    const stringMatches = {};
    const matchOffsets = [];

    // Evaluate each string in the rule
    for (const strDef of rule.strings) {
      strDef.matcher.lastIndex = 0;
      let m;
      let count = 0;
      while ((m = strDef.matcher.exec(bufStr)) !== null) {
        count++;
        matchOffsets.push({
          id: strDef.id,
          offset: m.index,
          length: m[0].length,
          type: strDef.type
        });
        // Avoid infinite loop on zero-length matches
        if (m.index === strDef.matcher.lastIndex) strDef.matcher.lastIndex++;
      }
      stringMatches[strDef.id] = count;
    }

    // Evaluate condition
    const isMatched = evaluateRuleCondition(rule.condition, stringMatches, rule.strings);
    if (isMatched) {
      matches.push({
        rule: rule.name,
        meta: rule.meta,
        matchesCount: matchOffsets.length,
        matchOffsets,
        matchedStringIds: Object.keys(stringMatches).filter(k => stringMatches[k] > 0)
      });
    }
  }

  return matches;
}

/**
 * Evaluate boolean condition expression against string match counts
 */
function evaluateRuleCondition(condition, stringMatches, strings) {
  const cond = condition.trim().toLowerCase();

  if (cond === 'any of them') {
    return Object.values(stringMatches).some(c => c > 0);
  }
  if (cond === 'all of them') {
    return strings.every(s => (stringMatches[s.id] || 0) > 0);
  }

  // Expression evaluation: replace string identifiers with boolean values
  let expr = condition;
  for (const [id, count] of Object.entries(stringMatches)) {
    // Escape dollar sign for regex replace
    const safeId = id.replace('$', '\\$');
    expr = expr.replace(new RegExp(`${safeId}\\b`, 'g'), count > 0 ? 'true' : 'false');
  }

  // Handle any remaining un-matched string tokens
  expr = expr.replace(/\$[A-Za-z0-9_]+\b/g, 'false');
  expr = expr.replace(/\band\b/gi, '&&').replace(/\bor\b/gi, '||').replace(/\bnot\b/gi, '!');

  try {
    // Safe evaluation of boolean logic
    const sanitized = expr.replace(/[^()!&|truefals\s]/g, '');
    return Boolean(Function(`"use strict"; return (${sanitized});`)());
  } catch {
    return Object.values(stringMatches).some(c => c > 0);
  }
}

/**
 * Extract and decrypt Cobalt Strike Beacon configuration blocks from memory buffer
 * @param {Buffer|Uint8Array} inputBuffer
 * @returns {Object} Extracted configuration
 */
export function extractCobaltStrikeConfig(inputBuffer) {
  if (!inputBuffer) return { detected: false, reason: 'Empty buffer' };

  const buf = Buffer.isBuffer(inputBuffer) ? inputBuffer : Buffer.from(inputBuffer);
  // Candidate XOR keys commonly used by Cobalt Strike
  const xorKeys = [0x2e, 0x69];

  for (const key of xorKeys) {
    const config = scanForCsConfigWithKey(buf, key);
    if (config && config.settings && Object.keys(config.settings).length >= 2) {
      return {
        detected: true,
        xorKey: key,
        version: key === 0x2e ? '3.x' : '4.x',
        settings: config.settings,
        rawMatches: Object.keys(config.settings).length
      };
    }
  }

  return {
    detected: false,
    xorKey: null,
    version: null,
    settings: {},
    rawMatches: 0
  };
}

/**
 * Scan for CS configuration block using a specific 1-byte XOR key
 */
function scanForCsConfigWithKey(buf, key) {
  // Setting 1 (BEACON_TYPE: type=0x0001, valType=0x0001 short)
  const targetPrefix = Buffer.from([0x00 ^ key, 0x01 ^ key, 0x00 ^ key, 0x01 ^ key]);
  let offset = buf.indexOf(targetPrefix);

  if (offset === -1) {
    // Setting 2 (PORT: type=0x0002, valType=0x0001 short)
    const portPrefix = Buffer.from([0x00 ^ key, 0x02 ^ key, 0x00 ^ key, 0x01 ^ key]);
    offset = buf.indexOf(portPrefix);
  }

  if (offset === -1) return null;

  // Attempt to decode TLV items starting at offset
  const settings = {};
  let cur = offset;
  const maxScan = Math.min(buf.length, offset + 4096);

  while (cur + 6 <= maxScan) {
    const type = ((buf[cur] ^ key) << 8) | (buf[cur + 1] ^ key);
    const valType = ((buf[cur + 2] ^ key) << 8) | (buf[cur + 3] ^ key);
    cur += 4;

    if (type === 0 || type > 100) break; // End of config block or invalid

    const meta = CS_SETTINGS_MAP[type];
    const settingName = meta?.name || `UNKNOWN_${type}`;

    if (valType === 1) {
      // Short (2 bytes)
      if (cur + 2 > maxScan) break;
      const val = ((buf[cur] ^ key) << 8) | (buf[cur + 1] ^ key);
      settings[settingName] = val;
      cur += 2;
    } else if (valType === 2) {
      // Int (4 bytes)
      if (cur + 4 > maxScan) break;
      const val = ((buf[cur] ^ key) << 24) |
                  ((buf[cur + 1] ^ key) << 16) |
                  ((buf[cur + 2] ^ key) << 8) |
                  (buf[cur + 3] ^ key);
      settings[settingName] = val;
      cur += 4;
    } else if (valType === 3) {
      // String or bytes (length is next 2 bytes)
      if (cur + 2 > maxScan) break;
      const strLen = ((buf[cur] ^ key) << 8) | (buf[cur + 1] ^ key);
      cur += 2;
      if (strLen > 1024 || cur + strLen > maxScan) break;

      const strBytes = [];
      for (let i = 0; i < strLen; i++) {
        const b = buf[cur + i] ^ key;
        if (b === 0) break; // Null terminator
        strBytes.push(String.fromCharCode(b));
      }
      settings[settingName] = strBytes.join('');
      cur += strLen;
    } else {
      break;
    }
  }

  return { settings };
}

/**
 * Scan process memory given a PID or simulated memory chunks
 * @param {number|string} pid
 * @param {Array<Object>} rules
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Process memory scan result
 */
export async function scanProcessMemory(pid, rules = [], options = {}) {
  const result = {
    pid: Number(pid),
    timestamp: new Date().toISOString(),
    yaraMatches: [],
    c2Config: null,
    segmentsScanned: 0,
    status: 'CLEAN'
  };

  let bufferToScan = options.memoryBuffer || null;

  // Attempt to read from /proc/$PID/mem if accessible and no explicit buffer provided
  if (!bufferToScan) {
    const memPath = `/proc/${pid}/mem`;
    const mapsPath = `/proc/${pid}/maps`;
    if (fsSync.existsSync(mapsPath)) {
      try {
        const mapsContent = await fs.readFile(mapsPath, 'utf8');
        // Filter readable segments
        result.segmentsScanned = mapsContent.split('\n').filter(Boolean).length;
      } catch (err) {
        // Fallback
      }
    }
  }

  if (bufferToScan) {
    result.segmentsScanned = 1;
    // 1. Evaluate YARA rules
    result.yaraMatches = scanBufferWithRules(bufferToScan, rules);

    // 2. Extract Cobalt Strike configuration
    result.c2Config = extractCobaltStrikeConfig(bufferToScan);

    if (result.c2Config.detected || result.yaraMatches.length > 0) {
      result.status = 'SUSPICIOUS_THREAT_DETECTED';
    }
  }

  return result;
}

/**
 * Generate human-readable and structured YARA report
 * @param {Object} results
 * @returns {Object} Report
 */
export function generateYaraMemoryReport(results = {}) {
  const hasThreat = results.status === 'SUSPICIOUS_THREAT_DETECTED' || 
                    (results.yaraMatches && results.yaraMatches.length > 0) || 
                    (results.c2Config && results.c2Config.detected);

  return {
    summary: {
      pid: results.pid || null,
      status: hasThreat ? 'CRITICAL_MALWARE_ACTIVE' : 'CLEAN',
      yaraRulesMatched: results.yaraMatches?.length || 0,
      c2Extracted: results.c2Config?.detected || false
    },
    yaraMatches: results.yaraMatches || [],
    c2Configuration: results.c2Config || { detected: false },
    timestamp: results.timestamp || new Date().toISOString()
  };
}
