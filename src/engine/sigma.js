/**
 * SIGMA-to-SQL Detection Transpiler & Automated Threat Hunting Engine
 * Converts vendor-agnostic SIGMA detection rules (YAML/JSON) into ANSI SQL
 * compatible with embedded node:sqlite and DuckDB Data Lake instances.
 */

import { queryDataLake } from './datalake.js';
import { logger } from '../utils/logger.js';

/**
 * Standard field mapping from common SIGMA field names to Vigilante security_events columns
 */
export const SIGMA_FIELD_MAPPINGS = {
  'destination.ip': 'dest_ip',
  'destinationip': 'dest_ip',
  'dest_ip': 'dest_ip',
  'dst_ip': 'dest_ip',
  'dst': 'dest_ip',
  'source.ip': 'source_ip',
  'sourceip': 'source_ip',
  'src_ip': 'source_ip',
  'src': 'source_ip',
  'destination.port': 'dest_port',
  'destinationport': 'dest_port',
  'dest_port': 'dest_port',
  'dst_port': 'dest_port',
  'event_type': 'event_type',
  'service': 'event_type',
  'product': 'event_type',
  'pod': 'source_pod',
  'source_pod': 'source_pod',
  'severity': 'severity',
  'level': 'severity',
  'indicator': 'indicator',
  'ioc': 'indicator',
  'mitre_technique': 'mitre_technique',
  'technique': 'mitre_technique'
};

/**
 * Parse simple SIGMA YAML or JSON content into a structured object
 * Supports basic YAML structures without external yaml dependencies
 * @param {string|Object} input
 * @returns {Object} Structured SIGMA rule definition
 */
export function parseSigmaRule(input) {
  if (typeof input === 'object' && input !== null) {
    return input;
  }

  if (typeof input !== 'string') {
    throw new Error('Invalid SIGMA input: expected string or object');
  }

  // Attempt standard JSON parse first
  try {
    return JSON.parse(input);
  } catch {
    // Basic lightweight YAML line parser for key-value and detection mappings
    const rule = { detection: {}, logsource: {}, tags: [] };
    const lines = input.split(/\r?\n/);
    let currentSection = null;
    let currentSubSection = null;

    for (let rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith('#')) continue;

      if (!rawLine.startsWith(' ') && !rawLine.startsWith('\t') && line.includes(':')) {
        const [k, ...v] = line.split(':');
        const key = k.trim();
        const val = v.join(':').trim();
        if (['detection', 'logsource', 'tags'].includes(key)) {
          currentSection = key;
          currentSubSection = null;
        } else {
          currentSection = null;
          rule[key] = val.replace(/^['"]|['"]$/g, '');
        }
      } else if (currentSection === 'tags' && line.startsWith('-')) {
        rule.tags.push(line.replace(/^-\s*/, '').replace(/^['"]|['"]$/g, ''));
      } else if (currentSection === 'detection') {
        if ((rawLine.startsWith('  ') || rawLine.startsWith('\t')) && !rawLine.startsWith('    ') && line.includes(':')) {
          const [k, ...v] = line.split(':');
          const subKey = k.trim();
          const subVal = v.join(':').trim();
          if (subKey === 'condition') {
            rule.detection.condition = subVal.replace(/^['"]|['"]$/g, '');
            currentSubSection = null;
          } else {
            currentSubSection = subKey;
            rule.detection[currentSubSection] = subVal ? { _val: subVal.replace(/^['"]|['"]$/g, '') } : {};
          }
        } else if (currentSubSection && line.includes(':')) {
          const [k, ...v] = line.split(':');
          const field = k.trim().replace(/^-\s*/, '');
          const val = v.join(':').trim().replace(/^['"]|['"]$/g, '');
          rule.detection[currentSubSection][field] = val;
        }
      }
    }

    if (!rule.title) rule.title = 'Untitled SIGMA Rule';
    if (!rule.detection.condition) rule.detection.condition = 'selection';
    return rule;
  }
}

/**
 * Transpile a single field and value into an SQL WHERE clause fragment
 * @param {string} field
 * @param {any} value
 * @returns {string}
 */
function transpileFieldClause(field, value) {
  let [fieldName, ...modifiers] = field.split('|');
  const normalizedCol = SIGMA_FIELD_MAPPINGS[fieldName.toLowerCase()];
  const isDirectCol = Boolean(normalizedCol);
  const targetCol = isDirectCol ? normalizedCol : 'raw_json';

  const stringVal = String(value);
  const hasContains = modifiers.includes('contains');
  const hasStartswith = modifiers.includes('startswith');
  const hasEndswith = modifiers.includes('endswith');

  if (targetCol === 'raw_json') {
    // If not a direct column, search within raw_json or indicator
    const pattern = stringVal.replace(/\*/g, '%');
    return `(raw_json LIKE '%"${fieldName}":"%${pattern}%"%' OR indicator LIKE '%${pattern}%' OR raw_json LIKE '%${pattern}%')`;
  }

  if (hasContains || stringVal.includes('*')) {
    const pattern = stringVal.replace(/\*/g, '%');
    const sqlPattern = hasContains && !pattern.includes('%') ? `%${pattern}%` : pattern;
    return `${targetCol} LIKE '${sqlPattern}'`;
  }

  if (hasStartswith) {
    return `${targetCol} LIKE '${stringVal}%'`;
  }

  if (hasEndswith) {
    return `${targetCol} LIKE '%${stringVal}'`;
  }

  if (typeof value === 'number' || (!isNaN(Number(value)) && normalizedCol === 'dest_port')) {
    return `${targetCol} = ${Number(value)}`;
  }

  return `${targetCol} = '${stringVal.replace(/'/g, "''")}'`;
}

/**
 * Transpile a SIGMA detection section selection into an SQL predicate
 * @param {Object} selection
 * @returns {string}
 */
function transpileSelection(selection) {
  if (!selection || typeof selection !== 'object') return '1=1';

  const clauses = [];
  for (const [key, val] of Object.entries(selection)) {
    if (key === '_val') continue;
    if (Array.isArray(val)) {
      const orClauses = val.map(v => transpileFieldClause(key, v));
      clauses.push(`(${orClauses.join(' OR ')})`);
    } else {
      clauses.push(transpileFieldClause(key, val));
    }
  }

  return clauses.length > 0 ? clauses.join(' AND ') : '1=1';
}

/**
 * Transpile a complete SIGMA rule into an ANSI SQL query over security_events
 * @param {Object|string} ruleInput
 * @param {Object} [options={}]
 * @returns {{ sql: string, title: string, level: string, technique: string|null }}
 */
export function transpileSigmaToSql(ruleInput, options = {}) {
  const rule = parseSigmaRule(ruleInput);
  const tableName = options.table || 'security_events';

  const detection = rule.detection || {};
  const condition = (detection.condition || 'selection').trim();

  // Transpile named selections
  const selectionClauses = {};
  for (const [name, def] of Object.entries(detection)) {
    if (name === 'condition') continue;
    selectionClauses[name] = transpileSelection(def);
  }

  let sqlCondition = condition;

  // Handle "1 of selection*" pattern
  if (/1 of (selection\*|[a-zA-Z0-9_]+)/i.test(sqlCondition)) {
    const matching = Object.keys(selectionClauses).filter(k => k.startsWith('selection'));
    const orBlock = matching.length > 0
      ? matching.map(k => `(${selectionClauses[k]})`).join(' OR ')
      : '1=1';
    sqlCondition = sqlCondition.replace(/1 of (selection\*|[a-zA-Z0-9_]+)/gi, `(${orBlock})`);
  }

  // Handle "all of selection*" pattern
  if (/all of (selection\*|[a-zA-Z0-9_]+)/i.test(sqlCondition)) {
    const matching = Object.keys(selectionClauses).filter(k => k.startsWith('selection'));
    const andBlock = matching.length > 0
      ? matching.map(k => `(${selectionClauses[k]})`).join(' AND ')
      : '1=1';
    sqlCondition = sqlCondition.replace(/all of (selection\*|[a-zA-Z0-9_]+)/gi, `(${andBlock})`);
  }

  // Replace discrete named selections
  for (const [name, clause] of Object.entries(selectionClauses)) {
    const regex = new RegExp(`\\b${name}\\b`, 'g');
    sqlCondition = sqlCondition.replace(regex, `(${clause})`);
  }

  // Normalize boolean operators
  sqlCondition = sqlCondition
    .replace(/\band\b/gi, 'AND')
    .replace(/\bor\b/gi, 'OR')
    .replace(/\bnot\b/gi, 'NOT');

  const technique = (rule.tags || []).find(t => /^attack\.t\d{4}/i.test(t))?.replace(/^attack\./i, '').toUpperCase() || null;

  const sql = `SELECT * FROM ${tableName} WHERE ${sqlCondition} ORDER BY timestamp DESC`;

  return {
    sql,
    title: rule.title || 'SIGMA Rule Detection',
    level: (rule.level || 'medium').toUpperCase(),
    technique
  };
}

/**
 * Execute a batch of SIGMA rules against the active Security Data Lake
 * @param {Array<Object|string>} sigmaRules
 * @returns {Array<Object>} Matched threat hunt findings
 */
export function runSigmaThreatHunt(sigmaRules = []) {
  const matches = [];
  const rules = Array.isArray(sigmaRules) ? sigmaRules : (sigmaRules ? [sigmaRules] : []);

  for (const item of rules) {
    try {
      const transpiled = transpileSigmaToSql(item);
      const rows = queryDataLake(transpiled.sql);

      if (rows && rows.length > 0) {
        matches.push({
          ruleTitle: transpiled.title,
          level: transpiled.level,
          technique: transpiled.technique,
          matchCount: rows.length,
          firstSeen: rows[rows.length - 1].timestamp,
          lastSeen: rows[0].timestamp,
          affectedPods: Array.from(new Set(rows.map(r => r.source_pod).filter(Boolean))),
          events: rows
        });
      }
    } catch (err) {
      logger.warn('SIGMA', `Failed to execute rule: ${err.message}`);
    }
  }

  return matches;
}

/**
 * Generate candidate threat hunting hypothesis and SIGMA/SQL query for a MITRE technique
 * @param {string} techniqueId e.g. 'T1059.004', 'T1021.002', 'T1071.001'
 * @returns {Object}
 */
export function generateHypothesisForTechnique(techniqueId) {
  const tid = techniqueId.toUpperCase();

  const presets = {
    'T1059.004': {
      title: 'Suspicious Unix Shell Spawn in Container',
      technique: 'T1059.004',
      description: 'Detects execution of interactive bash/sh shells inside non-administrative container workloads.',
      hypothesis: 'Adversary leveraged an RCE vulnerability to spawn a reverse shell in a web application pod.',
      sigma: {
        title: 'Shell Spawn in Web Container',
        level: 'high',
        tags: ['attack.t1059.004'],
        detection: {
          selection: {
            indicator: '*sh*',
            severity: 'CRITICAL'
          },
          condition: 'selection'
        }
      }
    },
    'T1021.002': {
      title: 'Lateral SMB Traffic Between Workload Pods',
      technique: 'T1021.002',
      description: 'Detects East-West SMB (port 445) communication across non-storage pods.',
      hypothesis: 'Compromised identity attempting lateral file share access or PsExec-style lateral execution.',
      sigma: {
        title: 'Anomalous Lateral SMB Connections',
        level: 'high',
        tags: ['attack.t1021.002'],
        detection: {
          selection: {
            'destination.port': 445
          },
          condition: 'selection'
        }
      }
    },
    'T1071.001': {
      title: 'C2 Web Beaconing to Untrusted IPs',
      technique: 'T1071.001',
      description: 'Detects outbound HTTPS/HTTP egress to low-reputation or newly discovered IP addresses.',
      hypothesis: 'Malware establishing command and control channel to external host.',
      sigma: {
        title: 'C2 Web Protocol Beaconing',
        level: 'critical',
        tags: ['attack.t1071.001'],
        detection: {
          selection: {
            'destination.port': 443,
            severity: 'CRITICAL'
          },
          condition: 'selection'
        }
      }
    }
  };

  const selected = presets[tid] || {
    title: `Generic Threat Hunt for ${tid}`,
    technique: tid,
    description: `Automated hypothesis for technique ${tid}`,
    hypothesis: `Telemetry reveals behaviors matching ${tid}`,
    sigma: {
      title: `Rule for ${tid}`,
      level: 'medium',
      tags: [`attack.${tid.toLowerCase()}`],
      detection: {
        selection: {
          mitre_technique: tid
        },
        condition: 'selection'
      }
    }
  };

  const transpiled = transpileSigmaToSql(selected.sigma);
  return {
    ...selected,
    sql: transpiled.sql
  };
}

export {
  generateHypothesisForTechnique as generateSigmaHypothesis
};
