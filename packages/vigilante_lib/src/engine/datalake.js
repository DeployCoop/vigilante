/**
 * High-Throughput Embedded Security Data Lake Engine
 * In-process, zero-dependency SQL analytics over security telemetry
 * (Falco alerts, Zeek conn/dns logs, Suricata eve, K8s audit, and CTI hits).
 * Supports retrospective threat hunting against newly ingested IOCs.
 */

import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { getVigilanteDatalakeDir } from './config.js';
import { logger } from '../utils/logger.js';

const require = createRequire(import.meta.url);

let DatabaseSync = null;
try {
  const sqlite = require('node:sqlite');
  DatabaseSync = sqlite.DatabaseSync || null;
} catch {
  try {
    DatabaseSync = require('better-sqlite3');
  } catch {
    DatabaseSync = null;
  }
}

let dbInstance = null;
let activeBackend = 'sqlite';

/**
 * Attempt to load the official DuckDB driver if installed
 * @returns {Object|null}
 */
function tryLoadDuckDb() {
  try {
    return require('duckdb');
  } catch {
    try {
      return require('@duckdb/node-api');
    } catch {
      return null;
    }
  }
}

/**
 * Returns the currently active Data Lake SQL engine backend ('sqlite' or 'duckdb')
 * @returns {'sqlite'|'duckdb'}
 */
export function getDataLakeBackend() {
  return activeBackend;
}

/**
 * Get or initialize embedded Data Lake database instance.
 * Defaults to built-in zero-dependency SQLite (free first),
 * with support for official DuckDB when requested/installed.
 * @param {string|Object} [customPathOrOptions='']
 * @param {Object} [options={}]
 * @returns {DatabaseSync|Object}
 */
export function initDataLake(customPathOrOptions = '', options = {}) {
  let opts = options;
  let dbPath = customPathOrOptions;

  if (typeof customPathOrOptions === 'object' && customPathOrOptions !== null) {
    opts = customPathOrOptions;
    dbPath = opts.customPath || opts.path || '';
  }

  if (dbInstance) return dbInstance;

  const preferredBackend = (opts.backend || process.env.VIGILANTE_DATALAKE_BACKEND || 'auto').toLowerCase();
  const duckdbPkg = (preferredBackend === 'duckdb' || preferredBackend === 'official') ? tryLoadDuckDb() : null;

  if ((preferredBackend === 'duckdb' || preferredBackend === 'official') && !duckdbPkg) {
    logger.warn(
      'DATALAKE',
      "Official DuckDB backend requested ('duckdb'), but 'duckdb' package is not installed. Falling back to built-in zero-dependency high-throughput SQLite engine."
    );
  }

  if (!dbPath) {
    const lakeDir = getVigilanteDatalakeDir();
    if (!fsSync.existsSync(lakeDir)) {
      fsSync.mkdirSync(lakeDir, { recursive: true });
    }
    const ext = (duckdbPkg && (preferredBackend === 'duckdb' || preferredBackend === 'official')) ? 'duckdb' : 'db';
    dbPath = path.join(lakeDir, `events.${ext}`);
  }

  // Official DuckDB Adapter (when installed and requested)
  if (duckdbPkg && (preferredBackend === 'duckdb' || preferredBackend === 'official')) {
    activeBackend = 'duckdb';
    const ddb = new duckdbPkg.Database(dbPath);
    ddb.run(`
      CREATE TABLE IF NOT EXISTS security_events (
        id VARCHAR PRIMARY KEY,
        event_type VARCHAR NOT NULL,
        source_pod VARCHAR,
        source_ip VARCHAR,
        dest_ip VARCHAR,
        dest_port INTEGER,
        severity VARCHAR NOT NULL,
        mitre_technique VARCHAR,
        indicator VARCHAR,
        raw_json VARCHAR,
        timestamp VARCHAR NOT NULL
      );
    `);
    logger.info('DATALAKE', `Initialized Official DuckDB Security Data Lake at ${dbPath}`);
    dbInstance = {
      backend: 'duckdb',
      rawDb: ddb,
      exec: (sql) => ddb.exec(sql),
      close: () => ddb.close(),
      prepare: (sql) => ({
        all: (...params) => {
          let rows = [];
          ddb.all(sql, ...params, (err, res) => {
            if (err) throw err;
            rows = res;
          });
          return rows;
        },
        run: (...params) => {
          ddb.run(sql, ...params);
        }
      })
    };
    return dbInstance;
  }

  // Free First: Built-in Node.js SQLite (DatabaseSync)
  activeBackend = 'sqlite';
  if (!DatabaseSync) {
    throw new Error(
      "SQLite engine unavailable: built-in 'node:sqlite' requires Node.js >= 22.5.0, or install 'better-sqlite3' / 'duckdb'."
    );
  }
  const db = new DatabaseSync(dbPath);

  // Initialize unified security events schema
  db.exec(`
    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      source_pod TEXT,
      source_ip TEXT,
      dest_ip TEXT,
      dest_port INTEGER,
      severity TEXT NOT NULL,
      mitre_technique TEXT,
      indicator TEXT,
      raw_json TEXT,
      timestamp TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_events_type ON security_events(event_type);
    CREATE INDEX IF NOT EXISTS idx_events_src ON security_events(source_ip);
    CREATE INDEX IF NOT EXISTS idx_events_dst ON security_events(dest_ip);
    CREATE INDEX IF NOT EXISTS idx_events_indicator ON security_events(indicator);
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON security_events(timestamp);
  `);

  logger.info('DATALAKE', `Initialized Security Data Lake (${activeBackend}) at ${dbPath}`);
  dbInstance = db;
  return db;
}

/**
 * Close Data Lake database instance (useful for clean test teardowns)
 */
export function closeDataLake() {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch {
      // Ignore
    }
    dbInstance = null;
    activeBackend = 'sqlite';
  }
}

/**
 * Ingest an array of normalized security events into the Data Lake
 * @param {string} eventType e.g. 'falco', 'zeek', 'suricata', 'audit', 'canary'
 * @param {Array<Object>} events List of event objects
 * @returns {number} Count of successfully ingested records
 */
export function ingestSecurityEvents(eventType, events = []) {
  const db = initDataLake();
  if (!events || events.length === 0) return 0;

  const insertStmt = db.prepare(`
    INSERT OR REPLACE INTO security_events (
      id, event_type, source_pod, source_ip, dest_ip, dest_port, severity, mitre_technique, indicator, raw_json, timestamp
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  db.exec('BEGIN TRANSACTION');
  let inserted = 0;

  try {
    for (const ev of events) {
      const id = ev.id || `${eventType}-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
      const srcPod = ev.sourcePod || ev.pod || ev.podName || null;
      const srcIp = ev.sourceIp || ev.srcIp || ev.src || null;
      const dstIp = ev.destIp || ev.dstIp || ev.dst || null;
      const dstPort = ev.destPort || ev.dstPort || ev.port || null;
      const severity = (ev.severity || 'INFO').toUpperCase();
      const mitre = ev.mitreTechnique || ev.technique || null;
      const indicator = ev.indicator || ev.ioc || ev.query || null;
      const rawJson = typeof ev === 'string' ? ev : JSON.stringify(ev);
      const ts = ev.timestamp || new Date().toISOString();

      insertStmt.run(id, eventType, srcPod, srcIp, dstIp, dstPort ? Number(dstPort) : null, severity, mitre, indicator, rawJson, ts);
      inserted++;
    }
    db.exec('COMMIT');
    logger.info('DATALAKE', `Ingested ${inserted} [${eventType}] records into Data Lake.`);
  } catch (err) {
    db.exec('ROLLBACK');
    logger.error('DATALAKE', `Ingestion failed: ${err.message}`);
    throw err;
  }

  return inserted;
}

/**
 * Execute an analytical SQL query across Data Lake events
 * @param {string} sql 
 * @param {Array<any>} [params=[]]
 * @returns {Array<Object>} Row results
 */
export function queryDataLake(sql, params = []) {
  const db = initDataLake();
  const stmt = db.prepare(sql);
  return stmt.all(...params);
}

/**
 * Perform a retrospective threat hunt across historical events matching CTI indicators
 * @param {Array<string|Object>} indicators List of IPs, domains, or hash strings
 * @returns {Array<Object>} Historical matches
 */
export function runRetrospectiveThreatHunt(indicators = []) {
  const db = initDataLake();
  const matches = [];

  for (const item of indicators) {
    const val = typeof item === 'string' ? item : (item.ip || item.domain || item.hash || '');
    if (!val) continue;

    const query = `
      SELECT id, event_type, source_pod, source_ip, dest_ip, dest_port, severity, mitre_technique, indicator, timestamp
      FROM security_events
      WHERE source_ip = ? OR dest_ip = ? OR indicator LIKE ? OR raw_json LIKE ?
      ORDER BY timestamp DESC
      LIMIT 100
    `;

    const rows = db.prepare(query).all(val, val, `%${val}%`, `%${val}%`);
    if (rows && rows.length > 0) {
      matches.push({
        indicator: val,
        matchCount: rows.length,
        firstSeen: rows[rows.length - 1].timestamp,
        lastSeen: rows[0].timestamp,
        affectedPods: Array.from(new Set(rows.map(r => r.source_pod).filter(Boolean))),
        events: rows
      });
    }
  }

  logger.info('DATALAKE', `Retrospective threat hunt completed: ${matches.length} matched indicators found.`);
  return matches;
}
