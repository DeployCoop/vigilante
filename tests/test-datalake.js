import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  initDataLake,
  closeDataLake,
  getDataLakeBackend,
  ingestSecurityEvents,
  queryDataLake,
  runRetrospectiveThreatHunt
} from '../src/engine/datalake.js';

async function runTests() {
  console.log('🧪 Testing High-Throughput Embedded Security Data Lake Engine...');

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-datalake-'));
  const testDb = path.join(tempDir, 'events.db');

  // Test 1: Initialize Data Lake
  initDataLake(testDb);
  const backend = getDataLakeBackend();
  if (backend !== 'sqlite') throw new Error(`Expected default backend 'sqlite', got: ${backend}`);
  console.log(`✔ Test 1 passed: Embedded Data Lake schema initialized with indexes (Active Backend: ${backend}).`);

  // Test 2: Ingest Security Telemetry
  const mockFalcoEvents = [
    {
      sourcePod: 'nginx-ingress-x7',
      sourceIp: '10.42.0.77',
      destIp: '185.220.101.5',
      destPort: 443,
      severity: 'CRITICAL',
      mitreTechnique: 'T1071.001',
      indicator: 'c2.evil-tracker.org',
      timestamp: '2026-09-26T20:00:00Z'
    },
    {
      sourcePod: 'auth-service',
      sourceIp: '10.42.0.88',
      destIp: '10.42.0.77',
      destPort: 445,
      severity: 'HIGH',
      mitreTechnique: 'T1021.002',
      indicator: 'smb_lateral',
      timestamp: '2026-09-26T20:05:00Z'
    },
    {
      sourcePod: 'payment-worker',
      sourceIp: '10.42.0.99',
      destIp: '8.8.8.8',
      destPort: 53,
      severity: 'INFO',
      mitreTechnique: null,
      indicator: 'google.com',
      timestamp: '2026-09-26T20:10:00Z'
    }
  ];

  const count = ingestSecurityEvents('falco', mockFalcoEvents);
  if (count !== 3) throw new Error(`Expected 3 records ingested, got: ${count}`);
  console.log(`✔ Test 2 passed: Ingested ${count} telemetry records into Data Lake.`);

  // Test 3: SQL Analytical Queries
  const results = queryDataLake(`
    SELECT event_type, count(*) as count, max(severity) as max_severity
    FROM security_events
    GROUP BY event_type
  `);

  if (results.length !== 1 || results[0].count !== 3) {
    throw new Error('Unexpected SQL aggregation result');
  }
  console.log(`✔ Test 3 passed: Analytical SQL aggregation returned ${results[0].count} events.`);

  // Test 4: Retrospective Threat Hunt against CTI Indicators
  const ctiIocs = ['185.220.101.5', 'c2.evil-tracker.org', '1.1.1.1'];
  const huntResults = runRetrospectiveThreatHunt(ctiIocs);
  if (huntResults.length !== 2) throw new Error(`Expected 2 historical threat matches, got: ${huntResults.length}`);
  const match = huntResults.find(h => h.indicator === '185.220.101.5');
  if (!match || !match.affectedPods.includes('nginx-ingress-x7')) {
    throw new Error('Failed to associate retrospective hit with affected pod');
  }
  console.log(`✔ Test 4 passed: Retrospective threat hunt uncovered historical beaconing from pod: ${match.affectedPods[0]}.`);

  closeDataLake();

  // Test 5: Verify official DuckDB request falls back gracefully when uninstalled
  const testDb2 = path.join(tempDir, 'duckdb-fallback.db');
  initDataLake({ backend: 'duckdb', customPath: testDb2 });
  const fallbackBackend = getDataLakeBackend();
  if (fallbackBackend !== 'sqlite') throw new Error(`Expected fallback to 'sqlite', got: ${fallbackBackend}`);
  console.log('✔ Test 5 passed: Official DuckDB requested falls back gracefully to zero-dependency SQLite when uninstalled.');
  closeDataLake();

  console.log('🎉 ALL 5 DATA LAKE TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Data Lake test failure:', err);
  process.exit(1);
});
