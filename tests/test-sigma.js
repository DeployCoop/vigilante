import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  parseSigmaRule,
  transpileSigmaToSql,
  runSigmaThreatHunt,
  generateHypothesisForTechnique
} from '../src/engine/sigma.js';
import {
  initDataLake,
  closeDataLake,
  ingestSecurityEvents
} from '../src/engine/datalake.js';

async function runTests() {
  console.log('🧪 Testing SIGMA-to-SQL Detection Transpiler & Threat Hunt Engine...');

  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-sigma-'));
  const testDb = path.join(tempDir, 'events.db');
  initDataLake(testDb);

  // Test 1: Parse YAML SIGMA Rule
  const sampleYaml = `
title: Suspicious SMB Lateral Connection
status: experimental
description: Detects East-West SMB traffic to sensitive ports
level: high
tags:
  - attack.t1021.002
logsource:
  category: network_connection
detection:
  selection:
    destination.port: 445
    severity: HIGH
  condition: selection
`;

  const parsed = parseSigmaRule(sampleYaml);
  if (parsed.title !== 'Suspicious SMB Lateral Connection') {
    throw new Error(`Failed to parse title: ${parsed.title}`);
  }
  if (!parsed.detection.selection) {
    throw new Error('Failed to parse detection selection');
  }
  console.log('✔ Test 1 passed: Successfully parsed SIGMA YAML specification.');

  // Test 2: Transpile to ANSI SQL
  const transpiled = transpileSigmaToSql(parsed);
  if (!transpiled.sql.includes('dest_port = 445') || !transpiled.sql.includes("severity = 'HIGH'")) {
    throw new Error(`Unexpected SQL generation: ${transpiled.sql}`);
  }
  if (transpiled.technique !== 'T1021.002') {
    throw new Error(`Expected technique T1021.002, got: ${transpiled.technique}`);
  }
  console.log(`✔ Test 2 passed: Transpiled SIGMA rule to ANSI SQL: ${transpiled.sql}`);

  // Test 3: Complex Boolean & Modifiers Transpilation (1 of selection*, contains)
  const complexRule = {
    title: 'Multi-Condition Threat',
    level: 'critical',
    detection: {
      selection_port: {
        'destination.port': 443
      },
      selection_ioc: {
        'indicator|contains': 'malicious-c2'
      },
      condition: 'selection_port and selection_ioc'
    }
  };

  const complexTranspiled = transpileSigmaToSql(complexRule);
  if (!complexTranspiled.sql.includes('dest_port = 443') || !complexTranspiled.sql.includes("indicator LIKE '%malicious-c2%'")) {
    throw new Error(`Complex transpilation failed: ${complexTranspiled.sql}`);
  }
  console.log('✔ Test 3 passed: Transpiled complex boolean and modifier selections.');

  // Test 4: Ingest Telemetry & Execute Automated Threat Hunt
  const mockEvents = [
    {
      sourcePod: 'auth-service',
      sourceIp: '10.42.0.88',
      destIp: '10.42.0.77',
      destPort: 445,
      severity: 'HIGH',
      indicator: 'smb_lateral',
      timestamp: '2026-09-27T01:00:00Z'
    },
    {
      sourcePod: 'frontend',
      sourceIp: '10.42.0.12',
      destIp: '1.1.1.1',
      destPort: 53,
      severity: 'INFO',
      indicator: 'dns',
      timestamp: '2026-09-27T01:05:00Z'
    }
  ];

  ingestSecurityEvents('network', mockEvents);
  const huntMatches = runSigmaThreatHunt([parsed]);
  if (huntMatches.length !== 1 || huntMatches[0].matchCount !== 1) {
    throw new Error(`Expected 1 hunt match, got: ${huntMatches.length}`);
  }
  if (!huntMatches[0].affectedPods.includes('auth-service')) {
    throw new Error('Failed to identify affected pod in hunt match');
  }
  console.log(`✔ Test 4 passed: Automated SIGMA hunt matched ${huntMatches[0].matchCount} incident in Data Lake.`);

  // Test 5: MITRE Technique Hypothesis Generation
  const hypothesis = generateHypothesisForTechnique('T1059.004');
  if (!hypothesis.hypothesis || !hypothesis.sql.includes('indicator LIKE')) {
    throw new Error('Failed to generate hypothesis for T1059.004');
  }
  console.log(`✔ Test 5 passed: Generated threat hunt hypothesis for MITRE ${hypothesis.technique}.`);

  closeDataLake();
  console.log('🎉 ALL 5 SIGMA TRANSPILER TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ SIGMA test failure:', err);
  process.exit(1);
});
