import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import {
  WARGAME_SCENARIOS,
  runPurpleTeamSimulation,
  calculatePurpleScorecard,
  generatePurpleReport,
  savePurpleReport
} from '../src/engine/purpleteam.js';

async function runTests() {
  console.log('🧪 Testing Autonomous Purple Team Arena...');

  // Setup isolated XDG config home
  const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-test-purple-'));
  process.env.XDG_CONFIG_HOME = tempDir;

  // Test 1: Verify Scenarios Catalog
  const scenarios = Object.keys(WARGAME_SCENARIOS);
  if (!scenarios.includes('lateral-smb-exfil') || !scenarios.includes('container-escape-privileged')) {
    throw new Error('Missing expected default wargame scenarios');
  }
  console.log(`✔ Test 1 passed: Validated ${scenarios.length} pre-configured wargame scenarios.`);

  // Test 2: Run Purple Team Simulation
  const sim = await runPurpleTeamSimulation('lateral-smb-exfil');
  if (!sim.simulationId) throw new Error('Missing simulationId');
  if (!sim.isContained) throw new Error('Expected adversary to be contained by SOAR');
  if (sim.containmentStep !== 3) throw new Error(`Expected containment at step 3, got: ${sim.containmentStep}`);
  console.log(`✔ Test 2 passed: Simulation executed (${sim.simulationId}) - Adversary contained at Step ${sim.containmentStep}.`);

  // Test 3: Calculate Scorecard
  const scorecard = calculatePurpleScorecard(sim);
  if (!scorecard.grade) throw new Error('Missing grade in scorecard');
  if (scorecard.mttdSec <= 0 || scorecard.mttrSec <= 0) throw new Error('Invalid MTTD/MTTR telemetry');
  console.log(`✔ Test 3 passed: Scorecard generated: Grade [${scorecard.grade}] (${scorecard.score}/100), MTTD: ${scorecard.mttdSec}s, MTTR: ${scorecard.mttrSec}s.`);

  // Test 4: Generate Markdown Report & Persist
  const reportPath = await savePurpleReport(sim, scorecard);
  const exists = await fs.access(reportPath).then(() => true).catch(() => false);
  if (!exists) throw new Error('Purple Team report file was not persisted');
  console.log(`✔ Test 4 passed: Executive Markdown report rendered and saved to ${reportPath}.`);

  console.log('🎉 ALL 4 PURPLE TEAM TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Purple Team test failure:', err);
  process.exit(1);
});
