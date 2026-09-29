import assert from 'node:assert';
import {
  createSwarmDuel,
  executeDuelRound,
  runFullDuelSimulation,
  evaluateDuelMetrics,
  generateDuelTranscript,
  DUEL_OUTCOMES,
  ATTACK_PHASES
} from '../src/engine/swarmduel.js';

async function runTests() {
  console.log('🧪 Testing Autonomous Adversarial Swarm Duel ("Cyber Range") Engine...');

  // Test 1: createSwarmDuel initialization
  const duel = createSwarmDuel({ maxRounds: 4, crownJewel: 'k8s-etcd-vault' });
  assert.strictEqual(duel.status, 'ACTIVE');
  assert.strictEqual(duel.round, 0);
  assert.strictEqual(duel.maxRounds, 4);
  assert.strictEqual(duel.crownJewel, 'k8s-etcd-vault');
  assert.strictEqual(duel.currentPhaseIndex, 0);
  assert.strictEqual(duel.isContained, false);
  console.log(`✔ Test 1 passed: createSwarmDuel initialized duel [${duel.duelId}] targeting '${duel.crownJewel}'.`);

  // Test 2: executeDuelRound single-turn progression
  const round1 = executeDuelRound(duel, { forceRedSuccess: true, forceBlueDetect: false });
  assert.strictEqual(duel.round, 1);
  assert.strictEqual(round1.redAction.agent, 'ReconAgent');
  assert.strictEqual(round1.redAction.phase, 'RECONNAISSANCE');
  assert.strictEqual(round1.blueAction.success, false);
  assert.strictEqual(duel.scores.redTeam, 20);
  assert.strictEqual(duel.currentPhaseIndex, 1); // progressed to INITIAL_ACCESS
  console.log('✔ Test 2 passed: executeDuelRound progressed Red swarm to INITIAL_ACCESS while evading Blue sensors.');

  // Test 3: Round 2 with Blue Detection & Tactical Triage
  const round2 = executeDuelRound(duel, { forceRedSuccess: true, forceBlueDetect: true });
  assert.strictEqual(duel.round, 2);
  assert.strictEqual(duel.firstDetectedRound, 2);
  assert.strictEqual(round2.blueAction.action, 'TACTICAL_TRIAGE');
  assert.strictEqual(round2.blueAction.success, true);
  console.log('✔ Test 3 passed: Round 2 triggered Blue swarm detection and alert triage.');

  // Test 4: Full Simulation resulting in Blue Team Containment Victory
  const blueSim = runFullDuelSimulation({
    maxRounds: 5,
    forceRedSuccess: true,
    forceBlueDetect: true
  });
  assert.strictEqual(blueSim.duelState.status, 'COMPLETED');
  assert.strictEqual(blueSim.duelState.outcome, DUEL_OUTCOMES.BLUE_TEAM_VICTORY_CONTAINED);
  assert.strictEqual(blueSim.metrics.winner, 'BLUE_TEAM');
  assert.strictEqual(blueSim.metrics.containmentRatio, 1.0);
  assert.ok(blueSim.metrics.mttdRounds <= 2);
  console.log(`✔ Test 4 passed: runFullDuelSimulation completed with ${blueSim.metrics.winner} in round ${blueSim.duelState.round}.`);

  // Test 5: Full Simulation resulting in Red Team Exfiltration Victory
  const redSim = runFullDuelSimulation({
    maxRounds: 6,
    forceRedSuccess: true,
    forceBlueDetect: false // Blue team never detects
  });
  assert.strictEqual(redSim.duelState.status, 'COMPLETED');
  assert.strictEqual(redSim.duelState.outcome, DUEL_OUTCOMES.RED_TEAM_VICTORY_EXFILTRATED);
  assert.strictEqual(redSim.metrics.winner, 'RED_TEAM');
  assert.strictEqual(redSim.metrics.compromisePercentage, 100);
  console.log(`✔ Test 5 passed: runFullDuelSimulation simulated stealthy APT exfiltration (Compromise: ${redSim.metrics.compromisePercentage}%).`);

  // Test 6: Transcript Generation
  const transcript = generateDuelTranscript(blueSim.duelState);
  assert.ok(transcript.includes('SWARM DUEL CYBER RANGE BATTLE'));
  assert.ok(transcript.includes('ROUND 1'));
  assert.ok(transcript.includes('BLUE_TEAM_VICTORY_CONTAINED'));
  console.log('✔ Test 6 passed: generateDuelTranscript formatted complete battle log.');

  console.log('🎉 All Autonomous Adversarial Swarm Duel tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ Swarm Duel tests failed:', err);
  process.exit(1);
});
