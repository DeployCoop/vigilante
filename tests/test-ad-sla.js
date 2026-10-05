import assert from 'node:assert';
import { TournamentEngine, TOURNAMENT_MODES } from '../src/engine/tournament.js';
import {
  AttackDefenseRunner,
  generateAdTickFlag,
  parseAdFlag,
  SLA_STATUS
} from '../src/engine/ad-runner.js';

console.log('🧪 Testing Autonomous Attack-Defense SLA Runner & Dynamic Flag Injector...');

// Setup test tournament
const engine = new TournamentEngine({
  id: 'ad-test-cup',
  title: 'AD Test Cup',
  modes: [TOURNAMENT_MODES.ATTACK_DEFENSE]
});
engine.start({ durationHours: 2 });

// Register 3 teams
const teamRed = engine.registerTeam({ name: 'Red Dragons' });
const teamBlue = engine.registerTeam({ name: 'Blue Phantoms' });
const teamGreen = engine.registerTeam({ name: 'Green Vipers' });

// Instantiate AttackDefenseRunner
const runner = new AttackDefenseRunner({
  tournamentEngine: engine,
  tickDurationSeconds: 60,
  defensePointsPerTick: 100,
  attackPointsPerCapture: 150,
  slaPenaltyDown: 50,
  slaPenaltyFaulty: 25,
  flagGraceTicks: 1,
  mockProbes: true
});

// Test 1: Flag generation & parsing
const testFlag = generateAdTickFlag({
  teamId: teamRed.id,
  serviceId: 'ad-service-vault',
  tick: 1,
  secretKey: engine.secretKey
});
assert.ok(testFlag.startsWith('VIGILANTE{ad__ad-service-vault__' + teamRed.id + '__t1_'));
const parsed = parseAdFlag(testFlag);
assert.strictEqual(parsed.teamId, teamRed.id);
assert.strictEqual(parsed.serviceId, 'ad-service-vault');
assert.strictEqual(parsed.tick, 1);
assert.ok(parsed.token.length >= 16);
console.log('✔ Test 1 passed: Deterministic AD tick flags generated and parsed.');

// Test 2: Execute Tick #1 with all services UP
const round1 = await runner.stepTick();
assert.strictEqual(round1.tick, 1);
assert.strictEqual(engine.adState.currentTick, 1);
// All 3 teams should receive 100 defense points because all were UP and none attacked yet
assert.strictEqual(teamRed.adDefenseScore, 100);
assert.strictEqual(teamBlue.adDefenseScore, 100);
assert.strictEqual(teamGreen.adDefenseScore, 100);
console.log('✔ Test 2 passed: Tick #1 executed; UP services awarded defense points.');

// Test 3: Attack Flag Submission during Tick #1
// Blue captures Red's tick 1 flag
const redTick1Flag = runner.injectedFlags.get(`ad-service-vault:${teamRed.id}:1`).flag;
const attackRes = runner.submitAttackFlag({
  attackerTeamId: teamBlue.id,
  flag: redTick1Flag
});
assert.strictEqual(attackRes.success, true);
assert.strictEqual(attackRes.awardedPoints, 150);
assert.strictEqual(teamBlue.adAttackScore, 150);
assert.strictEqual(teamBlue.score, 250); // 100 defense + 150 attack
console.log('✔ Test 3 passed: Valid adversary flag capture verified and attack points awarded.');

// Test 4: Prevent duplicate attack flag submission by same team
const dupAttackRes = runner.submitAttackFlag({
  attackerTeamId: teamBlue.id,
  flag: redTick1Flag
});
assert.strictEqual(dupAttackRes.success, false);
assert.ok(dupAttackRes.reason.includes('already submitted'));
console.log('✔ Test 4 passed: Duplicate attack submissions prevented.');

// Test 5: Prevent self-flag submission
const selfAttackRes = runner.submitAttackFlag({
  attackerTeamId: teamRed.id,
  flag: redTick1Flag
});
assert.strictEqual(selfAttackRes.success, false);
assert.ok(selfAttackRes.reason.includes('stolen from your own team'));
console.log('✔ Test 5 passed: Self-flag capture submissions blocked.');

// Test 6: Tick #2 with simulated service states (Red FAULTY, Green DOWN, Blue UP)
runner.setMockProbeResult(teamRed.id, 'ad-service-vault', { status: SLA_STATUS.FAULTY, latencyMs: 250 });
runner.setMockProbeResult(teamGreen.id, 'ad-service-vault', { status: SLA_STATUS.DOWN, latencyMs: 1500 });
runner.setMockProbeResult(teamBlue.id, 'ad-service-vault', { status: SLA_STATUS.UP, latencyMs: 30 });

const round2 = await runner.stepTick();
assert.strictEqual(round2.tick, 2);
// Red: FAULTY -> docks 25 SLA penalty, no defense points
assert.strictEqual(round2.services[teamRed.id]['ad-service-vault'].slaStatus, SLA_STATUS.FAULTY);
assert.strictEqual(teamRed.adSlaScore, -25);

// Green: DOWN -> docks 50 SLA penalty, no defense points
assert.strictEqual(round2.services[teamGreen.id]['ad-service-vault'].slaStatus, SLA_STATUS.DOWN);
assert.strictEqual(teamGreen.adSlaScore, -50);

// Blue: UP -> awards 100 defense points
assert.strictEqual(round2.services[teamBlue.id]['ad-service-vault'].slaStatus, SLA_STATUS.UP);
assert.strictEqual(teamBlue.adDefenseScore, 200); // 100 from tick 1 + 100 from tick 2
console.log('✔ Test 6 passed: SLA probes evaluated and penalties/defense points applied correctly.');

// Test 7: Grace tick flag submission (Tick 1 flag submitted in Tick 2 is allowed)
const greenTick1Flag = runner.injectedFlags.get(`ad-service-vault:${teamGreen.id}:1`).flag;
const graceAttackRes = runner.submitAttackFlag({
  attackerTeamId: teamRed.id,
  flag: greenTick1Flag
});
assert.strictEqual(graceAttackRes.success, true);
assert.strictEqual(teamRed.adAttackScore, 150);
console.log('✔ Test 7 passed: Flag submitted within 1 grace tick window accepted.');

// Test 8: Generate live PCAP network trace for team defense analysis
const pcap = runner.generateAdTrafficPcap({ teamId: teamRed.id, tick: 2 });
assert.strictEqual(pcap.teamId, teamRed.id);
assert.strictEqual(pcap.tick, 2);
assert.strictEqual(pcap.contentType, 'application/vnd.tcpdump.pcap');
assert.ok(pcap.byteLength > 24, 'PCAP buffer must contain header and packet bytes');
// Verify PCAP magic bytes 0xa1b2c3d4 in little-endian (0xd4, 0xc3, 0xb2, 0xa1)
assert.strictEqual(pcap.buffer[0], 0xd4);
assert.strictEqual(pcap.buffer[1], 0xc3);
assert.strictEqual(pcap.buffer[2], 0xb2);
assert.strictEqual(pcap.buffer[3], 0xa1);
console.log('✔ Test 8 passed: Valid PCAP traffic capture generated for adversary analysis.');

console.log('\n🎉 All Autonomous Attack-Defense SLA Runner tests passed successfully!\n');
