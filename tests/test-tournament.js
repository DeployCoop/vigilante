import assert from 'node:assert';
import {
  TournamentEngine,
  calculateDynamicPoints,
  generateTeamDynamicFlag,
  TOURNAMENT_MODES,
  TOURNAMENT_STATES
} from '../src/engine/tournament.js';

console.log('🧪 Testing Multi-Mode Tournament Engine (Jeopardy, Attack-Defense, KotH)...');

// Test 1: Dynamic points calculation
assert.strictEqual(calculateDynamicPoints({ initialPoints: 500, minimumPoints: 100, decaySolves: 30, solveCount: 0 }), 500);
assert.strictEqual(calculateDynamicPoints({ initialPoints: 500, minimumPoints: 100, decaySolves: 30, solveCount: 1 }), 500);
const midDecay = calculateDynamicPoints({ initialPoints: 500, minimumPoints: 100, decaySolves: 30, solveCount: 15 });
assert.ok(midDecay < 500 && midDecay > 100, `Mid decay points must be between 100 and 500: got ${midDecay}`);
assert.strictEqual(calculateDynamicPoints({ initialPoints: 500, minimumPoints: 100, decaySolves: 30, solveCount: 30 }), 100);
assert.strictEqual(calculateDynamicPoints({ initialPoints: 500, minimumPoints: 100, decaySolves: 30, solveCount: 50 }), 100);
console.log('✔ Test 1 passed: Dynamic decay scoring algorithm validated.');

// Test 2: Per-team dynamic flag generation
const flagTeamA = generateTeamDynamicFlag({ teamId: 'team_01', challengeId: 'pwn-rop', secretKey: 'topsecret' });
const flagTeamB = generateTeamDynamicFlag({ teamId: 'team_02', challengeId: 'pwn-rop', secretKey: 'topsecret' });
assert.ok(flagTeamA.startsWith('VIGILANTE{pwn-rop_team_01_'));
assert.ok(flagTeamB.startsWith('VIGILANTE{pwn-rop_team_02_'));
assert.notStrictEqual(flagTeamA, flagTeamB, 'Team flags must be cryptographically distinct');
console.log('✔ Test 2 passed: Deterministic per-team dynamic flags generated and differentiated.');

// Test 3: Tournament instantiation & Team registration
const engine = new TournamentEngine({
  id: 'cup-2026',
  title: 'Vigilante Invitational CTF',
  initialPoints: 500,
  minimumPoints: 100,
  decaySolves: 20
});
assert.strictEqual(engine.state, TOURNAMENT_STATES.DRAFT);
const team1 = engine.registerTeam({ name: 'CyberWarriors', email: 'team1@example.com' });
const team2 = engine.registerTeam({ name: 'BitBusters', email: 'team2@example.com' });
assert.ok(team1.id && team1.token);
assert.strictEqual(engine.teams.size, 2);
console.log('✔ Test 3 passed: Team registration and token generation succeeded.');

// Test 4: Duplicate team name protection
assert.throws(() => {
  engine.registerTeam({ name: 'Cyberwarriors' });
}, /already registered/);
console.log('✔ Test 4 passed: Duplicate team registration prevented.');

// Test 5: Challenge catalog & Tournament startup
const chal1 = engine.addChallenge({
  id: 'web-sqli',
  name: 'SQLi Directory',
  category: 'web',
  port: 8082,
  isDynamicFlag: true
});
const chal2 = engine.addChallenge({
  id: 'pwn-nsjail',
  name: 'nsjail Echo',
  category: 'pwn',
  port: 31337,
  isDynamicFlag: true
});
engine.start({ durationHours: 2, freezeHoursBeforeEnd: 0.5 });
assert.strictEqual(engine.state, TOURNAMENT_STATES.ACTIVE);
assert.ok(engine.startTime && engine.endTime);
console.log('✔ Test 5 passed: Tournament started and challenges indexed.');

// Test 6: First Blood solve & dynamic flag submission
const flag1 = generateTeamDynamicFlag({ teamId: team1.id, challengeId: 'web-sqli', secretKey: engine.secretKey });
const solveResult1 = engine.submitFlag({ teamId: team1.id, challengeId: 'web-sqli', flag: flag1 });
assert.strictEqual(solveResult1.success, true);
assert.strictEqual(solveResult1.bloodBadge, '🩸', 'First solve must receive First Blood badge');
assert.ok(solveResult1.firstBloodBonus > 0, 'First solve must earn blood bonus');
assert.strictEqual(team1.solves.length, 1);
console.log(`✔ Test 6 passed: Team 1 achieved First Blood on web-sqli (+${solveResult1.points} pts).`);

// Test 7: Anti-cheat collusion detection (Flag sharing)
const solveCollusion = engine.submitFlag({
  teamId: team2.id,
  challengeId: 'web-sqli',
  flag: flag1 // Team 2 submitting Team 1's flag!
});
assert.strictEqual(solveCollusion.success, false);
assert.ok(solveCollusion.reason.includes('Security anomaly'), 'Must reject shared dynamic flags');
assert.strictEqual(engine.alerts.length, 1);
assert.strictEqual(engine.alerts[0].type, 'COLLUSION_DETECTED');
console.log('✔ Test 7 passed: Anti-cheat detected and blocked dynamic flag sharing between teams.');

// Test 8: Attack-Defense Tick Simulation
engine.adState.services.push({ id: 'auth-service', name: 'Auth Gateway', port: 9000 });
const tickResult = engine.runAttackDefenseTick({
  slaResults: {
    [`${team1.id}_auth-service`]: true,
    [`${team2.id}_auth-service`]: false // Team 2 service crashed / offline
  }
});
assert.strictEqual(tickResult.tick, 1);
assert.ok(team1.adDefenseScore > team2.adDefenseScore, 'Team with passing SLA earns defense points');
console.log('✔ Test 8 passed: Attack-Defense tick evaluated SLA and awarded defense points.');

// Test 9: King of the Hill (KotH) Claim & Tick
const claimRes = engine.claimHill({ hillId: 'citadel-01', teamId: team2.id });
assert.strictEqual(claimRes.success, true);
assert.strictEqual(claimRes.king, 'BitBusters');
const kothTick = engine.runKothTick();
assert.strictEqual(kothTick.tick, 1);
assert.strictEqual(kothTick.awards[0].kingName, 'BitBusters');
assert.strictEqual(kothTick.awards[0].points, 25);
console.log('✔ Test 9 passed: King of the Hill claimed and tick awarded crown points.');

// Test 10: Leaderboard sorting & tie-breaking
const leaderboard = engine.getLeaderboard();
assert.strictEqual(leaderboard.length, 2);
assert.strictEqual(leaderboard[0].rank, 1);
assert.ok(leaderboard[0].totalScore >= leaderboard[1].totalScore);
console.log(`✔ Test 10 passed: Leaderboard computed. #1: ${leaderboard[0].name} (${leaderboard[0].totalScore} pts).`);

// Test 11: Live Event Bus Subscription & Broadcast
const capturedEvents = [];
engine.onEvent((ev) => capturedEvents.push(ev));
engine.broadcastEvent('ADMIN_BROADCAST', { message: 'Tournament final hour commencing!' });
assert.strictEqual(capturedEvents.length, 1);
assert.strictEqual(capturedEvents[0].type, 'ADMIN_BROADCAST');
assert.strictEqual(capturedEvents[0].message, 'Tournament final hour commencing!');
console.log('✔ Test 11 passed: Live event bus publishes and broadcasts tournament notifications.');

// Test 12: Socratic Hint Unlock & Score Penalty
const scoreBeforeHint = team1.score;
const hintRes = engine.unlockHint({ teamId: team1.id, challengeId: 'pwn-nsjail', tier: 2 });
assert.strictEqual(hintRes.success, true);
assert.strictEqual(hintRes.tier, 2);
assert.strictEqual(hintRes.penaltyPoints, 50); // 10% of 500 initial points
assert.strictEqual(team1.score, scoreBeforeHint - 50);
console.log(`✔ Test 12 passed: Tier 2 Socratic hint unlocked with accurate point deduction (-${hintRes.penaltyPoints} pts).`);

// Test 13: Time-Series Score Curves & Solve Matrix
const curveData = engine.getScoreProgressionData();
assert.strictEqual(curveData.length, 2);
const svg = engine.renderScoreCurvesSvg();
assert.ok(svg.includes('<svg'));
assert.ok(svg.includes('<polyline'));
assert.ok(svg.includes('POINTS'));

const matrix = engine.getSolveMatrix();
assert.strictEqual(matrix.challenges.length, 2);
assert.strictEqual(matrix.matrix.length, 2);
assert.strictEqual(matrix.matrix[0].challenges['web-sqli'].solved, true);
assert.strictEqual(matrix.matrix[0].challenges['web-sqli'].badge, '🩸');
console.log('✔ Test 13 passed: Time-series score curve SVG rendered and 2D solve matrix generated.');

console.log('\n🎉 All Multi-Mode Tournament Engine tests passed successfully!\n');
