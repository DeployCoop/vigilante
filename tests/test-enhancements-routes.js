import assert from 'node:assert/strict';
import test from 'node:test';
import { TournamentEngine, TOURNAMENT_STATES } from '../packages/vigilante_lib/src/engine/tournament.js';
import { CHALLENGE_TEMPLATES, deriveTeamHmacFlag } from '../packages/vigilante_lib/src/engine/kctf.js';
import { findRopGadgets, checksec } from '../packages/vigilante_lib/src/engine/ctf-tools.js';
import { validateFalcoRule, simulateFalcoEvent, evaluateFalcoSoarAction } from '../packages/vigilante_lib/src/engine/falco.js';

test('TournamentEngine dynamic points and flag verification', () => {
  const secretKey = 'test-tournament-secret-key-12345';
  const engine = new TournamentEngine({
    id: 'test-tournament',
    secretKey
  });
  engine.state = TOURNAMENT_STATES.ACTIVE;

  for (const chal of CHALLENGE_TEMPLATES.slice(0, 3)) {
    engine.addChallenge({
      id: chal.id,
      name: chal.name,
      category: chal.category,
      difficulty: chal.difficulty,
      port: chal.port,
      protocol: chal.protocol,
      defaultFlag: chal.defaultFlag,
      isDynamicFlag: true
    });
  }

  const team1 = engine.registerTeam({ name: 'Alpha Team' });
  const team2 = engine.registerTeam({ name: 'Bravo Team' });

  const chalId = CHALLENGE_TEMPLATES[0].id;
  const flag1 = deriveTeamHmacFlag({ teamId: team1.id, challengeId: chalId, secretKey });

  // Wrong flag rejected
  const failRes = engine.submitFlag({ teamId: team1.id, challengeId: chalId, flag: 'VIGILANTE{wrong}' });
  assert.equal(failRes.success, false);

  // Correct flag accepted with First Blood bonus
  const solveRes = engine.submitFlag({ teamId: team1.id, challengeId: chalId, flag: flag1 });
  assert.equal(solveRes.success, true);
  assert.equal(solveRes.firstBloodBonus > 0, true);
  assert.equal(solveRes.bloodBadge, '🩸');

  // Second solve gets decayed points and second blood
  const flag2 = deriveTeamHmacFlag({ teamId: team2.id, challengeId: chalId, secretKey });
  const solve2Res = engine.submitFlag({ teamId: team2.id, challengeId: chalId, flag: flag2 });
  assert.equal(solve2Res.success, true);
  assert.equal(solve2Res.bloodBadge, '🥈');

  // Collusion detection: Team 1 submitting Team 2's flag is flagged
  const flag2ForChal2 = deriveTeamHmacFlag({ teamId: team2.id, challengeId: CHALLENGE_TEMPLATES[1].id, secretKey });
  const colludeRes = engine.submitFlag({ teamId: team1.id, challengeId: CHALLENGE_TEMPLATES[1].id, flag: flag2ForChal2 });
  assert.equal(colludeRes.success, false);
  assert.match(colludeRes.reason, /Security anomaly detected/);
});

test('CTF Tools: ROP Gadget Finder on binary buffer', () => {
  // Buffer containing: pop rdi; ret (0x5f, 0xc3) and syscall; ret (0x0f, 0x05, 0xc3)
  const binaryBuf = Buffer.from([0x90, 0x5f, 0xc3, 0x90, 0x0f, 0x05, 0xc3, 0x90]);
  const result = findRopGadgets({ binaryBuffer: binaryBuf });

  assert.equal(result.totalFound >= 2, true);
  const rdi = result.gadgets.find(g => g.mnemonic === 'pop rdi; ret');
  const syscall = result.gadgets.find(g => g.mnemonic === 'syscall; ret');
  assert.ok(rdi);
  assert.equal(rdi.offset, 1);
  assert.ok(syscall);
  assert.equal(syscall.offset, 4);
});

test('CTF Tools: checksec binary mitigations inspector', async () => {
  // Minimal ELF header
  const elfBuf = Buffer.alloc(64);
  elfBuf[0] = 0x7f; elfBuf[1] = 0x45; elfBuf[2] = 0x4c; elfBuf[3] = 0x46; // \x7fELF
  elfBuf[4] = 2; // 64-bit
  elfBuf[5] = 1; // little endian

  const sec = await checksec(elfBuf);
  assert.equal(sec.isElf, true);
  assert.equal(sec.arch, 'x86_64');
  assert.equal(sec.bits, 64);
  assert.ok(sec.summary);
});

test('Falco engine: Rule validation and eBPF simulation', () => {
  const validRule = {
    rule: 'Test Shell Spawn',
    condition: 'proc.name in (bash, sh)',
    output: 'Shell spawned (%proc.name)',
    priority: 'WARNING'
  };
  const val = validateFalcoRule(validRule);
  assert.equal(val.valid, true);

  const event = simulateFalcoEvent('shell-spawn', {});
  assert.ok(event);
  assert.ok(event.process);
  assert.ok(event.rule);

  const soar = evaluateFalcoSoarAction(event);
  assert.ok(soar);
  assert.ok(soar.action);
});
