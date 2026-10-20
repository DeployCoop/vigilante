import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { TournamentEngine, TOURNAMENT_STATES } from '../packages/vigilante_lib/src/engine/tournament.js';
import { CHALLENGE_TEMPLATES, deriveTeamHmacFlag } from '../packages/vigilante_lib/src/engine/kctf.js';
import { findRopGadgets, checksec } from '../packages/vigilante_lib/src/engine/ctf-tools.js';
import { validateFalcoRule, parseFalcoRulesYaml, simulateFalcoEvent, evaluateFalcoSoarAction } from '../packages/vigilante_lib/src/engine/falco.js';
import { parseCrashContext } from '../packages/vigilante_lib/src/engine/llm.js';
import { sealSolveEvidence, generateSignedWriteup } from '../packages/vigilante_lib/src/engine/ctf-client.js';
import { resolvePathInside } from '../packages/vigilante_lib/src/engine/config.js';

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

test('TournamentEngine SVG chart escapes XML special characters in teamName (XSS prevention)', () => {
  const secretKey = 'svg-xss-test-secret';
  const engine = new TournamentEngine({ id: 'xss-test', secretKey });
  engine.state = TOURNAMENT_STATES.ACTIVE;
  const chal = CHALLENGE_TEMPLATES[0];
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

  const xssTeam = engine.registerTeam({ name: '<script>alert("xss")</script>&"team\'' });
  const flag = deriveTeamHmacFlag({ teamId: xssTeam.id, challengeId: chal.id, secretKey });
  engine.submitFlag({ teamId: xssTeam.id, challengeId: chal.id, flag });

  const svg = engine.renderScoreCurvesSvg();
  assert.equal(svg.includes('<script>'), false, 'Raw <script> tag must not appear in SVG output');
  assert.equal(svg.includes('&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;&amp;&quot;team&apos;'), true);
});

test('Crash Triage: parseCrashContext parses both GDB whitespace and pwntools register formats', () => {
  const gdbCrashLog = `
Program received signal SIGSEGV, Segmentation fault.
0x0000000041414141 in vuln ()
rax            0x0                 0
rsp            0x7fffffffe000      0x7fffffffe000
rip            0x4141414141414141  0x4141414141414141
`;
  const diag = parseCrashContext({ crashLog: gdbCrashLog });
  assert.equal(diag.signal, 'SIGSEGV (Segmentation Fault)');
  assert.equal(diag.registers.rip, '0x4141414141414141');
  assert.equal(diag.crashType, 'BUFFER_OVERFLOW_CONTROL_HIJACK');
  assert.ok(diag.diagnosisExplanation.includes('overwritten directly'));
  assert.equal(Array.isArray(diag.socraticQuestions), true);
  assert.equal(diag.socraticQuestions.length > 0, true);
});

test('Falco engine: all 6 simulator scenarios and raw YAML rule parsing', () => {
  const scenarios = [
    'shell-spawn',
    'sensitive-file-read',
    'c2-connection',
    'k8s-token-theft',
    'container-escape',
    'ransomware-encryption'
  ];
  const rulesSeen = new Set();
  for (const sc of scenarios) {
    const ev = simulateFalcoEvent(sc);
    rulesSeen.add(ev.rule);
    const soar = evaluateFalcoSoarAction(ev);
    assert.ok(soar.action);
    assert.ok(soar.description);
    assert.ok(soar.target);
    assert.equal(typeof soar.recommendedSlaMinutes, 'number');
  }
  assert.equal(rulesSeen.size, 6, 'All 6 Falco scenarios must produce distinct rules');

  const yamlText = `
- rule: Terminal Spawn in Isolated Sandbox
  desc: Detects shell execution inside ctf-sandboxes namespace
  condition: k8s.ns.name = "ctf-sandboxes" and proc.name in (bash, sh, zsh)
  output: "Shell initiated in CTF sandbox (user=%user.name pod=%k8s.pod.name)"
  priority: NOTICE
  tags: [ctf_telemetry, mitre_execution]
`;
  const parsed = parseFalcoRulesYaml(yamlText);
  assert.equal(parsed.length, 1);
  assert.deepEqual(parsed[0].tags, ['ctf_telemetry', 'mitre_execution']);
  const val = validateFalcoRule(parsed[0]);
  assert.equal(val.valid, true);
});

test('CTF Client: sealSolveEvidence and generateSignedWriteup contract fields & path containment', async () => {
  const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-ctf-test-'));
  try {
    // Path containment check
    assert.throws(() => {
      resolvePathInside(path.join(tmpDir, 'ctf-workspace'), '../ctf-workspace-evil/chal');
    }, /escapes its base directory/);

    const sealRes = await sealSolveEvidence({
      teamId: 'team-alpha',
      challengeId: 'pwn-bof-101',
      flag: 'VIGILANTE{test_flag_123}',
      writeupContent: 'Exploited buffer overflow at offset 72',
      outputDir: path.join(tmpDir, 'proofs')
    });
    assert.ok(sealRes.receiptId);
    assert.ok(sealRes.merkleEntryHash || sealRes.flagHash);
    assert.ok(sealRes.manifestFile);

    const writeupRes = await generateSignedWriteup({
      challengeId: 'pwn-bof-101',
      challengeName: 'Stack Overflow 101',
      category: 'pwn',
      teamName: 'Team Alpha',
      vulnerabilityDescription: 'Classic stack smash',
      flag: 'VIGILANTE{test_flag_123}',
      outputDir: path.join(tmpDir, 'writeups')
    });
    assert.ok(writeupRes.filePath);
    assert.ok(writeupRes.filename);
  } finally {
    await fs.rm(tmpDir, { recursive: true, force: true });
  }
});
