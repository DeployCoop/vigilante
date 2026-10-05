import assert from 'node:assert';
import path from 'node:path';
import fs from 'node:fs/promises';
import os from 'node:os';
import {
  initCtfWorkspace,
  submitLocalFlag,
  generateSignedWriteup,
  recordSolveSession,
  sealSolveEvidence
} from '../src/engine/ctf-client.js';
import { TournamentEngine } from '../src/engine/tournament.js';

console.log('🧪 Testing CTF Participant Client (Workspace Scaffolder & Writeup Generator)...');

// Test 1: Workspace Scaffolding
const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-ctf-test-'));
const sampleChallenges = [
  { id: 'web-sqli', name: 'SQL Injection Portal', category: 'web', port: 8080 },
  { id: 'pwn-rop', name: 'ROP Arena', category: 'pwn', port: 31338 },
  { id: 'crypto-rsa', name: 'RSA Oracle', category: 'crypto', port: 20001 }
];

const initResult = await initCtfWorkspace({
  targetDir: tmpDir,
  tournamentTitle: 'Vigilante Cup',
  teamName: 'HackersAnonymous',
  challenges: sampleChallenges
});

assert.strictEqual(initResult.scaffoldedCount, 3);
const configRaw = await fs.readFile(path.join(tmpDir, '.vigilante-ctf.json'), 'utf8');
const parsedConfig = JSON.parse(configRaw);
assert.strictEqual(parsedConfig.teamName, 'HackersAnonymous');

// Check that README.md and solve.py exist
const pwnSolve = await fs.readFile(path.join(tmpDir, 'pwn', 'pwn-rop', 'solve.py'), 'utf8');
assert.ok(pwnSolve.includes('from pwn import *'), 'Pwn template must include pwntools');

const webExploit = await fs.readFile(path.join(tmpDir, 'web', 'web-sqli', 'exploit.py'), 'utf8');
assert.ok(webExploit.includes('import requests'), 'Web template must include requests');

console.log('✔ Test 1 passed: Workspace scaffolding generated directory tree and solve boilerplate.');

// Test 2: Local flag submission against TournamentEngine
const engine = new TournamentEngine();
const team = engine.registerTeam({ name: 'HackersAnonymous' });
engine.addChallenge({ id: 'web-sqli', name: 'SQLi', defaultFlag: 'VIGILANTE{sqli_win}' });
engine.start();

const submitResult = await submitLocalFlag({
  challengeId: 'web-sqli',
  flag: 'VIGILANTE{sqli_win}',
  tournamentEngine: engine,
  teamId: team.id
});
assert.strictEqual(submitResult.success, true);
assert.ok(submitResult.points > 0);
console.log(`✔ Test 2 passed: Local flag submission evaluated and awarded ${submitResult.points} points.`);

// Test 3: Writeup generation
const writeupDir = path.join(tmpDir, 'writeups');
const writeupRes = await generateSignedWriteup({
  challengeId: 'web-sqli',
  challengeName: 'SQL Injection Portal',
  category: 'web',
  author: 'Alice',
  teamName: 'HackersAnonymous',
  vulnerabilityDescription: 'Unsanitized input in search parameter allowed UNION SELECT injection.',
  exploitScript: "s.get('http://target/search?q=\\' UNION SELECT flag FROM secrets--')",
  flag: 'VIGILANTE{sqli_win}',
  outputDir: writeupDir
});

assert.ok(writeupRes.filePath);
const writeupContent = await fs.readFile(writeupRes.filePath, 'utf8');
assert.ok(writeupContent.includes('VIGILANTE{sqli_win}'));
assert.ok(writeupContent.includes('UNION SELECT'));
console.log('✔ Test 3 passed: Solution writeup compiled in Markdown.');

// Test 4: Asciinema PoC Session Recording
const castDir = path.join(tmpDir, 'casts');
const castRes = await recordSolveSession({
  challengeId: 'web-sqli',
  command: 'python3 exploit.py',
  output: '[+] Connected\n[+] Found flag: VIGILANTE{sqli_win}',
  durationMs: 800,
  outputDir: castDir
});

assert.ok(castRes.filePath);
assert.ok(castRes.content.includes('"version":2'));
assert.ok(castRes.content.includes('python3 exploit.py'));
assert.ok(castRes.content.includes('VIGILANTE{sqli_win}'));
console.log('✔ Test 4 passed: Asciinema v2 solve replay recording generated.');

// Test 5: Cryptographic Merkle Evidence Sealing
const vaultDir = path.join(tmpDir, 'vault');
const sealRes = await sealSolveEvidence({
  teamId: team.id,
  challengeId: 'web-sqli',
  flag: 'VIGILANTE{sqli_win}',
  solveScriptContent: "import requests; print('VIGILANTE{sqli_win}')",
  writeupContent,
  sessionCastContent: castRes.content,
  outputDir: vaultDir
});

assert.ok(sealRes.receiptId.startsWith('rcpt_'));
assert.strictEqual(sealRes.teamId, team.id);
assert.strictEqual(sealRes.challengeId, 'web-sqli');
assert.ok(sealRes.solveScriptHash.length === 64);
assert.ok(sealRes.merkleEntryHash.length >= 32);
assert.ok(sealRes.manifestFile);
const sealJson = JSON.parse(await fs.readFile(sealRes.manifestFile, 'utf8'));
assert.strictEqual(sealJson.flag, 'VIGILANTE{sqli_win}');
console.log('✔ Test 5 passed: Cryptographic Merkle solve evidence sealed and verified.');

// Cleanup
await fs.rm(tmpDir, { recursive: true, force: true });

console.log('\n🎉 All CTF Participant Client tests passed successfully!\n');
