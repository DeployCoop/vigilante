import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';
import { signFile } from './gpg.js';
import { loadConfig } from './config.js';

/**
 * Initializes and scaffolds a structured local CTF participant workspace
 */
export async function initCtfWorkspace({
  targetDir = './ctf-workspace',
  tournamentTitle = 'Vigilante CTF Tournament',
  tournamentUrl = 'https://ctf.vigilante.local',
  teamToken = null,
  teamName = 'Team Unknown',
  challenges = []
} = {}) {
  const absTargetDir = path.resolve(targetDir);
  await fs.mkdir(absTargetDir, { recursive: true });

  const categories = ['web', 'pwn', 'crypto', 'rev', 'forensics', 'misc'];
  for (const cat of categories) {
    await fs.mkdir(path.join(absTargetDir, cat), { recursive: true });
  }

  // Create writeups directory
  await fs.mkdir(path.join(absTargetDir, 'writeups'), { recursive: true });

  // Save workspace configuration
  const configData = {
    tournamentTitle,
    tournamentUrl,
    teamName,
    teamToken,
    initializedAt: new Date().toISOString(),
    challengesCount: challenges.length
  };

  await fs.writeFile(
    path.join(absTargetDir, '.vigilante-ctf.json'),
    JSON.stringify(configData, null, 2),
    'utf8'
  );

  // Scaffold challenge directories
  const scaffolded = [];
  for (const chal of challenges) {
    const cat = (chal.category || 'misc').toLowerCase();
    const chalDir = path.join(absTargetDir, cat, chal.id || chal.name);
    await fs.mkdir(chalDir, { recursive: true });

    // Generate challenge README.md
    const readmeContent = `# ${chal.name || chal.id}
**Category**: ${(chal.category || 'misc').toUpperCase()}
**Difficulty**: ${chal.difficulty || 'Normal'}
**Points**: ${chal.currentPoints || 500} pts
**Connection**: \`${chal.connectionString || (chal.category === 'web' ? `http://ctf.vigilante.local:${chal.port || 8080}` : `nc ctf.vigilante.local ${chal.port || 31337}`)}\`

---

## 📝 Challenge Description
${chal.description || 'No description provided.'}

## 💡 Hints
${(chal.hints && chal.hints.length > 0) ? chal.hints.map(h => `- ${h}`).join('\n') : '- No hints unlocked yet.'}

---

## 🚩 Flag Submission
To submit your flag using Vigilante CLI:
\`\`\`bash
$ vigilante ctf submit ${chal.id} VIGILANTE{...}
\`\`\`
`;
    await fs.writeFile(path.join(chalDir, 'README.md'), readmeContent, 'utf8');

    // Generate boilerplate starter solve scripts
    if (cat === 'pwn') {
      const pwnTemplate = `#!/usr/bin/env python3
# Pwntools Exploit Template for ${chal.name}
from pwn import *

context.arch = 'amd64'
context.terminal = ['tmux', 'splitw', '-h']

HOST = "${tournamentUrl.replace(/https?:\/\//, '')}"
PORT = ${chal.port || 31337}

def start():
    if args.REMOTE:
        return remote(HOST, PORT)
    else:
        return process("./${chal.id}.elf")

io = start()
# TODO: Inject buffer overflow or format string payload
# payload = cyclic(128)
# io.sendlineafter(b"Input: ", payload)

io.interactive()
`;
      await fs.writeFile(path.join(chalDir, 'solve.py'), pwnTemplate, 'utf8');
    } else if (cat === 'web') {
      const webTemplate = `#!/usr/bin/env python3
# Web Exploitation Script for ${chal.name}
import requests

TARGET = "${tournamentUrl}:${chal.port || 8080}"
session = requests.Session()

# Step 1: Probe target endpoint
res = session.get(TARGET)
print(f"[*] Status: {res.status_code}")
print(f"[*] Headers: {res.headers}")

# TODO: Inject authentication bypass or SQLi payload
`;
      await fs.writeFile(path.join(chalDir, 'exploit.py'), webTemplate, 'utf8');
    } else if (cat === 'crypto') {
      const cryptoTemplate = `#!/usr/bin/env python3
# Cryptographic Solver for ${chal.name}
import socket

HOST = "${tournamentUrl.replace(/https?:\/\//, '')}"
PORT = ${chal.port || 20001}

# Connect to oracle service
s = socket.socket()
s.connect((HOST, PORT))
banner = s.recv(1024)
print(banner.decode())

# TODO: Query oracle and compute decryption
`;
      await fs.writeFile(path.join(chalDir, 'solve.py'), cryptoTemplate, 'utf8');
    }

    scaffolded.push(chal.id);
  }

  logger.info('CTF_CLIENT:INIT', `Initialized workspace at ${absTargetDir} with ${scaffolded.length} challenges.`);
  return {
    workspacePath: absTargetDir,
    scaffoldedCount: scaffolded.length,
    categories
  };
}

/**
 * Submits a flag either to a local TournamentEngine or writes a local solve log
 */
export async function submitLocalFlag({
  challengeId,
  flag,
  tournamentEngine = null,
  teamId = null,
  workspaceDir = './ctf-workspace'
}) {
  if (!challengeId || !flag) {
    throw new Error('Both challengeId and flag are required for submission');
  }

  const cleanFlag = flag.trim();

  // If local engine is provided, execute validation
  if (tournamentEngine && teamId) {
    const result = tournamentEngine.submitFlag({
      teamId,
      challengeId,
      flag: cleanFlag
    });

    return result;
  }

  return {
    success: true,
    message: `Flag for '${challengeId}' formatted and ready for submission: ${cleanFlag}`,
    flag: cleanFlag
  };
}

/**
 * Generates an RFC 4880 GPG-signed writeup for competition prize verification
 */
export async function generateSignedWriteup({
  challengeId,
  challengeName = 'Challenge',
  category = 'web',
  author = 'Participant',
  teamName = 'Team',
  vulnerabilityDescription = '',
  exploitScript = '',
  flag = '',
  outputDir = './ctf-workspace/writeups'
}) {
  const absOutputDir = path.resolve(outputDir);
  await fs.mkdir(absOutputDir, { recursive: true });

  const safeChal = challengeId.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const filename = `writeup-${safeChal}.md`;
  const filePath = path.join(absOutputDir, filename);

  const writeupMarkdown = `# 🚩 CTF Solution Writeup: ${challengeName}
**Challenge ID**: \`${challengeId}\`
**Category**: ${category.toUpperCase()}
**Author**: ${author} (${teamName})
**Timestamp**: ${new Date().toISOString()}
**Captured Flag**: \`${flag}\`

---

## 🔍 Vulnerability Analysis
${vulnerabilityDescription || 'Identified security flaw in input validation / boundary handling.'}

---

## 💥 Exploit Mechanics & Proof of Concept
\`\`\`python
${exploitScript || '# Working exploit script'}
\`\`\`

---

*Generated and cryptographically sealed via Vigilante CTF Operator.*
`;

  await fs.writeFile(filePath, writeupMarkdown, 'utf8');

  // Attempt GPG signature
  let signaturePath = null;
  let isSigned = false;
  const cfg = loadConfig();

  if (cfg.gpg?.enabled) {
    try {
      const sigRes = await signFile(filePath, { keyId: cfg.gpg.keyId });
      signaturePath = sigRes.signaturePath;
      isSigned = true;
    } catch (err) {
      logger.warn('CTF_CLIENT:WRITEUP:GPG', `Could not sign writeup: ${err.message}`);
    }
  }

  return {
    filePath,
    signaturePath,
    isSigned,
    filename
  };
}

// ==============================================================================
// Automated PoC Session Recorder & Merkle Evidence Sealer
// ==============================================================================

/**
 * Records an execution session to Asciinema v2 terminal cast (.cast) format
 */
export async function recordSolveSession({
  challengeId,
  command = 'python3 solve.py',
  output = '',
  inputData = '',
  durationMs = 1200,
  outputDir = './ctf-workspace/casts'
} = {}) {
  if (!challengeId) {
    throw new Error('challengeId required for session recording');
  }

  const absDir = path.resolve(outputDir);
  await fs.mkdir(absDir, { recursive: true });

  const safeChal = challengeId.toLowerCase().replace(/[^a-z0-9_-]/g, '-');
  const filename = `session-${safeChal}-${Date.now()}.cast`;
  const filePath = path.join(absDir, filename);

  const header = JSON.stringify({
    version: 2,
    width: 120,
    height: 35,
    timestamp: Math.floor(Date.now() / 1000),
    title: `Vigilante CTF Solve Replay: ${challengeId}`,
    env: { SHELL: '/bin/bash', TERM: 'xterm-256color' }
  });

  const lines = [header];
  lines.push(JSON.stringify([0.1, 'o', `$ ${command}\r\n`]));
  if (inputData) {
    lines.push(JSON.stringify([0.3, 'i', `${inputData}\r\n`]));
  }
  const cleanOutput = (output || 'Solve completed successfully.\r\n').replace(/\r?\n/g, '\r\n');
  lines.push(JSON.stringify([0.6, 'o', cleanOutput]));
  lines.push(JSON.stringify([durationMs / 1000, 'o', '\r\n[+] Exploit finished. Session terminated.\r\n']));

  const castContent = lines.join('\n') + '\n';
  await fs.writeFile(filePath, castContent, 'utf8');

  logger.info('CTF_CLIENT:RECORDER', `Recorded solve replay session to ${filePath}`);
  return {
    filePath,
    filename,
    durationMs,
    content: castContent
  };
}

/**
 * Compiles a solution bundle and cryptographically seals it into the Merkle Evidence Ledger
 */
export async function sealSolveEvidence({
  teamId,
  challengeId,
  flag,
  solveScriptContent = '',
  writeupContent = '',
  sessionCastContent = '',
  outputDir = './ctf-workspace/vault'
} = {}) {
  if (!teamId || !challengeId || !flag) {
    throw new Error('teamId, challengeId, and flag are required to seal solve evidence');
  }

  const absDir = path.resolve(outputDir);
  await fs.mkdir(absDir, { recursive: true });

  // 1. Calculate cryptographic SHA-256 hashes of all artifacts
  const solveScriptHash = crypto.createHash('sha256').update(solveScriptContent || '').digest('hex');
  const writeupHash = crypto.createHash('sha256').update(writeupContent || '').digest('hex');
  const sessionCastHash = crypto.createHash('sha256').update(sessionCastContent || '').digest('hex');
  const flagHash = crypto.createHash('sha256').update(flag.trim()).digest('hex');

  const receiptId = 'rcpt_' + crypto.randomBytes(6).toString('hex');
  const timestamp = new Date().toISOString();

  // 2. Build immutable evidence payload
  const evidencePayload = {
    receiptId,
    teamId,
    challengeId,
    flag: flag.trim(),
    flagHash,
    solveScriptHash,
    writeupHash,
    sessionCastHash,
    sealedAt: timestamp
  };

  // 3. Ingest into Cryptographic Merkle Ledger
  let ledgerEntry = null;
  try {
    const { appendLedgerEntry } = await import('./ledger.js');
    ledgerEntry = await appendLedgerEntry({
      type: 'CTF_SOLVE_EVIDENCE',
      source: 'ctf-client',
      payload: evidencePayload,
      description: `Cryptographic proof of solve for challenge '${challengeId}' by team '${teamId}'`
    });
  } catch (err) {
    logger.warn('CTF_CLIENT:LEDGER', `Ledger append warning: ${err.message}`);
  }

  // 4. Save sealed manifest
  const manifestFile = path.join(absDir, `${receiptId}-seal.json`);
  const fullSealRecord = {
    ...evidencePayload,
    merkleIndex: ledgerEntry?.index ?? 0,
    merkleEntryHash: ledgerEntry?.entryHash ?? crypto.createHash('sha256').update(JSON.stringify(evidencePayload)).digest('hex'),
    merkleRoot: ledgerEntry?.merkleRoot ?? null
  };

  await fs.writeFile(manifestFile, JSON.stringify(fullSealRecord, null, 2), 'utf8');

  // 5. Attempt GPG signature if enabled
  let isSigned = false;
  let signaturePath = null;
  const cfg = loadConfig();
  if (cfg.gpg?.enabled) {
    try {
      const sigRes = await signFile(manifestFile, { keyId: cfg.gpg.keyId });
      signaturePath = sigRes.signaturePath;
      isSigned = true;
    } catch {
      // Ignore if gpg not configured
    }
  }

  logger.info('CTF_CLIENT:SEAL', `Sealed solve evidence receipt '${receiptId}' (Merkle Hash: ${fullSealRecord.merkleEntryHash})`);

  return {
    ...fullSealRecord,
    manifestFile,
    signaturePath,
    isSigned
  };
}
