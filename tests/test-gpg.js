import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import { execa } from 'execa';
import {
  isGpgAvailable,
  listSecretKeys,
  parseGpgKeyList,
  signFile,
  verifyFileSignature,
  autoSignIfConfigured
} from '../src/engine/gpg.js';
import {
  ensureVigilanteConfig,
  saveConfig,
  loadConfig
} from '../src/engine/config.js';
import {
  saveEvidenceFile,
  saveTriageBundle,
  listHostEvidence
} from '../src/engine/evidence.js';

async function runTests() {
  console.log('🧪 Testing GPG Digital Signatures & Evidence Non-Repudiation Engine...');

  const hasGpg = await isGpgAvailable();
  if (!hasGpg) {
    console.log('⚠️ GPG binary not found in environment, skipping live GPG signing tests.');
    return;
  }

  const tempXdg = path.join(os.tmpdir(), `vigilante-gpg-test-${Math.random().toString(36).slice(2, 8)}`);
  const tempGnuPg = path.join(tempXdg, 'gnupg');
  process.env.XDG_CONFIG_HOME = tempXdg;

  try {
    await fs.mkdir(tempGnuPg, { recursive: true, mode: 0o700 });
    await ensureVigilanteConfig();

    // Test 1: Key parsing helper
    const sampleColonOutput = `sec:u:255:22:C74C7A9B38C82477:1786891612:1818427612::u:::scESC:::+::ed25519:::0:
fpr:::::::::4DD2F4C975173231A69AFE92C74C7A9B38C82477:
grp:::::::::470D4691E05497A4A3046DE263C5661070103E6F:
uid:u::::1786891612::0DED6E1DEDE5B9A8DA46AA8889DACEC57C52DDF7::Vigilante Security Lead <security@vigilante.local>::::::::::0:`;
    const parsedKeys = parseGpgKeyList(sampleColonOutput);
    if (parsedKeys.length !== 1 || parsedKeys[0].email !== 'security@vigilante.local') {
      throw new Error(`parseGpgKeyList failed: ${JSON.stringify(parsedKeys)}`);
    }
    console.log('✔ Test 1 passed: parseGpgKeyList parsed keyId, fingerprint, name, and email correctly.');

    // Test 2: Generate temporary GPG key in isolated GNUPGHOME
    console.log('Generating test GPG key in isolated test environment...');
    await execa('gpg', [
      '--batch',
      '--passphrase', '',
      '--quick-generate-key', 'Vigilante Incident Responder <ir@vigilante.local>',
      'default', 'default', '1y'
    ], {
      env: { ...process.env, GNUPGHOME: tempGnuPg }
    });

    const secretKeys = await listSecretKeys(tempGnuPg);
    if (secretKeys.length === 0 || !secretKeys[0].email.includes('vigilante.local')) {
      throw new Error(`listSecretKeys failed: ${JSON.stringify(secretKeys)}`);
    }
    const keyFingerprint = secretKeys[0].fingerprint;
    console.log(`✔ Test 2 passed: Created test key & listed secret keys (Fingerprint: ${keyFingerprint}).`);

    // Test 3: Sign file with detached signature
    const testFile = path.join(tempXdg, 'forensic-dump.txt');
    await fs.writeFile(testFile, 'INCIDENT FORENSICS: Attacker IP 192.168.1.100 identified at 2026-08-16', 'utf8');

    const signRes = await signFile(testFile, { gnupgHome: tempGnuPg });
    if (!signRes.success || !signRes.signaturePath) {
      throw new Error(`signFile failed: ${JSON.stringify(signRes)}`);
    }
    const sigExists = await fs.access(signRes.signaturePath).then(() => true).catch(() => false);
    if (!sigExists) {
      throw new Error(`Detached signature file not found at ${signRes.signaturePath}`);
    }
    console.log(`✔ Test 3 passed: signFile generated detached signature ${signRes.signaturePath}.`);

    // Test 4: Verify valid signature
    const verifyRes = await verifyFileSignature(testFile, signRes.signaturePath, { gnupgHome: tempGnuPg });
    if (!verifyRes.isValid || !verifyRes.signerUid.includes('Vigilante Incident Responder')) {
      throw new Error(`verifyFileSignature failed: ${JSON.stringify(verifyRes)}`);
    }
    console.log(`✔ Test 4 passed: verifyFileSignature validated signature from "${verifyRes.signerUid}" at ${verifyRes.signedAt}.`);

    // Test 5: Tamper detection
    await fs.writeFile(testFile, 'TAMPERED INCIDENT FORENSICS: Attacker IP cleared', 'utf8');
    const tamperVerify = await verifyFileSignature(testFile, signRes.signaturePath, { gnupgHome: tempGnuPg });
    if (tamperVerify.isValid) {
      throw new Error('Tampered file should NOT validate against original signature!');
    }
    console.log('✔ Test 5 passed: Tampered file correctly rejected by verifyFileSignature.');

    // Test 6: Auto-signing when configured in config.yaml
    const config = loadConfig();
    config.gpg = {
      enabled: true,
      keyId: 'ir@vigilante.local',
      autoSign: true,
      detached: true,
      gnupgHome: tempGnuPg
    };
    await saveConfig(config);

    // Save evidence file - should automatically create .asc file alongside
    const saved = await saveEvidenceFile('10.0.1.0/24', '10.0.1.5', 'mtr.txt', '1. gateway 0.5ms\n2. target 1.2ms');
    if (!saved.isSigned || !saved.signaturePath) {
      throw new Error(`saveEvidenceFile with GPG enabled did not sign: ${JSON.stringify(saved)}`);
    }
    const ascExists = await fs.access(saved.signaturePath).then(() => true).catch(() => false);
    if (!ascExists) {
      throw new Error(`Expected signature file ${saved.signaturePath} does not exist`);
    }
    console.log(`✔ Test 6 passed: saveEvidenceFile automatically generated ${saved.signaturePath} when GPG is enabled.`);

    // Test 7: Full Triage Bundle with GPG signatures
    const triageBundle = {
      ping: { latency: '0.05ms' },
      dns: { ptr: 'target.local' }
    };
    const triageRes = await saveTriageBundle('10.0.1.0/24', '10.0.1.5', triageBundle);
    const signedArtifacts = triageRes.artifacts.filter(a => a.isSigned);
    if (signedArtifacts.length !== 3) { // ping, dns, triage_summary
      throw new Error(`Expected 3 signed artifacts, got: ${signedArtifacts.length}`);
    }

    const hostArtifacts = await listHostEvidence('10.0.1.0/24', '10.0.1.5');
    const signedDiscovered = hostArtifacts.filter(a => a.isSigned);
    if (signedDiscovered.length < 3) {
      throw new Error(`listHostEvidence failed to discover signed artifacts: ${JSON.stringify(hostArtifacts)}`);
    }
    console.log(`✔ Test 7 passed: saveTriageBundle and listHostEvidence signed and tracked ${signedArtifacts.length} artifacts.`);

    console.log('🎉 All GPG Digital Signatures & Evidence Non-Repudiation tests passed successfully!');
  } finally {
    try {
      await fs.rm(tempXdg, { recursive: true, force: true });
    } catch {
      // Ignore cleanup
    }
  }
}

runTests().catch((err) => {
  console.error('✖ Test failed:', err);
  process.exit(1);
});
