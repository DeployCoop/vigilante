import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import assert from 'node:assert';
import {
  sanitizePathComponent,
  resolvePathInside,
  assertPathStrictlyInside,
  getVigilanteConfigDir,
  getVigilanteInstancesDir,
  getVigilanteEvidenceDir,
  getVigilanteOobscansDir,
  getVigilanteNmapsDir,
  getInstanceDir,
  getHostEvidenceDir,
  ensureVigilanteConfig
} from '../src/engine/config.js';
import { deleteInstance, ensureInstanceDirs } from '../src/engine/instances.js';
import { saveEvidenceFile, readEvidenceFile, deleteHostEvidence } from '../src/engine/evidence.js';
import { readSavedOobScan, deleteSavedOobScan, exportRakpHashes } from '../src/engine/oobscan.js';
import { releaseContainment } from '../src/engine/soar.js';
import { readSavedScan, deleteSavedScan } from '../src/engine/nmap.js';
import { readXmlScan } from '../src/engine/nmap-xml.js';
import { setupCertificates, checkCertificates, isValidDomain } from '../src/engine/certs.js';
import { ScenarioEngine } from '../src/engine/scenarios.js';
import { resolveChartValuesArgs } from '../src/engine/helm.js';
import { fileURLToPath } from 'node:url';

const rootDir = path.dirname(fileURLToPath(import.meta.url));

async function expectThrow(fn, label) {
  let threw = false;
  try {
    await fn();
  } catch {
    threw = true;
  }
  assert(threw, `${label}: expected an error, but none was thrown`);
}

async function runTests() {
  console.log('🧪 Testing Path Traversal Containment (sanitize + resolvePathInside family)...');

  const tempXdg = path.join(os.tmpdir(), `vigilante-traversal-test-${Math.random().toString(36).slice(2, 8)}`);
  process.env.XDG_CONFIG_HOME = tempXdg;

  try {
    await ensureVigilanteConfig();
    const configDir = getVigilanteConfigDir();
    const configFile = path.join(configDir, 'config.yaml');

    // Test 1: sanitizePathComponent neutralizes dot segments, keeps legit names
    assert.strictEqual(sanitizePathComponent('..'), 'unknown');
    assert.strictEqual(sanitizePathComponent('.'), 'unknown');
    assert.strictEqual(sanitizePathComponent('   '), 'unknown');
    assert.strictEqual(sanitizePathComponent(''), 'unknown');
    assert.strictEqual(sanitizePathComponent('vigilante.local'), 'vigilante.local');
    assert.strictEqual(sanitizePathComponent('10.0.1.0/24'), '10.0.1.0_24');
    assert.strictEqual(sanitizePathComponent('my-instance_1'), 'my-instance_1');
    console.log('✔ Test 1 passed: sanitizePathComponent maps ./../empty to unknown, legit names untouched.');

    // Test 2: resolvePathInside / assertPathStrictlyInside semantics
    const base = path.join(tempXdg, 'base');
    assert.strictEqual(resolvePathInside(base, 'file.txt'), path.join(base, 'file.txt'));
    assert.strictEqual(resolvePathInside(base, path.join(base, 'inner.txt')), path.join(base, 'inner.txt'));
    await expectThrow(async () => resolvePathInside(base, '../escape.txt'), 'relative escape');
    await expectThrow(async () => resolvePathInside(base, '/etc/passwd'), 'absolute escape');
    await expectThrow(async () => assertPathStrictlyInside(base, base), 'base itself is not strictly inside');
    assert.strictEqual(assertPathStrictlyInside(base, path.join(base, 'x')), path.join(base, 'x'));
    console.log('✔ Test 2 passed: resolvePathInside allows inside paths and rejects escapes.');

    // Test 3: derived dirs cannot escape their roots via '..' inputs
    const instancesRoot = path.resolve(getVigilanteInstancesDir());
    assert(path.resolve(getInstanceDir('..')).startsWith(instancesRoot + path.sep), 'instance dir escaped');
    assert(path.resolve(getInstanceDir('.')).startsWith(instancesRoot + path.sep), 'instance dir escaped');
    const evidenceRoot = path.resolve(getVigilanteEvidenceDir());
    assert(path.resolve(getHostEvidenceDir('..', '..')).startsWith(evidenceRoot + path.sep), 'evidence dir escaped');
    console.log('✔ Test 3 passed: getInstanceDir/getHostEvidenceDir stay inside their roots for .. inputs.');

    // Test 4: deleteInstance('..') / deleteInstance('.') cannot wipe the config dir
    await ensureInstanceDirs('keepme');
    assert(fsSync.existsSync(configFile), 'config.yaml should exist before delete attempts');
    await deleteInstance('..', { deleteCluster: false });
    await deleteInstance('.', { deleteCluster: false });
    assert(fsSync.existsSync(configFile), 'config.yaml was deleted by deleteInstance(..)!');
    assert(fsSync.existsSync(path.join(instancesRoot, 'keepme', 'instance.json')) || fsSync.existsSync(path.join(instancesRoot, 'keepme')), 'sibling instance was deleted!');
    // Legit delete still works
    await deleteInstance('keepme', { deleteCluster: false });
    assert(!fsSync.existsSync(path.join(instancesRoot, 'keepme')), 'legit deleteInstance failed');
    console.log('✔ Test 4 passed: deleteInstance cannot wipe config dir; legitimate delete still works.');

    // Test 5: evidence read/delete containment
    const secretPath = path.join(tempXdg, 'secret.txt');
    await fs.writeFile(secretPath, 'TOPSECRET', 'utf8');
    await saveEvidenceFile('10.0.1.0/24', '10.0.1.5', 'note.txt', 'hello evidence');
    const legit = await readEvidenceFile('10.0.1.0/24', '10.0.1.5', 'note.txt');
    assert(legit.includes('hello evidence'), 'legit readEvidenceFile failed');
    const relEscape = '../../../../secret.txt';
    let leaked = null;
    try {
      leaked = await readEvidenceFile('10.0.1.0/24', '10.0.1.5', relEscape);
    } catch { /* expected */ }
    assert(leaked === null || !String(leaked).includes('TOPSECRET'), 'readEvidenceFile leaked a file outside the vault');
    await deleteHostEvidence('..', '..');
    assert(fsSync.existsSync(configFile), 'config.yaml was deleted by deleteHostEvidence(.., ..)!');
    await deleteHostEvidence('10.0.1.0/24', '10.0.1.5');
    assert(!fsSync.existsSync(getHostEvidenceDir('10.0.1.0/24', '10.0.1.5')), 'legit deleteHostEvidence failed');
    console.log('✔ Test 5 passed: evidence read/delete contained; legitimate flows still work.');

    // Test 6: oobscan read/delete/export containment
    const oobDir = getVigilanteOobscansDir();
    const scanName = `trav-${Date.now()}.jsonl`;
    await fs.writeFile(path.join(oobDir, scanName), '{"summary":{}}\n', 'utf8');
    const scanDetails = await readSavedOobScan(scanName);
    assert.strictEqual(scanDetails.filename, scanName, 'legit readSavedOobScan failed');
    await expectThrow(() => readSavedOobScan(secretPath), 'readSavedOobScan absolute outside');
    await expectThrow(() => readSavedOobScan('../../secret.txt'), 'readSavedOobScan relative escape');
    const victim = path.join(tempXdg, 'victim.txt');
    await fs.writeFile(victim, 'x', 'utf8');
    await expectThrow(() => deleteSavedOobScan('../../victim.txt'), 'deleteSavedOobScan escape');
    assert(fsSync.existsSync(victim), 'deleteSavedOobScan deleted a file outside oobscans');
    await expectThrow(() => exportRakpHashes(path.join(tempXdg, 'evil-out.txt')), 'exportRakpHashes destination outside');
    await deleteSavedOobScan(scanName);
    assert(!fsSync.existsSync(path.join(oobDir, scanName)), 'legit deleteSavedOobScan failed');
    console.log('✔ Test 6 passed: oobscan read/delete/export contained to the oobscans directory.');

    // Test 7: SOAR releaseContainment cannot read/overwrite arbitrary JSON
    const victimJson = path.join(tempXdg, 'victim.json');
    await fs.writeFile(victimJson, JSON.stringify({ note: 'untouched' }), 'utf8');
    await expectThrow(() => releaseContainment('../../victim'), 'releaseContainment escape');
    const afterVictim = JSON.parse(await fs.readFile(victimJson, 'utf8'));
    assert.strictEqual(afterVictim.note, 'untouched', 'releaseContainment overwrote an arbitrary JSON file');
    assert.strictEqual(afterVictim.status, undefined, 'releaseContainment mutated an arbitrary JSON file');
    console.log('✔ Test 7 passed: releaseContainment rejects ids that escape the containments directory.');

    // Test 8: nmap saved-scan read/delete + XML read containment
    const nmapsDir = getVigilanteNmapsDir();
    const scanFile = path.join(nmapsDir, 'trav-scan.nmap');
    await fs.writeFile(scanFile, 'scan body', 'utf8');
    assert((await readSavedScan(scanFile)) === 'scan body', 'legit readSavedScan failed');
    await expectThrow(() => readSavedScan(secretPath), 'readSavedScan outside nmaps');
    await expectThrow(() => deleteSavedScan(secretPath), 'deleteSavedScan outside nmaps');
    assert(fsSync.existsSync(secretPath), 'deleteSavedScan deleted a file outside nmaps');
    await expectThrow(() => readXmlScan(secretPath), 'readXmlScan outside nmaps');
    await deleteSavedScan(scanFile);
    assert(!fsSync.existsSync(scanFile), 'legit deleteSavedScan failed');
    console.log('✔ Test 8 passed: nmap saved-scan APIs contained to the nmaps directory.');

    // Test 9: cert domain validation blocks traversal and flag injection
    assert(isValidDomain('vigilante.local'));
    assert(isValidDomain('soc-prod.vigilante.local'));
    assert(!isValidDomain('../../evil'));
    assert(!isValidDomain('-evil.local'));
    assert(!isValidDomain('evil/local'));
    assert(!isValidDomain('..'));
    await expectThrow(() => setupCertificates('../../evil'), 'setupCertificates traversal domain');
    await expectThrow(() => setupCertificates('-cert-file'), 'setupCertificates flag-like domain');
    const badCheck = await checkCertificates('../../evil');
    assert.strictEqual(badCheck.exists, false, 'checkCertificates should report exists:false for invalid domain');
    console.log('✔ Test 9 passed: cert domains validated before becoming paths or mkcert arguments.');

    // Test 10: scenario id traversal cannot load a YAML outside the scenario dirs
    const marker = path.join(tempXdg, 'pwned-marker');
    const evilDir = await fs.mkdtemp(path.join(os.tmpdir(), 'vig-evil-scenario-'));
    await fs.writeFile(path.join(evilDir, 'evil.yaml'), [
      'name: Evil',
      'description: planted outside scenario dirs',
      'steps:',
      '  - name: pwn',
      '    type: kubectl',
      `    command: "version --client; touch ${marker}"`,
      ''
    ].join('\n'), 'utf8');
    const engine = new ScenarioEngine({ scenarioDir: path.join(tempXdg, 'no-such-scenarios') });
    const relId = path.relative(engine.userScenarioDir, path.join(evilDir, 'evil')).split(path.sep).join('/');
    await expectThrow(() => engine.runScenario(relId), 'runScenario traversal id');
    assert(!fsSync.existsSync(marker), 'runScenario executed a YAML file outside the scenario directories');
    console.log('✔ Test 10 passed: ScenarioEngine refuses ids that escape the scenario directories.');

    // Test 11: helm rendered values land in a private dir with a sanitized name
    const defaultValuesPath = path.join(rootDir, '..', 'packages', 'vigilante_lib', 'src', 'modules', 'falco', 'values', 'falco.yaml');
    const evilArgs = await resolveChartValuesArgs({
      moduleId: '../../evil',
      chartName: 'falco',
      defaultValuesPath,
      domain: 'vigilante.test',
      tlsSecretName: 'test-tls',
      namespace: 'falco-ns'
    });
    const renderedPath = evilArgs[evilArgs.indexOf('-f') + 1];
    assert(renderedPath.startsWith(os.tmpdir()), 'rendered values path outside tmpdir');
    // The file must sit directly inside a per-call mkdtemp directory — the
    // moduleId may contribute dots/underscores to the *name*, but no segment
    // of the path may be a traversal step.
    const renderedDir = path.dirname(renderedPath);
    assert(path.basename(renderedDir).startsWith('vigilante-helm-values-'), 'rendered file not in a per-call temp dir');
    assert(!renderedPath.split(path.sep).includes('..'), 'rendered path contains a .. segment');
    assert(fsSync.existsSync(renderedPath), 'rendered values file missing');
    console.log('✔ Test 11 passed: helm rendered values use a per-call temp dir and sanitized filenames.');

    console.log('🎉 All Path Traversal Containment tests passed successfully!');
  } finally {
    await fs.rm(tempXdg, { recursive: true, force: true }).catch(() => {});
  }
}

runTests().catch(err => {
  console.error('❌ Traversal test failed:', err);
  process.exit(1);
});
