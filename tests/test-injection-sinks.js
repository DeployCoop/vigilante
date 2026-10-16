import assert from 'node:assert';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

console.log('🧪 Testing injection-sink hardening: Sigma SQL, scenario argv, OpenVAS, threat jobs, remediation scripts, hosts, kCTF manifests, CLI targets...');

const tmpRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-injection-'));
process.env.XDG_CONFIG_HOME = tmpRoot;

const { transpileSigmaToSql, runSigmaThreatHunt } = await import('../src/engine/sigma.js');
const { initDataLake, ingestSecurityEvents, runRetrospectiveThreatHunt, closeDataLake } = await import('../src/engine/datalake.js');
const { splitCommandWords, ScenarioEngine } = await import('../src/engine/scenarios.js');
const { gvmCliCommand, escapeXml } = await import('../src/engine/openvas.js');
const { generateThreatJobManifest } = await import('../src/engine/threats.js');
const { generateRemediationPrScript } = await import('../src/engine/remediation.js');
const { generateManagedBlock } = await import('../src/engine/hosts.js');
const { generateChallengeManifest, generateEphemeralSandboxManifest } = await import('../src/engine/kctf.js');
const { runPing, runDnsLookup } = await import('../src/engine/diagnostics.js');
const { createK3dCluster } = await import('../src/engine/cluster.js');
const { shQuote } = await import('../src/engine/config.js');

// Test 1: Sigma transpiler — rule values cannot break out of the SQL literal
{
  initDataLake(path.join(tmpRoot, 'events.db'));
  ingestSecurityEvents('network', [
    { source_ip: '10.0.0.1', dest_ip: '10.0.0.2', dest_port: 443, severity: 'HIGH', indicator: 'evil.example', source_pod: 'pod-a' },
    { source_ip: '10.0.0.3', dest_ip: '10.0.0.4', dest_port: 80, severity: 'LOW', indicator: 'benign.example', source_pod: 'pod-b' }
  ]);

  // A value crafted to rewrite the WHERE clause must match literally (nothing)
  const hostile = {
    title: 'hostile', level: 'high',
    detection: { selection: { 'indicator|startswith': "x' OR severity='HIGH') -- " }, condition: 'selection' }
  };
  const hostileMatches = await runSigmaThreatHunt([hostile]);
  assert.strictEqual(hostileMatches.length, 0, 'Injected startswith value must not select rows');

  const hostileContains = {
    title: 'hostile2', level: 'high',
    detection: { selection: { 'indicator|contains': "' OR '1'='1') -- " }, condition: 'selection' }
  };
  assert.strictEqual((await runSigmaThreatHunt([hostileContains])).length, 0, 'Injected contains value must not select rows');

  // Unmapped-field (raw_json) branch: same guarantee
  const hostileRaw = {
    title: 'hostile3', level: 'high',
    detection: { selection: { 'unmapped.field|contains': "' OR '1'='1" }, condition: 'selection' }
  };
  assert.strictEqual((await runSigmaThreatHunt([hostileRaw])).length, 0, 'Injected raw_json value must not select rows');

  // Legitimate rules still match, and LIKE wildcards in values stay literal
  const legit = {
    title: 'legit', level: 'high',
    detection: { selection: { 'indicator|contains': 'evil' }, condition: 'selection' }
  };
  const legitMatches = await runSigmaThreatHunt([legit]);
  assert.strictEqual(legitMatches.length, 1);
  assert.strictEqual(legitMatches[0].matchCount, 1);

  const wildcard = {
    title: 'wild', level: 'high',
    detection: { selection: { 'indicator|contains': '%' }, condition: 'selection' }
  };
  assert.strictEqual((await runSigmaThreatHunt([wildcard])).length, 0, 'A literal % value must not act as a wildcard');

  // Table name is an identifier allowlist, not an interpolation
  assert.throws(() => transpileSigmaToSql(legit, { table: 'x; DROP TABLE security_events' }), /Invalid table name/);

  // Retrospective hunt (datalake): % in an indicator is literal too
  assert.strictEqual((await runRetrospectiveThreatHunt(['%'])).length, 0);
  assert.strictEqual((await runRetrospectiveThreatHunt(['evil.example'])).length, 1);
  closeDataLake();
}
console.log('✔ Test 1 passed: Sigma and datalake queries treat rule values as data, not SQL.');

// Test 2: Scenario steps execute as argv, never through a host shell
{
  const words = splitCommandWords(`exec vulnerable-pod -- sh -c 'mkdir -p /hostos && mount /dev/sda1 /hostos || true'`);
  assert.deepStrictEqual(words.slice(0, 4), ['exec', 'vulnerable-pod', '--', 'sh']);
  assert.strictEqual(words[4], '-c');
  assert.strictEqual(words[5], 'mkdir -p /hostos && mount /dev/sda1 /hostos || true', 'Pod-side script stays a single argv word');

  const metachars = splitCommandWords('get pods; touch /tmp/should-not-exist');
  assert.ok(metachars.includes('pods;'), 'Shell metacharacters stay glued to their literal word (inert argv, no shell to interpret them)');
  assert.throws(() => splitCommandWords("get 'unterminated"), /Unterminated/);

  // End to end: a hostile step cannot create a file on the host
  const marker = path.join(tmpRoot, 'scenario-pwned');
  const engine = new ScenarioEngine({ scenarioDir: tmpRoot });
  engine.executeKubectl(`get pods; touch ${marker}`, 'default');
  engine.executeKubectl(`get pods $(touch ${marker})`, 'default');
  assert.strictEqual(fsSync.existsSync(marker), false, 'Hostile scenario step created a host file');
  // Invalid namespace is rejected before execution
  engine.executeKubectl('get pods', 'bad;namespace');
  assert.strictEqual(fsSync.existsSync(marker), false);
}
console.log('✔ Test 2 passed: Scenario commands are tokenized to argv; shell syntax is inert.');

// Test 3: OpenVAS GMP command — credentials and XML are quoted/escaped per context
{
  const cmd = gvmCliCommand('ad min', `p@$$'w0rd`, '<create_target/>');
  assert.ok(cmd.includes(`--gmp-username='ad min'`), 'Username is a single quoted word');
  assert.ok(cmd.includes(`--gmp-password='p@$$'\\''w0rd'`), 'Password quote is escaped, $ stays literal');
  assert.ok(escapeXml('a</hosts><evil/>') === 'a&lt;/hosts&gt;&lt;evil/&gt;', 'Host value cannot break out of <hosts>');
}
console.log('✔ Test 3 passed: OpenVAS in-pod command quotes credentials and escapes the target XML.');

// Test 4: Threat job manifest — playbook data cannot become shell lines or YAML structure
{
  const hostilePlaybook = {
    id: 'evil"; rm -rf',
    name: "x$(touch /tmp/pwned) `id`",
    events: [{ action: 'benign line\ntouch /tmp/pwned # breakout', message: 'm' }]
  };
  const manifest = generateThreatJobManifest(hostilePlaybook, { namespace: 'threat-lab' });
  const lines = manifest.split('\n');
  assert.ok(!lines.some(l => l.trim() === 'touch /tmp/pwned # breakout'), 'Newline in an event action must not become a script line');
  assert.ok(manifest.includes(`echo ${shQuote(`⚡ Injecting Threat Scenario '${hostilePlaybook.name}' (${hostilePlaybook.id}) into OpenSearch at http://opensearch-cluster-master.threat-lab.svc.cluster.local:9200...`)}`),
    'Playbook name/id are emitted as one quoted literal');
  assert.ok(!manifest.includes('vigilante.io/playbook: evil"; rm -rf'), 'Label value is sanitized');
  assert.throws(() => generateThreatJobManifest(hostilePlaybook, { namespace: 'bad namespace' }), /Invalid namespace/);
  assert.throws(() => generateThreatJobManifest(hostilePlaybook, { namespace: 'a/b' }), /Invalid namespace/);
}
console.log('✔ Test 4 passed: Threat job manifests flatten comments, quote literals, and validate namespaces.');

// Test 5: Remediation PR script — branch/file values cannot execute when the script runs
{
  // Payloads use ${IFS} instead of a literal space: git ref names cannot
  // contain spaces, and the point is the substitution, not the space.
  const script = generateRemediationPrScript(['$(touch${IFS}PWNED).yaml'], 'evil$(touch${IFS}PWNED)');
  assert.ok(script.includes('BRANCH_NAME="evil\\$(touch\\${IFS}PWNED)"'), 'Branch substitution is escaped');
  assert.ok(script.includes('git add -- "\\$(touch\\${IFS}PWNED).yaml"'), 'Filename substitution is escaped');

  // Actually run a generated script in a scratch repo: the payloads must
  // be treated as a literal branch name and a literal filename.
  const workDir = path.join(tmpRoot, 'pr-run');
  await fs.mkdir(workDir, { recursive: true });
  const marker = path.join(workDir, 'PWNED');
  try {
    await execFileAsync('git', ['init', '-q'], { cwd: workDir });
    await execFileAsync('git', ['config', 'user.email', 't@example.com'], { cwd: workDir });
    await execFileAsync('git', ['config', 'user.name', 'T'], { cwd: workDir });
    await fs.writeFile(path.join(workDir, '$(touch${IFS}PWNED).yaml'), 'x: 1\n');
    const scriptPath = path.join(workDir, 'pr.sh');
    await fs.writeFile(scriptPath, generateRemediationPrScript(['$(touch${IFS}PWNED).yaml'], 'evil$(touch${IFS}PWNED)'));
    await execFileAsync('bash', [scriptPath], { cwd: workDir });
    assert.strictEqual(fsSync.existsSync(marker), false, 'Generated script executed the payload');
    const { stdout } = await execFileAsync('git', ['branch', '--format=%(refname:short)'], { cwd: workDir });
    assert.ok(stdout.includes('evil$(touch${IFS}PWNED)'), 'Branch was created under its literal name');
  } catch (err) {
    if (err.code !== 'ENOENT') throw err; // git unavailable in this environment: string-level checks above stand
    console.log('  (git unavailable — skipped live script execution)');
  }
}
console.log('✔ Test 5 passed: Generated remediation scripts escape substitutions, live-verified in a scratch repo.');

// Test 6: Hosts block — entries are validated before they can reach /etc/hosts
{
  assert.throws(() => generateManagedBlock(['evil.local\n1.2.3.4 bad.example']), /Invalid hostname/);
  assert.throws(() => generateManagedBlock(['ok.local'], 'not-an-ip'), /Invalid IP/);
  assert.throws(() => generateManagedBlock(['-leading-dash.local']), /Invalid hostname/);
  const block = generateManagedBlock(['siem.vigilante.local'], '127.0.0.1');
  assert.ok(block.includes('127.0.0.1 siem.vigilante.local'));
}
console.log('✔ Test 6 passed: Hosts entries are validated; newline injection is rejected.');

// Test 7: kCTF manifests — identifiers validated/escaped in both generators
{
  assert.throws(() => generateChallengeManifest({ namespace: 'bad/ns' }), /Invalid namespace/);
  assert.throws(() => generateChallengeManifest({ powDifficultySeconds: '10; evil: 1' }), /Invalid powDifficultySeconds/);
  const chal = generateChallengeManifest({ customCategory: 'web"; evil', powDifficultySeconds: 5, namespace: 'ctf-lab' });
  assert.ok(!chal.includes('web"; evil'), 'Category cannot break out of its scalar');
  assert.ok(chal.includes('powDifficultySeconds: 5'));

  const sandbox = generateEphemeralSandboxManifest({
    teamId: 'Team";\nmalicious: 1', challengeId: 'web-1', sandboxId: 'sbx 1', namespace: 'ctf-sandboxes',
    domain: 'vigilante.local', flag: 'VIGILANTE{a"b}', ttlMinutes: 30
  });
  assert.ok(!sandbox.split('\n').some(l => l.startsWith('malicious:')), 'Team id cannot inject manifest structure');
  assert.ok(sandbox.includes('value: "VIGILANTE{a\\"b}"'), 'Flag env value is JSON-escaped');
  assert.ok(sandbox.includes('vigilante.dev/team-id: team'), 'Team label uses the sanitized id');
  assert.throws(() => generateEphemeralSandboxManifest({
    teamId: 't', challengeId: 'c', sandboxId: 's', namespace: 'bad ns', domain: 'vigilante.local', flag: 'f'
  }), /Invalid namespace/);
}
console.log('✔ Test 7 passed: kCTF manifest generators validate and escape caller-supplied identifiers.');

// Test 8: CLI target guards — option-shaped values never reach the tools
{
  await assert.rejects(() => runPing('-oProxyCommand=touch'), /Invalid ping target/);
  await assert.rejects(() => runDnsLookup('-f/etc/passwd'), /Invalid dig target/);
  await assert.rejects(() => createK3dCluster('--create-argument'), /Invalid cluster name/);
}
console.log('✔ Test 8 passed: Leading-dash targets are rejected before reaching ping/dig/k3d.');

console.log('\n🎉 All injection-sink hardening tests passed successfully!\n');
