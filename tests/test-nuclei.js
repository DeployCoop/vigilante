import assert from 'node:assert';
import {
  NUCLEI_PROFILES,
  checkNucleiInstalled,
  parseNucleiOutput,
  runNucleiScan,
  listSavedNucleiScans
} from '../src/engine/nuclei.js';

async function runTests() {
  console.log('🧪 Testing Nuclei Vulnerability Engine...');

  // Test 1: Profiles
  assert(Array.isArray(NUCLEI_PROFILES) && NUCLEI_PROFILES.length >= 4, 'Should have Nuclei profiles');
  const cveProfile = NUCLEI_PROFILES.find(p => p.id === 'cves');
  assert(cveProfile, 'cves profile must exist');
  const cveArgs = cveProfile.buildArgs('http://example.com', { severity: 'critical,high', concurrency: 10 });
  assert(cveArgs.includes('-u') && cveArgs.includes('http://example.com'));
  assert(cveArgs.includes('-tags') && cveArgs.includes('cve'));
  assert(cveArgs.includes('-s') && cveArgs.includes('critical,high'));
  console.log('✔ Test 1 passed: Nuclei profiles and CLI argument builder validated.');

  // Test 2: Tool checks
  const toolStatus = await checkNucleiInstalled();
  assert('installed' in toolStatus && 'runner' in toolStatus);
  console.log(`✔ Test 2 passed: checkNucleiInstalled returned status (runner: ${toolStatus.runner}).`);

  // Test 3: Parse NDJSON output
  const sampleNdjson = `
{"template-id":"cve-2023-12345","info":{"name":"Remote Code Execution in Acme Portal","severity":"critical","description":"Unauthenticated RCE via deserialization","reference":["https://nvd.nist.gov"]},"type":"http","host":"http://target.local","matched-at":"http://target.local/api/vuln"}
{"template-id":"default-admin-creds","info":{"name":"Default Admin Credentials Exposed","severity":"high","description":"Weak default admin password in use"},"type":"http","host":"http://target.local"}
{"template-id":"exposed-git-config","info":{"name":"Git Config Disclosure","severity":"medium"},"type":"http","host":"http://target.local"}
`;
  const findings = parseNucleiOutput(sampleNdjson);
  assert.strictEqual(findings.length, 3);
  assert.strictEqual(findings[0].severity, 'critical');
  assert.strictEqual(findings[0].templateId, 'cve-2023-12345');
  assert.strictEqual(findings[1].severity, 'high');
  assert.strictEqual(findings[2].severity, 'medium');
  console.log('✔ Test 3 passed: parseNucleiOutput successfully extracted findings, severities, and metadata.');

  // Test 4: Run scan and verify evidence & triage
  const scan = await runNucleiScan('http://localhost:8080', 'cves');
  assert(scan.id && scan.filePath);
  assert(scan.stats && typeof scan.stats.total === 'number');

  const saved = await listSavedNucleiScans();
  assert(saved.length >= 1);
  console.log('✔ Test 4 passed: runNucleiScan generated scan record, stats summary, and saved evidence.');

  console.log('🎉 ALL 4 NUCLEI TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('✖ Nuclei test failed:', err);
  process.exit(1);
});
