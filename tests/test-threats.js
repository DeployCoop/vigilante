import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';
import React from 'react';
import { render } from 'ink';
import {
  BUILTIN_PLAYBOOKS,
  listAvailablePlaybooks,
  loadPlaybook,
  validatePlaybook,
  generateThreatJobManifest,
  createCustomPlaybookTemplate,
  executeThreatPlaybook
} from '../src/engine/threats.js';
import { ThreatSimView } from '../src/ui/ThreatSimView.js';

console.log('🧪 Testing Modular Threat Simulation Engine & Custom Playbooks...');

// Set up isolated XDG test environment
const testXdg = await fs.mkdtemp(path.join(os.tmpdir(), 'vigilante-threats-test-'));
process.env.XDG_CONFIG_HOME = testXdg;

try {
  // Test 1: Verify built-in playbooks and MITRE techniques
  assert(Array.isArray(BUILTIN_PLAYBOOKS), 'BUILTIN_PLAYBOOKS must be an array');
  assert(BUILTIN_PLAYBOOKS.length >= 7, `Expected at least 7 built-in playbooks, got ${BUILTIN_PLAYBOOKS.length}`);

  const requiredScenarios = [
    'recon-sweep',
    'credential-bruteforce',
    'dns-tunneling-exfil',
    'ransomware-lateral',
    'k8s-pod-escape',
    'web-cve-rce',
    'arp-poison-mitm'
  ];

  requiredScenarios.forEach(id => {
    const pb = BUILTIN_PLAYBOOKS.find(p => p.id === id);
    assert(pb, `Built-in scenario '${id}' missing`);
    assert(pb.name, `Scenario '${id}' missing name`);
    assert(pb.mitreTechniques && pb.mitreTechniques.length > 0, `Scenario '${id}' missing MITRE techniques`);
    assert(pb.events && pb.events.length > 0, `Scenario '${id}' missing simulated events`);
  });
  console.log(`✔ Test 1 passed: Verified ${BUILTIN_PLAYBOOKS.length} built-in threat simulation playbooks with MITRE ATT&CK mappings.`);

  // Test 2: validatePlaybook validation logic
  const validRes = validatePlaybook(BUILTIN_PLAYBOOKS[0]);
  assert(validRes.valid === true, 'Built-in playbook should be valid');

  const invalidRes = validatePlaybook({ id: 'broken' });
  assert(invalidRes.valid === false, 'Playbook without name/events should be invalid');
  assert(invalidRes.errors.length > 0, 'Invalid playbook must report errors');
  console.log('✔ Test 2 passed: validatePlaybook correctly verified schema constraints.');

  // Test 3: listAvailablePlaybooks discovers all built-ins
  const allInitial = await listAvailablePlaybooks();
  assert(allInitial.length >= BUILTIN_PLAYBOOKS.length, 'listAvailablePlaybooks should return all built-in playbooks');
  console.log(`✔ Test 3 passed: listAvailablePlaybooks discovered ${allInitial.length} available scenarios.`);

  // Test 4: createCustomPlaybookTemplate generates valid YAML in XDG playbooks dir
  const templateRes = await createCustomPlaybookTemplate('zero-day-sql-injection', {
    name: 'Zero-Day SQL Injection & Database Exfiltration',
    category: 'initial-access',
    severity: 'CRITICAL',
    mitreTechniques: [{ id: 'T1190', name: 'Exploit Public-Facing Application' }]
  });

  assert(templateRes.filePath.includes('zero-day-sql-injection.yaml'), 'Template path should match name');
  const templateStats = await fs.stat(templateRes.filePath);
  assert(templateStats.size > 0, 'Template file should not be empty');
  console.log(`✔ Test 4 passed: createCustomPlaybookTemplate wrote ${path.basename(templateRes.filePath)}.`);

  // Test 5: listAvailablePlaybooks auto-discovers custom playbook from XDG
  const afterCustom = await listAvailablePlaybooks();
  const discoveredCustom = afterCustom.find(p => p.id === 'zero-day-sql-injection');
  assert(discoveredCustom, 'Custom playbook should be discovered in XDG playbooks dir');
  assert(discoveredCustom.isCustom === true, 'Custom playbook flag should be true');
  assert.strictEqual(discoveredCustom.name, 'Zero-Day SQL Injection & Database Exfiltration');
  console.log(`✔ Test 5 passed: Discovered and loaded custom user playbook '${discoveredCustom.name}'.`);

  // Test 6: loadPlaybook by ID and by explicit file path
  const loadedById = await loadPlaybook('dns-tunneling-exfil');
  assert.strictEqual(loadedById.id, 'dns-tunneling-exfil');

  const loadedByPath = await loadPlaybook(templateRes.filePath);
  assert.strictEqual(loadedByPath.id, 'zero-day-sql-injection');

  let failedNonExistent = false;
  try {
    await loadPlaybook('non-existent-scenario-xyz');
  } catch {
    failedNonExistent = true;
  }
  assert(failedNonExistent, 'loadPlaybook should throw on unknown scenario ID');
  console.log('✔ Test 6 passed: loadPlaybook retrieved scenarios by ID and absolute file path.');

  // Test 7: generateThreatJobManifest produces valid Kubernetes batch/v1 Job with ECS payloads
  const manifest = generateThreatJobManifest(loadedById, { namespace: 'threat-lab' });
  assert(manifest.includes('apiVersion: batch/v1'), 'Manifest must be batch/v1');
  assert(manifest.includes('kind: Job'), 'Manifest kind must be Job');
  assert(manifest.includes('namespace: threat-lab'), 'Manifest must target requested namespace');
  assert(manifest.includes('opensearch-cluster-master.threat-lab.svc.cluster.local:9200'), 'Manifest must target OpenSearch in namespace');
  assert(manifest.includes('T1071.004'), 'Manifest must include MITRE ATT&CK technique in payload');
  assert(manifest.includes('vigilante-network-events'), 'Manifest must target vigilante-network-events index');
  console.log('✔ Test 7 passed: generateThreatJobManifest generated valid Kubernetes Job with ECS telemetry payloads.');

  // Test 8: ThreatSimView React Ink Component Rendering
  assert(typeof ThreatSimView === 'function', 'ThreatSimView must be a React component function');
  const appInstance = render(React.createElement(ThreatSimView, { domain: 'vigilante.local' }));
  assert.ok(appInstance);
  appInstance.unmount();
  console.log('✔ Test 8 passed: ThreatSimView React component rendered successfully.');

  console.log('🎉 All Modular Threat Simulation Engine & Custom Playbooks tests passed successfully!');
} finally {
  await fs.rm(testXdg, { recursive: true, force: true }).catch(() => {});
}
