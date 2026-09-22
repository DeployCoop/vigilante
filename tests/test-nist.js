import assert from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

import {
  NIST_ATTACK_VECTORS,
  NIST_LIFECYCLE_PHASES,
  NIST_EVIDENCE_VOLATILITY,
  ARTIFACT_VOLATILITY_MAP,
  NIST_IMPACT_LEVELS,
  calculateNistIncidentScore,
  classifyAttackVector,
  generateNistIncidentRecord,
  generateNistPostMortemMarkdown,
  listNistIncidents
} from '../src/engine/nist.js';

import { saveTriageBundle } from '../src/engine/evidence.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { createVigilanteMcpServer } from '../src/mcp/server.js';

console.log('🧪 Testing NIST SP 800-61 Rev. 2 Framework & Incident Handling Engine...');

// Test 1: Framework Constants & Taxonomy
assert.ok(NIST_ATTACK_VECTORS.WEB_APPLICATION, 'WEB_APPLICATION vector defined');
assert.ok(NIST_ATTACK_VECTORS.IMPERSONATION, 'IMPERSONATION vector defined');
assert.ok(NIST_ATTACK_VECTORS.ATTRITION, 'ATTRITION vector defined');
assert.ok(NIST_ATTACK_VECTORS.IMPROPER_USAGE, 'IMPROPER_USAGE vector defined');
assert.strictEqual(Object.keys(NIST_ATTACK_VECTORS).length, 8, '8 official attack vectors defined');

assert.strictEqual(NIST_LIFECYCLE_PHASES.PREPARATION.phaseNumber, 1);
assert.strictEqual(NIST_LIFECYCLE_PHASES.DETECTION_AND_ANALYSIS.phaseNumber, 2);
assert.strictEqual(NIST_LIFECYCLE_PHASES.CONTAINMENT_ERADICATION_RECOVERY.phaseNumber, 3);
assert.strictEqual(NIST_LIFECYCLE_PHASES.POST_INCIDENT_ACTIVITY.phaseNumber, 4);

assert.strictEqual(NIST_EVIDENCE_VOLATILITY[1].name, 'CPU Registers & Cache');
assert.strictEqual(NIST_EVIDENCE_VOLATILITY[2].name, 'System Memory (RAM)');
assert.strictEqual(NIST_EVIDENCE_VOLATILITY[3].name, 'Network State & Socket Tables');
assert.strictEqual(ARTIFACT_VOLATILITY_MAP['arp_neighbors.json'].rank, 3);
assert.strictEqual(ARTIFACT_VOLATILITY_MAP['http_headers.txt'].rank, 4);
assert.strictEqual(ARTIFACT_VOLATILITY_MAP['triage_summary.json'].rank, 5);
console.log('✔ Test 1 passed: Verified NIST SP 800-61 Rev 2 vectors, lifecycle phases, and Order of Volatility.');

// Test 2: 3D Incident Prioritization & Scoring
const criticalScore = calculateNistIncidentScore({
  functionalImpact: 'HIGH',
  informationImpact: 'PROPRIETARY_BREACH',
  recoverabilityEffort: 'EXTENDED'
});
assert.strictEqual(criticalScore.severity, 'CRITICAL');
assert.strictEqual(criticalScore.slaTargetMinutes, 15);
assert.ok(criticalScore.compositeScore >= 18);

const mediumScore = calculateNistIncidentScore({
  functionalImpact: 'LOW',
  informationImpact: 'NONE',
  recoverabilityEffort: 'REGULAR'
});
assert.strictEqual(mediumScore.severity, 'LOW');
assert.strictEqual(mediumScore.slaTargetMinutes, 480);
console.log(`✔ Test 2 passed: calculateNistIncidentScore calculated CRITICAL (15m SLA) and LOW severity.`);

// Test 3: Attack Vector Classifier
const webVector = classifyAttackVector({
  ports: [{ port: 8080, service: 'http' }],
  message: 'Log4j JNDI injection string payload in HTTP POST'
});
assert.strictEqual(webVector.id, 'WEB_APPLICATION');

const mitmVector = classifyAttackVector({
  arp: { hasCollision: true },
  message: 'Gratuitous ARP broadcast flood'
});
assert.strictEqual(mitmVector.id, 'IMPERSONATION');

const bruteVector = classifyAttackVector({
  message: 'Repeated SSH brute force password spray'
});
assert.strictEqual(bruteVector.id, 'ATTRITION');
console.log('✔ Test 3 passed: classifyAttackVector accurately classified Web, Impersonation, and Attrition vectors.');

// Test 4: Incident Record & Post-Mortem Markdown Generation
const sampleRecord = generateNistIncidentRecord({
  network: '10.0.1.0_24',
  host: '10.0.1.15',
  attackVector: NIST_ATTACK_VECTORS.WEB_APPLICATION,
  functionalImpact: 'HIGH',
  informationImpact: 'PRIVACY_BREACH',
  rootCause: 'Unauthenticated RCE on port 8080 (CVE-2021-44228)'
});
assert.ok(sampleRecord.incidentId.startsWith('INC-'));
assert.strictEqual(sampleRecord.classification.attackVector.id, 'WEB_APPLICATION');
assert.strictEqual(sampleRecord.prioritization.severity, 'CRITICAL');

const markdown = generateNistPostMortemMarkdown(sampleRecord);
assert.ok(markdown.includes('NIST SP 800-61 Rev. 2 Incident Post-Mortem'));
assert.ok(markdown.includes('Order of Volatility'));
assert.ok(markdown.includes(sampleRecord.incidentId));
assert.ok(markdown.includes('Phase 1: Preparation'));
assert.ok(markdown.includes('Phase 2: Detection & Analysis'));
assert.ok(markdown.includes('Phase 3: Containment, Eradication & Recovery'));
assert.ok(markdown.includes('Phase 4: Post-Incident Activity'));
console.log('✔ Test 4 passed: Generated NIST incident manifest and 4-phase Post-Mortem Markdown.');

// Test 5: Triage Bundle Integration with NIST Incident Manifest
const testTmpDir = path.join(os.tmpdir(), `vigilante-nist-test-${Date.now().toString(36)}`);
process.env.XDG_CONFIG_HOME = testTmpDir;

try {
  const triageRes = await saveTriageBundle('10.0.1.0/24', '10.0.1.25', {
    ping: { rtt: 1.2, packetLoss: 0 },
    dns: { query: 'app.vigilante.local', ip: '10.0.1.25' },
    http: { output: 'HTTP/1.1 200 OK\r\nServer: Apache/2.4' },
    arp: { hasCollision: true, gateway: '10.0.1.1' },
    metadata: { reason: 'Active intrusion investigation' }
  });

  assert.ok(triageRes.nistIncidentId);
  assert.ok(triageRes.nistAttackVector);
  assert.ok(triageRes.artifacts.some(a => a.name === 'nist_incident_record.json'));
  assert.ok(triageRes.artifacts.some(a => a.name === 'triage_summary.json'));

  const discoveredIncidents = await listNistIncidents();
  assert.ok(discoveredIncidents.length >= 1, 'Discovered saved incident record in Evidence Vault');
  assert.strictEqual(discoveredIncidents[0].target.host, '10.0.1.25');
  console.log(`✔ Test 5 passed: saveTriageBundle generated and discovered nist_incident_record.json (${discoveredIncidents.length} incident found).`);
} finally {
  await fs.rm(testTmpDir, { recursive: true, force: true }).catch(() => {});
}

// Test 6: MCP Server Integration for NIST Resources and Tools
const mcpServer = createVigilanteMcpServer();
const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
const client = new Client(
  { name: 'nist-test-client', version: '0.1.0' },
  { capabilities: {} }
);

await mcpServer.connect(serverTransport);
await client.connect(clientTransport);

try {
  const resourcesRes = await client.listResources();
  const nistFrameworkRes = resourcesRes.resources.find(r => r.uri === 'vigilante://nist/framework');
  const nistIncidentsRes = resourcesRes.resources.find(r => r.uri === 'vigilante://nist/incidents');
  assert.ok(nistFrameworkRes, 'vigilante://nist/framework resource exposed');
  assert.ok(nistIncidentsRes, 'vigilante://nist/incidents resource exposed');

  const frameworkData = await client.readResource({ uri: 'vigilante://nist/framework' });
  const parsedFramework = JSON.parse(frameworkData.contents[0].text);
  assert.ok(parsedFramework.lifecyclePhases.PREPARATION);
  assert.ok(parsedFramework.attackVectors.WEB_APPLICATION);
  console.log('✔ Test 6 passed: MCP Server exposes vigilante://nist/framework and vigilante://nist/incidents.');

  const toolsRes = await client.listTools();
  const assessTool = toolsRes.tools.find(t => t.name === 'assess_nist_incident');
  const postmortemTool = toolsRes.tools.find(t => t.name === 'generate_nist_postmortem');
  assert.ok(assessTool, 'assess_nist_incident tool registered');
  assert.ok(postmortemTool, 'generate_nist_postmortem tool registered');

  const assessExecution = await client.callTool({
    name: 'assess_nist_incident',
    arguments: {
      host: '10.0.1.50',
      network: '10.0.1.0_24',
      functionalImpact: 'HIGH',
      informationImpact: 'INTEGRITY_LOSS',
      recoverabilityEffort: 'EXTENDED',
      rootCause: 'Ransomware lateral propagation via SMB'
    }
  });
  const assessedData = JSON.parse(assessExecution.content[0].text);
  assert.strictEqual(assessedData.prioritization.severity, 'CRITICAL');
  assert.strictEqual(assessedData.slas.containmentTargetMinutes, 15);
  console.log(`✔ Test 7 passed: assess_nist_incident tool executed successfully (Severity: ${assessedData.prioritization.severity}).`);
} finally {
  await client.close();
}

console.log('🎉 All NIST SP 800-61 Rev. 2 Framework & Incident Handling tests passed successfully!\n');
