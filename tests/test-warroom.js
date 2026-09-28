import assert from 'node:assert';
import {
  conveneIncidentWarRoom,
  calculateConsensusScore,
  generateWarRoomTranscript,
  WARROOM_ROLES
} from '../src/engine/warroom.js';

console.log('🧪 Testing Autonomous Multi-Agent Incident War Room & Consensus Debate...');

// Test 1: calculateConsensusScore calculation with unanimous opinions
const unanimousOpinions = [
  { role: WARROOM_ROLES.FORENSICS, verdict: 'CONTAIN', confidence: 90 },
  { role: WARROOM_ROLES.THREAT_INTEL, verdict: 'CONTAIN', confidence: 85 },
  { role: WARROOM_ROLES.SRE_RELIABILITY, verdict: 'CONTAIN', confidence: 80 }
];

const unanimousRes = calculateConsensusScore(unanimousOpinions, 75);
assert.strictEqual(unanimousRes.consensusScore, 100);
assert.strictEqual(unanimousRes.quorumApproved, true);
assert.strictEqual(unanimousRes.dissentingCount, 0);
assert.strictEqual(unanimousRes.finalVerdict, 'CONTAIN');
console.log('✔ Test 1 passed: calculateConsensusScore accurately evaluated unanimous consensus (100%).');

// Test 2: calculateConsensusScore with dissenting opinion
const dissentingOpinions = [
  { role: WARROOM_ROLES.FORENSICS, verdict: 'CONTAIN', confidence: 80 },
  { role: WARROOM_ROLES.THREAT_INTEL, verdict: 'INVESTIGATE', confidence: 80, rationale: 'Low IoC certainty' },
  { role: WARROOM_ROLES.SRE_RELIABILITY, verdict: 'MONITOR', confidence: 80, rationale: 'Production revenue risk' }
];

const dissentRes = calculateConsensusScore(dissentingOpinions, 75);
assert.ok(dissentRes.consensusScore < 75, `Expected score < 75%, got ${dissentRes.consensusScore}%`);
assert.strictEqual(dissentRes.quorumApproved, false);
assert.strictEqual(dissentRes.dissentingCount, 2);
assert.strictEqual(dissentRes.finalVerdict, 'INVESTIGATE');
console.log(`✔ Test 2 passed: calculateConsensusScore rejected containment when quorum not reached (Score: ${dissentRes.consensusScore}%).`);

// Test 3: conveneIncidentWarRoom execution on critical threat
const criticalIncident = {
  pod: 'api-server-7bc9-44x',
  severity: 'CRITICAL',
  mitreTechnique: 'T1059.004',
  isC2: true,
  memAnomalies: true
};

const session = conveneIncidentWarRoom(criticalIncident, { quorumThreshold: 75 });
assert.ok(session.sessionId.startsWith('warroom-'));
assert.strictEqual(session.targetWorkload, 'api-server-7bc9-44x');
assert.strictEqual(session.opinions.length, 4, 'Should contain 3 specialists + 1 Commander');
assert.strictEqual(session.consensus.quorumApproved, true);
assert.ok(session.transcriptMarkdown.includes('Autonomous Incident War Room Deliberation Transcript'));
assert.ok(session.transcriptMarkdown.includes('Incident Commander'));
console.log(`✔ Test 3 passed: conveneIncidentWarRoom convened 4-agent consortium and approved containment (Score: ${session.consensus.consensusScore}%).`);

// Test 4: generateWarRoomTranscript markdown structure
const transcript = generateWarRoomTranscript(session);
assert.ok(transcript.includes('Specialist Consortium Deliberations'));
assert.ok(transcript.includes('Quorum Consensus Determination'));
assert.ok(transcript.includes('QUORUM APPROVED'));
console.log('✔ Test 4 passed: generateWarRoomTranscript generated structured Markdown post-mortem.');

console.log('🎉 All Autonomous Multi-Agent Incident War Room tests passed successfully!\n');
