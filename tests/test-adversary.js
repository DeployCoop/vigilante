import {
  buildAttackGraphFromBloodhound,
  simulateDynamicAttackChain,
  calculateAdversaryResilienceScore,
  generateAdversaryReport
} from '../src/engine/adversary.js';
import { listActiveContainments } from '../src/engine/soar.js';

async function runTests() {
  console.log('🧪 Testing Autonomous Dynamic Red Team Adversary Engine...');

  // Mock BloodHound Graph data
  const mockBloodhoundData = {
    nodes: [
      { id: 'pod-frontend', type: 'Pod', label: 'frontend-nginx', compromised: true },
      { id: 'sa-frontend', type: 'ServiceAccount', label: 'frontend-sa' },
      { id: 'role-dev', type: 'Role', label: 'developer-role' },
      { id: 'sa-cicd', type: 'ServiceAccount', label: 'cicd-runner' },
      { id: 'cluster-admin', type: 'ClusterRole', label: 'cluster-admin', isHVT: true }
    ],
    edges: [
      { source: 'pod-frontend', target: 'sa-frontend', relationship: 'HasRole' },
      { source: 'sa-frontend', target: 'role-dev', relationship: 'MemberOf' },
      { source: 'role-dev', target: 'sa-cicd', relationship: 'CanImpersonate' },
      { source: 'sa-cicd', target: 'cluster-admin', relationship: 'ClusterAdminBinding' }
    ]
  };

  // Test 1: Graph BFS & Shortest Path Discovery
  const paths = buildAttackGraphFromBloodhound(mockBloodhoundData, 'cluster-admin');
  if (paths.length === 0) throw new Error('Failed to discover attack paths from BloodHound graph');
  const primaryPath = paths[0];
  if (primaryPath.hopCount !== 4) {
    throw new Error(`Expected 4 hops to cluster-admin, got: ${primaryPath.hopCount}`);
  }
  console.log(`✔ Test 1 passed: Discovered shortest attack path (${primaryPath.hopCount} hops) from ${primaryPath.startId} to ${primaryPath.targetId}.`);

  // Test 2: Dynamic Adversary Emulation & SOAR Containment
  const simResult = await simulateDynamicAttackChain(primaryPath, { detectionStep: 2, autoContain: true });
  if (!simResult.contained) throw new Error('Expected adversary to be contained by Blue Team');
  if (simResult.containmentStep !== 2) throw new Error(`Expected containment at step 2, got: ${simResult.containmentStep}`);
  if (!simResult.containmentActionId) throw new Error('Expected SOAR containment action ID');
  console.log(`✔ Test 2 passed: Adversary simulation executed (${simResult.simulationId}) - Halted at Step ${simResult.containmentStep}.`);

  // Test 3: Resilience Scorecard
  const scorecard = calculateAdversaryResilienceScore(simResult);
  if (scorecard.grade !== 'A+' && scorecard.grade !== 'A') {
    throw new Error(`Expected grade A or A+, got: ${scorecard.grade}`);
  }
  if (scorecard.verdict !== 'ADVERSARY_HALTED') {
    throw new Error(`Expected ADVERSARY_HALTED, got: ${scorecard.verdict}`);
  }
  console.log(`✔ Test 3 passed: Scorecard generated: Grade [${scorecard.grade}] (${scorecard.score}/100), MTTD: ${scorecard.mttdSec}s, MTTR: ${scorecard.mttrSec}s.`);

  // Test 4: Executive Markdown Report Rendering
  const report = generateAdversaryReport(simResult, scorecard);
  if (!report.includes('Autonomous Dynamic Red Team Adversary Report') || !report.includes('BLOCKED BY SOAR')) {
    throw new Error('Markdown report missing key adversary summary fields');
  }
  console.log('✔ Test 4 passed: Generated comprehensive wargame Markdown report.');

  console.log('🎉 ALL 4 DYNAMIC ADVERSARY TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Dynamic Adversary test failure:', err);
  process.exit(1);
});
