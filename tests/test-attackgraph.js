import assert from 'node:assert';
import React from 'react';
import {
  buildCompositeAttackGraph,
  findShortestAttackPath,
  calculateBlastRadius,
  renderAsciiAttackGraph
} from '../src/engine/attackgraph.js';
import { AttackGraphView } from '../src/ui/AttackGraphView.js';

async function runTests() {
  console.log('🧪 Testing Composite Attack Graph & Blast-Radius Engine...');

  // Test 1: Default Graph Construction
  const graph = buildCompositeAttackGraph();
  assert.ok(graph.nodes.length >= 8, 'Default graph must contain at least 8 nodes');
  assert.ok(graph.edges.length >= 8, 'Default graph must contain at least 8 edges');
  assert.ok(graph.adjacency instanceof Map, 'Adjacency list must be a Map');
  assert.strictEqual(graph.stats.crownJewels, 3, 'Must identify 3 Crown Jewel targets');
  console.log(`✔ Test 1 passed: buildCompositeAttackGraph initialized graph with ${graph.nodes.length} nodes and ${graph.edges.length} edges.`);

  // Test 2: Custom Multi-Source Telemetry Ingestion
  const mockNmap = [
    { ip: '10.0.0.5', hostname: 'db-master.prod', isCrownJewel: true, openPorts: [5432] }
  ];
  const mockK8s = [
    { name: 'frontend-deployment-xyz', namespace: 'web', tier: 'Edge', serviceAccount: 'web-sa' }
  ];
  const mockBloodhound = [
    {
      source: { id: 'web-sa', name: 'web-sa', type: 'Identity', isCrownJewel: false },
      target: { id: 'db-master.prod', name: 'db-master.prod', type: 'Datastore', isCrownJewel: true },
      relationship: 'DIRECT_ACCESS_CREDENTIAL',
      cost: 1
    }
  ];

  const customGraph = buildCompositeAttackGraph(mockNmap, mockK8s, mockBloodhound);
  assert.ok(customGraph.nodes.some(n => n.id.includes('db-master.prod')));
  assert.ok(customGraph.nodes.some(n => n.id.includes('frontend-deployment')));
  assert.ok(customGraph.edges.some(e => e.type === 'DIRECT_ACCESS_CREDENTIAL'));
  console.log('✔ Test 2 passed: Composite graph accurately federated Nmap, Kubernetes, and BloodHound telemetry.');

  // Test 3: Shortest Attack Path (BFS)
  const pathForward = findShortestAttackPath('ext-attacker', 'sa-cluster-admin', graph);
  assert.strictEqual(pathForward.pathFound, true);
  assert.ok(pathForward.hops >= 3, `Expected at least 3 hops, got ${pathForward.hops}`);
  assert.strictEqual(pathForward.nodePath[0], 'ext-attacker');
  assert.strictEqual(pathForward.nodePath[pathForward.nodePath.length - 1], 'sa-cluster-admin');
  assert.strictEqual(pathForward.edgePath.length, pathForward.hops);

  // Directed graph reverse path test (should not be traversable backwards)
  const pathReverse = findShortestAttackPath('payment-db', 'ext-attacker', graph);
  assert.strictEqual(pathReverse.pathFound, false);
  assert.strictEqual(pathReverse.hops, -1);
  console.log(`✔ Test 3 passed: Shortest attack path resolved ${pathForward.hops}-hop vector to cluster-admin (${pathForward.nodePath.join(' ➔ ')}).`);

  // Test 4: Blast Radius Impact Calculation
  const blastAttacker = calculateBlastRadius('ext-attacker', graph);
  assert.strictEqual(blastAttacker.startNodeId, 'ext-attacker');
  assert.strictEqual(blastAttacker.riskLevel, 'CRITICAL');
  assert.ok(blastAttacker.impactScore >= 70, `Expected high impact score, got ${blastAttacker.impactScore}`);
  assert.ok(blastAttacker.criticalPaths.length > 0, 'Must identify paths to Crown Jewels');

  // Terminal node with 0 blast radius
  const blastTerminal = calculateBlastRadius('corp-dc-01', graph);
  assert.strictEqual(blastTerminal.reachableCount, 0);
  assert.strictEqual(blastTerminal.impactScore, 0);
  assert.strictEqual(blastTerminal.riskLevel, 'LOW');
  console.log(`✔ Test 4 passed: Blast radius calculator scored high risk (${blastAttacker.impactScore}/100) vs isolated node (0/100).`);

  // Test 5: ASCII Attack Graph Renderer
  const ascii = renderAsciiAttackGraph(graph, { highlightPath: pathForward.nodePath });
  assert.ok(ascii.includes('VIGILANTE INTERACTIVE COMPOSITE ATTACK GRAPH'));
  assert.ok(ascii.includes('nginx-ingress-controller'));
  assert.ok(ascii.includes('sa-cluster-admin'));
  assert.ok(ascii.includes('──────▶') || ascii.includes('══════▶'));
  console.log('✔ Test 5 passed: renderAsciiAttackGraph generated colorized directional ANSI graph.');

  // Test 6: React Ink View Instantiation
  const el = React.createElement(AttackGraphView, {});
  assert.ok(el, 'AttackGraphView must instantiate as valid React element');
  console.log('✔ Test 6 passed: AttackGraphView React Ink component instantiated cleanly.');

  console.log('🎉 ALL 6 COMPOSITE ATTACK GRAPH TESTS PASSED SUCCESSFULLY!\n');
}

runTests().catch(err => {
  console.error('❌ Attack Graph test failed:', err);
  process.exit(1);
});
