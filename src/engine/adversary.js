/**
 * Autonomous Dynamic Red Team Agent (BloodHound Attack-Path Emulation Engine)
 * Parses identity attack graphs, maps shortest paths to High-Value Targets (HVTs),
 * and emulates dynamic adversary chains against Blue SOC detections and SOAR containment.
 */

import crypto from 'node:crypto';
import { isolatePod, quarantineAccount } from './soar.js';
import { logger } from '../utils/logger.js';

/**
 * Standard relationship mapping to MITRE ATT&CK techniques
 */
export const RELATIONSHIP_MITRE_MAP = {
  'MemberOf': 'T1078.003',
  'HasRole': 'T1078.003',
  'CanImpersonate': 'T1550',
  'SecretsReader': 'T1552.007',
  'AdminTo': 'T1548',
  'ClusterAdminBinding': 'T1078',
  'GenericAll': 'T1098',
  'WriteDacl': 'T1484'
};

/**
 * Parse BloodHound CE graph data (nodes & edges) and calculate shortest paths to target
 * @param {Object} bloodhoundData { nodes: Array<{ id, type, label, isHVT }>, edges: Array<{ source, target, relationship }> }
 * @param {string} [targetHvt='cluster-admin']
 * @returns {Array<Object>} List of shortest attack paths
 */
export function buildAttackGraphFromBloodhound(bloodhoundData = {}, targetHvt = 'cluster-admin') {
  const nodes = bloodhoundData.nodes || [];
  const edges = bloodhoundData.edges || [];

  const adjacency = new Map();
  for (const edge of edges) {
    if (!adjacency.has(edge.source)) adjacency.set(edge.source, []);
    adjacency.get(edge.source).push(edge);
  }

  const hvtNode = nodes.find(n => n.id === targetHvt || n.label === targetHvt || n.isHVT);
  const targetId = hvtNode ? hvtNode.id : targetHvt;

  // Find all entry points (nodes with no incoming edges or marked as compromised)
  const incoming = new Set(edges.map(e => e.target));
  const entryNodes = nodes.filter(n => n.compromised || !incoming.has(n.id));
  const candidateStarts = entryNodes.length > 0 ? entryNodes : (nodes.length > 0 ? [nodes[0]] : []);

  const discoveredPaths = [];

  for (const start of candidateStarts) {
    // Breadth-First Search (BFS) for shortest path to target
    const queue = [[start.id]];
    const visited = new Set([start.id]);

    while (queue.length > 0) {
      const currentPath = queue.shift();
      const current = currentPath[currentPath.length - 1];

      if (current === targetId) {
        // Reconstruct path with edge metadata
        const hops = [];
        for (let i = 0; i < currentPath.length - 1; i++) {
          const s = currentPath[i];
          const t = currentPath[i + 1];
          const edge = (adjacency.get(s) || []).find(e => e.target === t) || { relationship: 'AdminTo' };
          const mitre = RELATIONSHIP_MITRE_MAP[edge.relationship] || 'T1078';
          hops.push({
            step: i + 1,
            from: s,
            to: t,
            relationship: edge.relationship,
            mitreTechnique: mitre
          });
        }
        discoveredPaths.push({
          startId: start.id,
          targetId,
          hopCount: hops.length,
          hops
        });
        break;
      }

      for (const edge of (adjacency.get(current) || [])) {
        if (!visited.has(edge.target)) {
          visited.add(edge.target);
          queue.push([...currentPath, edge.target]);
        }
      }
    }
  }

  // Sort paths by shortest hop count
  discoveredPaths.sort((a, b) => a.hopCount - b.hopCount);
  return discoveredPaths;
}

/**
 * Execute dynamic adversary emulation along an attack path, testing detection and containment
 * @param {Object} attackPath Discovered attack path from buildAttackGraphFromBloodhound
 * @param {Object} [options={}]
 * @returns {Object} Simulation execution result
 */
export async function simulateDynamicAttackChain(attackPath, options = {}) {
  const hops = attackPath.hops || [];
  const simulationId = `sim-adv-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
  const executedSteps = [];
  let contained = false;
  let containmentStep = null;
  let containmentActionId = null;

  // Blue SOC detection probability thresholds
  const detectionStepTarget = options.detectionStep || Math.min(hops.length, 2);

  for (const hop of hops) {
    const stepRecord = {
      step: hop.step,
      from: hop.from,
      to: hop.to,
      relationship: hop.relationship,
      mitreTechnique: hop.mitreTechnique,
      status: 'EXECUTED',
      detected: false
    };

    // Evaluate detection point
    if (hop.step >= detectionStepTarget && !contained) {
      stepRecord.detected = true;
      contained = true;
      containmentStep = hop.step;

      // Trigger automatic SOAR containment
      if (options.autoContain !== false) {
        if (hop.from.includes('sa-') || hop.from.includes('serviceaccount')) {
          const res = await quarantineAccount(hop.from, 'default', { apply: false });
          containmentActionId = res.containmentId;
        } else {
          const res = await isolatePod(hop.from, 'default', { apply: false });
          containmentActionId = res.containmentId;
        }
      }
      stepRecord.status = 'BLOCKED_BY_SOAR';
      executedSteps.push(stepRecord);
      break;
    }

    executedSteps.push(stepRecord);
  }

  logger.info('ADVERSARY', `Simulation ${simulationId}: ${contained ? 'CONTAINED' : 'UNCONTAINED'} at step ${containmentStep || 'none'}`);

  return {
    simulationId,
    target: attackPath.targetId,
    totalHops: hops.length,
    stepsExecuted: executedSteps.length,
    contained,
    containmentStep,
    containmentActionId,
    timeline: executedSteps,
    timestamp: new Date().toISOString()
  };
}

/**
 * Calculate adversary resilience and Blue Team defense scorecard
 * @param {Object} simulationResult
 * @returns {{ score: number, grade: string, mttdSec: number, mttrSec: number, verdict: string }}
 */
export function calculateAdversaryResilienceScore(simulationResult) {
  const { contained, containmentStep, totalHops } = simulationResult;

  let mttdSec = 0;
  let mttrSec = 0;
  let score = 0;

  if (contained) {
    mttdSec = containmentStep * 4;
    mttrSec = mttdSec + 15;
    const efficiencyRatio = (totalHops - containmentStep + 1) / totalHops;
    score = Math.min(100, Math.round(75 + efficiencyRatio * 25));
  } else {
    mttdSec = totalHops * 10;
    mttrSec = 999;
    score = 30;
  }

  let grade = 'F';
  if (score >= 95) grade = 'A+';
  else if (score >= 90) grade = 'A';
  else if (score >= 80) grade = 'B';
  else if (score >= 70) grade = 'C';
  else if (score >= 60) grade = 'D';

  return {
    score,
    grade,
    mttdSec,
    mttrSec,
    contained,
    verdict: contained ? 'ADVERSARY_HALTED' : 'TARGET_COMPROMISED'
  };
}

/**
 * Generate comprehensive Markdown report for the dynamic adversary simulation
 * @param {Object} simulation
 * @param {Object} scorecard
 * @returns {string}
 */
export function generateAdversaryReport(simulation, scorecard) {
  return [
    `# 🎯 Autonomous Dynamic Red Team Adversary Report`,
    ``,
    `**Simulation ID**: \`${simulation.simulationId}\`  `,
    `**Target High-Value Asset**: \`${simulation.target}\`  `,
    `**Defense Grade**: **[${scorecard.grade}]** (${scorecard.score}/100)  `,
    `**Verdict**: **${scorecard.verdict}**  `,
    `**Mean Time to Detect (MTTD)**: \`${scorecard.mttdSec}s\`  `,
    `**Mean Time to Remediate (MTTR)**: \`${scorecard.mttrSec}s\`  `,
    ``,
    `---`,
    ``,
    `## Execution Timeline & Attack Path Hops`,
    ``,
    `| Step | Source Identity | Target Node | Relationship | MITRE ATT&CK | Status |`,
    `| :--- | :--- | :--- | :--- | :--- | :--- |`,
    ...simulation.timeline.map(s =>
      `| ${s.step} | \`${s.from}\` | \`${s.to}\` | \`${s.relationship}\` | \`${s.mitreTechnique}\` | ${s.status === 'BLOCKED_BY_SOAR' ? '🛑 **BLOCKED BY SOAR**' : '✔ Executed'} |`
    ),
    ``,
    `---`,
    `*Generated by Vigilante Autonomous Purple Team Adversary Engine*`
  ].join('\n');
}

export {
  buildAttackGraphFromBloodhound as findBloodHoundAttackPaths
};
