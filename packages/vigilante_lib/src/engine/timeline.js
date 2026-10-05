/**
 * VIGILANTE Automated Root-Cause DAG Synthesis & Attack Timeline Engine
 * Reconstructs end-to-end incident attack chains from heterogeneous security telemetry,
 * synthesizes causality DAGs (process lineage, network triggers, file drops),
 * pinpoints initial compromise root cause ($t_0$), and calculates attacker dwell time.
 */

import crypto from 'node:crypto';
import { logger } from '../utils/logger.js';

/**
 * Common causality relationship types
 */
export const CAUSAL_RELATIONS = {
  SPAWNED_BY: 'SPAWNED_BY',
  NETWORK_INITIATED: 'NETWORK_INITIATED',
  FILE_WRITTEN_THEN_EXEC: 'FILE_WRITTEN_THEN_EXEC',
  CREDENTIAL_STOLEN_THEN_USED: 'CREDENTIAL_STOLEN_THEN_USED',
  LATERAL_HOP: 'LATERAL_HOP',
  TEMPORAL_SEQUENCE: 'TEMPORAL_SEQUENCE'
};

/**
 * Build a Causal Directed Acyclic Graph (DAG) and chronological timeline
 * @param {Array<Object>} rawEvents Telemetry events (Falco, Wazuh, Suricata, Auditd, K8s)
 * @param {Object} [options={}]
 * @returns {Object} Causality DAG structure
 */
export function buildCausalTimeline(rawEvents = [], options = {}) {
  if (!rawEvents || rawEvents.length === 0) {
    return {
      nodes: [],
      edges: [],
      adjacency: new Map(),
      inDegrees: new Map(),
      stats: { totalEvents: 0, causalEdges: 0, rootCandidates: 0 }
    };
  }

  // 1. Sort events chronologically
  const sorted = [...rawEvents].map((evt, idx) => {
    const ts = evt.timestamp ? new Date(evt.timestamp).getTime() : Date.now() + idx * 1000;
    return {
      id: evt.id || `evt-${idx + 1}-${ts}`,
      index: idx + 1,
      timestamp: ts,
      isoTime: new Date(ts).toISOString(),
      type: evt.type || 'SECURITY_ALERT',
      title: evt.title || evt.name || evt.type || 'Event',
      entity: evt.entity || evt.workload || evt.pod || 'unknown-host',
      pid: evt.pid != null ? Number(evt.pid) : null,
      ppid: evt.ppid != null ? Number(evt.ppid) : null,
      command: evt.command || evt.cmdline || null,
      file: evt.file || evt.path || null,
      srcIp: evt.srcIp || evt.clientIp || null,
      dstIp: evt.dstIp || null,
      dstPort: evt.dstPort != null ? Number(evt.dstPort) : null,
      mitreTechnique: evt.mitreTechnique || evt.technique || null,
      severity: (evt.severity || 'MEDIUM').toUpperCase(),
      sourceModule: evt.sourceModule || evt.source || 'telemetry',
      details: evt.details || evt.message || ''
    };
  }).sort((a, b) => a.timestamp - b.timestamp);

  const nodes = sorted;
  const edges = [];
  const edgeSet = new Set();
  const adjacency = new Map();
  const inDegrees = new Map();

  nodes.forEach(n => {
    adjacency.set(n.id, []);
    inDegrees.set(n.id, 0);
  });

  const addEdge = (fromId, toId, type, description) => {
    if (fromId === toId) return;
    const key = `${fromId}->${toId}:${type}`;
    if (edgeSet.has(key)) return;
    edgeSet.add(key);

    const edge = { from: fromId, to: toId, type, description };
    edges.push(edge);
    adjacency.get(fromId).push(edge);
    inDegrees.set(toId, (inDegrees.get(toId) || 0) + 1);
  };

  // 2. Synthesize causality links
  for (let i = 0; i < nodes.length; i++) {
    const parent = nodes[i];

    for (let j = i + 1; j < nodes.length; j++) {
      const child = nodes[j];
      const timeDiffMs = child.timestamp - parent.timestamp;

      // Link A: Process Lineage (Parent PID -> Child PID / PPID)
      if (parent.pid != null && child.ppid != null && parent.pid === child.ppid) {
        addEdge(
          parent.id,
          child.id,
          CAUSAL_RELATIONS.SPAWNED_BY,
          `Process '${child.command || child.title}' (PID ${child.pid}) spawned by PID ${parent.pid} ('${parent.command || parent.title}')`
        );
        continue;
      }

      // Link B: Network Ingress -> Process Spawn / Shell Execution within 10s
      if (
        (parent.srcIp || parent.type.includes('NETWORK') || parent.type.includes('INGRESS')) &&
        (child.type.includes('EXEC') || child.type.includes('SHELL') || child.command) &&
        timeDiffMs >= 0 && timeDiffMs <= 10000 &&
        (!parent.entity || !child.entity || parent.entity === child.entity)
      ) {
        addEdge(
          parent.id,
          child.id,
          CAUSAL_RELATIONS.NETWORK_INITIATED,
          `Inbound network connection from ${parent.srcIp || 'external'} triggered execution of '${child.command || child.title}'`
        );
        continue;
      }

      // Link C: File Drop/Download -> Execution within 30s
      if (
        (parent.type.includes('FILE_WRITE') || parent.type.includes('DOWNLOAD') || parent.file) &&
        (child.type.includes('EXEC') || child.command) &&
        timeDiffMs >= 0 && timeDiffMs <= 30000
      ) {
        const parentPath = parent.file || (parent.command && parent.command.split(/\s+/).pop());
        const childCmd = child.command || '';
        if (parentPath && childCmd.includes(parentPath)) {
          addEdge(
            parent.id,
            child.id,
            CAUSAL_RELATIONS.FILE_WRITTEN_THEN_EXEC,
            `Executable file '${parentPath}' written/downloaded and subsequently executed`
          );
          continue;
        }
      }

      // Link D: Credential Theft -> Lateral Movement
      if (
        (parent.type.includes('CREDENTIAL') || parent.mitreTechnique === 'T1003') &&
        (child.type.includes('LATERAL') || child.mitreTechnique === 'T1021' || child.type.includes('EGRESS')) &&
        timeDiffMs >= 0 && timeDiffMs <= 60000
      ) {
        addEdge(
          parent.id,
          child.id,
          CAUSAL_RELATIONS.CREDENTIAL_STOLEN_THEN_USED,
          `Stolen credentials leveraged for lateral movement / authentication`
        );
        continue;
      }
    }
  }

  // 3. Fallback: If disconnected, link sequential events on same entity
  for (let i = 0; i < nodes.length - 1; i++) {
    const cur = nodes[i];
    const nxt = nodes[i + 1];
    if (inDegrees.get(nxt.id) === 0 && cur.entity === nxt.entity) {
      addEdge(
        cur.id,
        nxt.id,
        CAUSAL_RELATIONS.TEMPORAL_SEQUENCE,
        `Consecutive chronological action on host/workload ${cur.entity}`
      );
    }
  }

  const rootCandidates = nodes.filter(n => (inDegrees.get(n.id) || 0) === 0);

  return {
    nodes,
    edges,
    adjacency,
    inDegrees,
    stats: {
      totalEvents: nodes.length,
      causalEdges: edges.length,
      rootCandidates: rootCandidates.length
    }
  };
}

/**
 * Identify the primary root-cause event and attack entry vector
 * @param {Object} dag Causal timeline DAG
 * @returns {Object} Root cause analysis result
 */
export function identifyRootCause(dag) {
  if (!dag || !dag.nodes || dag.nodes.length === 0) {
    return {
      rootCauseNode: null,
      initialVector: 'UNKNOWN',
      confidence: 0,
      affectedNodeIds: [],
      cascadeLength: 0
    };
  }

  // Find candidate root nodes (inDegree === 0)
  const rootCandidates = dag.nodes.filter(n => (dag.inDegrees.get(n.id) || 0) === 0);

  // Score candidate root causes by downstream impact reach
  let bestRoot = rootCandidates[0] || dag.nodes[0];
  let maxReach = 0;
  let maxAffected = [];

  for (const candidate of rootCandidates) {
    const visited = new Set();
    const queue = [candidate.id];
    visited.add(candidate.id);

    while (queue.length > 0) {
      const curId = queue.shift();
      const outgoing = dag.adjacency.get(curId) || [];
      for (const edge of outgoing) {
        if (!visited.has(edge.to)) {
          visited.add(edge.to);
          queue.push(edge.to);
        }
      }
    }

    if (visited.size > maxReach) {
      maxReach = visited.size;
      bestRoot = candidate;
      maxAffected = Array.from(visited);
    }
  }

  const confidence = dag.nodes.length > 0 
    ? Math.min(1.0, Number((maxReach / dag.nodes.length).toFixed(2)) + 0.2) 
    : 0.5;

  return {
    rootCauseNode: bestRoot,
    initialVector: bestRoot.type || bestRoot.title || 'EXTERNAL_INGRESS',
    confidence,
    affectedNodeIds: maxAffected,
    cascadeLength: maxReach
  };
}

/**
 * Calculate dwell time metrics for an incident DAG
 * @param {Object} dag
 * @returns {Object} Dwell time assessment
 */
export function calculateDwellTime(dag) {
  if (!dag || !dag.nodes || dag.nodes.length === 0) {
    return {
      dwellTimeMs: 0,
      dwellTimeString: '0s',
      initialCompromiseTime: null,
      firstDetectionTime: null,
      containmentTime: null,
      timeToDetectMs: 0,
      timeToRemediateMs: 0
    };
  }

  const sorted = [...dag.nodes].sort((a, b) => a.timestamp - b.timestamp);
  const t0 = sorted[0].timestamp;
  const tEnd = sorted[sorted.length - 1].timestamp;

  // First alert that generated a detection
  const firstDetection = sorted.find(n => n.severity === 'HIGH' || n.severity === 'CRITICAL') || sorted[0];
  const tDetect = firstDetection.timestamp;

  const dwellTimeMs = Math.max(0, tEnd - t0);
  const timeToDetectMs = Math.max(0, tDetect - t0);
  const timeToRemediateMs = Math.max(0, tEnd - tDetect);

  const formatDuration = (ms) => {
    const sec = Math.floor(ms / 1000);
    if (sec < 60) return `${sec}s`;
    const min = Math.floor(sec / 60);
    const remSec = sec % 60;
    if (min < 60) return `${min}m ${remSec}s`;
    const hrs = Math.floor(min / 60);
    const remMin = min % 60;
    return `${hrs}h ${remMin}m`;
  };

  return {
    dwellTimeMs,
    dwellTimeString: formatDuration(dwellTimeMs),
    initialCompromiseTime: new Date(t0).toISOString(),
    firstDetectionTime: new Date(tDetect).toISOString(),
    containmentTime: new Date(tEnd).toISOString(),
    timeToDetectMs,
    timeToDetectString: formatDuration(timeToDetectMs),
    timeToRemediateMs,
    timeToRemediateString: formatDuration(timeToRemediateMs)
  };
}

/**
 * Render ASCII attack timeline graph for terminal displays
 * @param {Object} dag
 * @param {Object} [options={}]
 * @returns {string} Rendered timeline string
 */
export function renderAsciiTimeline(dag, options = {}) {
  if (!dag || !dag.nodes || dag.nodes.length === 0) {
    return 'No events available in attack timeline.';
  }

  const rootAnalysis = identifyRootCause(dag);
  const dwell = calculateDwellTime(dag);
  const lines = [];

  lines.push('╔══════════════════════════════════════════════════════════════════════════════╗');
  lines.push('║             ⚡ VIGILANTE CAUSAL ATTACK TIMELINE & ROOT CAUSE DAG            ║');
  lines.push('╚══════════════════════════════════════════════════════════════════════════════╝');
  lines.push(`Total Events: ${dag.nodes.length}  |  Causal Edges: ${dag.edges.length}  |  Dwell Time: ${dwell.dwellTimeString}`);
  lines.push(`Root Cause: [${rootAnalysis.rootCauseNode?.title}]  |  Confidence: ${(rootAnalysis.confidence * 100).toFixed(0)}%`);
  lines.push('─'.repeat(78));

  dag.nodes.forEach((node, idx) => {
    const isRoot = node.id === rootAnalysis.rootCauseNode?.id;
    const badge = isRoot ? '★ [ROOT CAUSE]' : `  [#${node.index}]`;
    const timeStr = new Date(node.timestamp).toLocaleTimeString();
    const severityMarker = node.severity === 'CRITICAL' ? '🔴' : node.severity === 'HIGH' ? '🟠' : '🟡';

    lines.push(`${badge} ${severityMarker} ${timeStr} | ${node.title} (${node.entity})`);
    if (node.mitreTechnique) {
      lines.push(`     └─ ATT&CK: ${node.mitreTechnique} | Module: ${node.sourceModule}`);
    }
    if (node.command) {
      lines.push(`     └─ Cmd: ${node.command}`);
    }

    // Print outgoing causal edges
    const outgoing = dag.adjacency.get(node.id) || [];
    for (const edge of outgoing) {
      lines.push(`        ├─► [${edge.type}] ➔ ${edge.description}`);
    }

    if (idx < dag.nodes.length - 1) {
      lines.push('        │');
    }
  });

  return lines.join('\n');
}
