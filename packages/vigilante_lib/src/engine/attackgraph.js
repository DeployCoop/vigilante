/**
 * VIGILANTE Interactive Composite Attack Graph & Blast-Radius Engine
 * Merges Network topology, Kubernetes RBAC/workloads, and Identity access graphs
 * to model multi-stage adversary pivot paths and calculate blast radius.
 */

import { logger } from '../utils/logger.js';

const TIER_WEIGHTS = {
  CrownJewel: 40,
  Restricted: 25,
  Infrastructure: 20,
  Edge: 10,
  Untrusted: 0
};

/**
 * Standard simulated realistic enterprise attack graph
 */
const DEFAULT_ATTACK_GRAPH = {
  nodes: [
    {
      id: 'ext-attacker',
      label: 'Internet Attacker / Adversary',
      type: 'External',
      tier: 'Untrusted',
      details: 'Unauthenticated external IP: 198.51.100.23'
    },
    {
      id: 'ingress-nginx',
      label: 'nginx-ingress-controller',
      type: 'Workload',
      tier: 'Edge',
      namespace: 'ingress-nginx',
      details: 'Public HTTP/S ingress; exposed on 80/443'
    },
    {
      id: 'web-frontend',
      label: 'frontend-web-app',
      type: 'Workload',
      tier: 'Edge',
      namespace: 'production',
      serviceAccount: 'frontend-sa',
      details: 'Node.js SSR frontend with CVE-2024-21626 container escape'
    },
    {
      id: 'api-gateway',
      label: 'api-gateway-service',
      type: 'Workload',
      tier: 'Restricted',
      namespace: 'production',
      serviceAccount: 'gateway-sa',
      details: 'Spring Boot REST API with internal mTLS access'
    },
    {
      id: 'payment-db',
      label: 'production-postgres-db',
      type: 'Datastore',
      tier: 'CrownJewel',
      namespace: 'database',
      details: 'Stores PCI-DSS customer credit cards & tokens'
    },
    {
      id: 'node-worker-01',
      label: 'k8s-node-worker-01',
      type: 'Host',
      tier: 'Infrastructure',
      details: 'Linux 6.8 host; mounts /etc/kubernetes/kubelet.conf'
    },
    {
      id: 'sa-cluster-admin',
      label: 'cluster-admin-serviceaccount',
      type: 'Identity',
      tier: 'CrownJewel',
      namespace: 'kube-system',
      details: 'Full RBAC wildcard (*:*) cluster control'
    },
    {
      id: 'corp-dc-01',
      label: 'active-directory-dc01',
      type: 'IdentityStore',
      tier: 'CrownJewel',
      details: 'Windows Server 2022 AD Domain Controller'
    }
  ],
  edges: [
    {
      from: 'ext-attacker',
      to: 'ingress-nginx',
      type: 'EXPLOIT_HTTP',
      label: 'Exploit Public Ingress (Port 443)',
      cost: 1
    },
    {
      from: 'ingress-nginx',
      to: 'web-frontend',
      type: 'ROUTED_TRAFFIC',
      label: 'Forward HTTP Payload',
      cost: 1
    },
    {
      from: 'web-frontend',
      to: 'api-gateway',
      type: 'PIVOT_NETWORK',
      label: 'Egress Call Internal mTLS (Port 8443)',
      cost: 2
    },
    {
      from: 'web-frontend',
      to: 'node-worker-01',
      type: 'CONTAINER_ESCAPE',
      label: 'HostPath Mount Escape (CVE-2024-21626)',
      cost: 3
    },
    {
      from: 'api-gateway',
      to: 'payment-db',
      type: 'DATA_ACCESS',
      label: 'Query PCI Database (Port 5432)',
      cost: 1
    },
    {
      from: 'api-gateway',
      to: 'sa-cluster-admin',
      type: 'RBAC_IMPERSONATE',
      label: 'Overprivileged Token Impersonation',
      cost: 2
    },
    {
      from: 'node-worker-01',
      to: 'sa-cluster-admin',
      type: 'KUBELET_STEAL_TOKEN',
      label: 'Read Kubelet Client Credentials',
      cost: 1
    },
    {
      from: 'node-worker-01',
      to: 'corp-dc-01',
      type: 'KERBEROS_TGS',
      label: 'Kerberoasting / TGS Request',
      cost: 3
    }
  ]
};

/**
 * Build composite attack graph from multiple telemetry feeds
 * @param {Array<Object>} nmapHosts 
 * @param {Array<Object>} k8sWorkloads 
 * @param {Array<Object>} bloodhoundPaths 
 * @param {Object} options 
 * @returns {Object} Graph { nodes, edges, adjacency, stats }
 */
export function buildCompositeAttackGraph(nmapHosts = [], k8sWorkloads = [], bloodhoundPaths = [], options = {}) {
  const nodesMap = new Map();
  const edges = [];

  // If no external data passed, use default enterprise composite graph
  if ((!nmapHosts || nmapHosts.length === 0) &&
      (!k8sWorkloads || k8sWorkloads.length === 0) &&
      (!bloodhoundPaths || bloodhoundPaths.length === 0)) {
    for (const n of DEFAULT_ATTACK_GRAPH.nodes) {
      nodesMap.set(n.id, { ...n });
    }
    for (const e of DEFAULT_ATTACK_GRAPH.edges) {
      edges.push({ ...e });
    }
  } else {
    // 1. Process Nmap Hosts
    for (const host of nmapHosts) {
      const hostId = `host-${host.ip || host.hostname}`;
      nodesMap.set(hostId, {
        id: hostId,
        label: host.hostname || host.ip,
        type: 'Host',
        tier: host.isCrownJewel ? 'CrownJewel' : 'Infrastructure',
        details: `IP: ${host.ip} (${host.openPorts?.length || 0} open ports)`
      });
    }

    // 2. Process Kubernetes Workloads
    for (const wk of k8sWorkloads) {
      const podId = `pod-${wk.name || wk.pod}`;
      nodesMap.set(podId, {
        id: podId,
        label: wk.name || wk.pod,
        type: 'Workload',
        tier: wk.tier || 'Edge',
        namespace: wk.namespace || 'default',
        serviceAccount: wk.serviceAccount || 'default',
        details: `Pod in namespace '${wk.namespace}'`
      });
    }

    // 3. Process BloodHound / RBAC paths
    for (const bp of bloodhoundPaths) {
      if (bp.source && !nodesMap.has(bp.source.id)) {
        nodesMap.set(bp.source.id, {
          id: bp.source.id,
          label: bp.source.name || bp.source.id,
          type: bp.source.type || 'Identity',
          tier: bp.source.isCrownJewel ? 'CrownJewel' : 'Restricted',
          details: bp.source.details || ''
        });
      }
      if (bp.target && !nodesMap.has(bp.target.id)) {
        nodesMap.set(bp.target.id, {
          id: bp.target.id,
          label: bp.target.name || bp.target.id,
          type: bp.target.type || 'Identity',
          tier: bp.target.isCrownJewel ? 'CrownJewel' : 'Restricted',
          details: bp.target.details || ''
        });
      }
      if (bp.source && bp.target) {
        edges.push({
          from: bp.source.id,
          to: bp.target.id,
          type: bp.relationship || 'ACCESS_RIGHT',
          label: bp.relationship || 'Privilege Link',
          cost: bp.cost || 1
        });
      }
    }
  }

  // Construct adjacency list
  const adjacency = new Map();
  for (const [nodeId] of nodesMap) {
    adjacency.set(nodeId, []);
  }
  for (const edge of edges) {
    if (adjacency.has(edge.from)) {
      adjacency.get(edge.from).push(edge);
    }
  }

  const nodes = Array.from(nodesMap.values());
  const stats = {
    totalNodes: nodes.length,
    totalEdges: edges.length,
    crownJewels: nodes.filter(n => n.tier === 'CrownJewel').length,
    workloads: nodes.filter(n => n.type === 'Workload').length,
    identities: nodes.filter(n => n.type === 'Identity' || n.type === 'IdentityStore').length
  };

  return {
    nodes,
    edges,
    adjacency,
    stats
  };
}

/**
 * Shortest attack path discovery between two nodes using Breadth-First Search (BFS)
 * @param {string} fromNodeId 
 * @param {string} toNodeId 
 * @param {Object} graph 
 * @returns {Object} { pathFound, hops, nodePath, edgePath }
 */
export function findShortestAttackPath(fromNodeId, toNodeId, graph) {
  if (fromNodeId === toNodeId) {
    return { pathFound: true, hops: 0, nodePath: [fromNodeId], edgePath: [] };
  }

  const queue = [[fromNodeId]];
  const visited = new Set([fromNodeId]);
  const edgeHistory = new Map(); // childNodeId -> edge

  while (queue.length > 0) {
    const currentPath = queue.shift();
    const currentNodeId = currentPath[currentPath.length - 1];

    const outgoingEdges = graph.adjacency.get(currentNodeId) || [];
    for (const edge of outgoingEdges) {
      const nextId = edge.to;
      if (!visited.has(nextId)) {
        visited.add(nextId);
        edgeHistory.set(nextId, edge);
        const newPath = [...currentPath, nextId];

        if (nextId === toNodeId) {
          // Reconstruct edge sequence
          const edgePath = [];
          for (let i = 1; i < newPath.length; i++) {
            edgePath.push(edgeHistory.get(newPath[i]));
          }
          return {
            pathFound: true,
            hops: newPath.length - 1,
            nodePath: newPath,
            edgePath
          };
        }

        queue.push(newPath);
      }
    }
  }

  return {
    pathFound: false,
    hops: -1,
    nodePath: [],
    edgePath: []
  };
}

/**
 * Calculate blast radius from a compromised origin node
 * @param {string} startNodeId 
 * @param {Object} graph 
 * @param {Object} options 
 * @returns {Object} Blast radius impact assessment
 */
export function calculateBlastRadius(startNodeId, graph, options = {}) {
  const startNode = graph.nodes.find(n => n.id === startNodeId);
  if (!startNode) {
    throw new Error(`Node '${startNodeId}' not found in attack graph.`);
  }

  const reachableNodes = [];
  const visited = new Set([startNodeId]);
  const queue = [{ id: startNodeId, depth: 0 }];

  while (queue.length > 0) {
    const { id, depth } = queue.shift();
    const edges = graph.adjacency.get(id) || [];

    for (const edge of edges) {
      if (!visited.has(edge.to)) {
        visited.add(edge.to);
        const targetNode = graph.nodes.find(n => n.id === edge.to);
        if (targetNode) {
          reachableNodes.push({
            ...targetNode,
            depth: depth + 1,
            viaEdge: edge
          });
          queue.push({ id: edge.to, depth: depth + 1 });
        }
      }
    }
  }

  // Calculate composite impact score based on reachable asset tiers
  let totalScore = 0;
  for (const node of reachableNodes) {
    const weight = TIER_WEIGHTS[node.tier] || 10;
    // Closer nodes carry slightly more immediate blast risk
    const depthDiscount = Math.max(0.5, 1 - (node.depth * 0.1));
    totalScore += weight * depthDiscount;
  }
  const impactScore = Math.min(100, Math.round(totalScore));

  const riskLevel = impactScore >= 70 ? 'CRITICAL' : impactScore >= 40 ? 'HIGH' : impactScore >= 20 ? 'MEDIUM' : 'LOW';

  // Filter paths to Crown Jewels
  const crownJewelNodes = reachableNodes.filter(n => n.tier === 'CrownJewel');
  const criticalPaths = crownJewelNodes.map(target => {
    return findShortestAttackPath(startNodeId, target.id, graph);
  });

  return {
    startNodeId,
    startNode,
    reachableCount: reachableNodes.length,
    reachableNodes,
    impactScore,
    riskLevel,
    compromisedBreakdown: {
      workloads: reachableNodes.filter(n => n.type === 'Workload').map(n => n.id),
      datastores: reachableNodes.filter(n => n.type === 'Datastore').map(n => n.id),
      identities: reachableNodes.filter(n => n.type === 'Identity' || n.type === 'IdentityStore').map(n => n.id),
      hosts: reachableNodes.filter(n => n.type === 'Host').map(n => n.id)
    },
    criticalPaths
  };
}

/**
 * Render ANSI/ASCII Attack Graph view for terminal
 * @param {Object} graph 
 * @param {Object} options - { highlightPath: Array<string> }
 * @returns {string} Formatted terminal ASCII graph
 */
export function renderAsciiAttackGraph(graph, options = {}) {
  const ANSI = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    red: '\x1b[38;2;255;50;50m',
    yellow: '\x1b[38;2;255;200;0m',
    green: '\x1b[38;2;0;255;120m',
    cyan: '\x1b[38;2;0;220;255m',
    magenta: '\x1b[38;2;255;100;255m',
    dim: '\x1b[2m'
  };

  const highlightSet = new Set(options.highlightPath || []);

  const getNodeGlyph = (node) => {
    switch (node.type) {
      case 'External': return '🌐 [EXT]';
      case 'Workload': return '📦 [POD]';
      case 'Datastore': return '💾 [DB] ';
      case 'Host': return '🖥️  [HOST]';
      case 'Identity': return '🔑 [SA] ';
      case 'IdentityStore': return '👑 [DC] ';
      default: return '⚪ [NODE]';
    }
  };

  const getTierColor = (tier) => {
    switch (tier) {
      case 'CrownJewel': return ANSI.red;
      case 'Restricted': return ANSI.yellow;
      case 'Infrastructure': return ANSI.cyan;
      case 'Edge': return ANSI.green;
      default: return ANSI.dim;
    }
  };

  const lines = [];
  lines.push(`${ANSI.bold}${ANSI.cyan}═══ VIGILANTE INTERACTIVE COMPOSITE ATTACK GRAPH ═══${ANSI.reset}`);
  lines.push(`${ANSI.dim}Nodes: ${graph.nodes.length} | Edges: ${graph.edges.length} | Crown Jewels: ${graph.stats?.crownJewels || 0}${ANSI.reset}\n`);

  for (const node of graph.nodes) {
    const isHighlighted = highlightSet.has(node.id);
    const color = isHighlighted ? ANSI.magenta : getTierColor(node.tier);
    const borderPrefix = isHighlighted ? `${ANSI.bold}${ANSI.magenta}▶▶▶ ` : '    ';
    
    lines.push(`${borderPrefix}${getNodeGlyph(node)} ${color}${ANSI.bold}${node.label}${ANSI.reset} ${ANSI.dim}(${node.id} | Tier: ${node.tier})${ANSI.reset}`);
    if (node.details) {
      lines.push(`        ${ANSI.dim}↳ ${node.details}${ANSI.reset}`);
    }

    // List outgoing edges
    const outgoing = graph.adjacency.get(node.id) || [];
    for (const edge of outgoing) {
      const isEdgeHighlighted = isHighlighted && highlightSet.has(edge.to);
      const edgeColor = isEdgeHighlighted ? `${ANSI.bold}${ANSI.magenta}` : ANSI.dim;
      const arrow = isEdgeHighlighted ? '══════▶ ' : '──────▶ ';
      lines.push(`        ${edgeColor}${arrow}${edge.label} [${edge.to}]${ANSI.reset}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}
