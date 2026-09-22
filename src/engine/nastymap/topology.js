/**
 * NastyMap Topology Graph Engine
 * Generates multi-layout graph topologies (Force 2D, Radial, Traceroute Hop Tree, Subnet Clusters).
 */

function getSubnetFromIp(ip) {
  if (!ip || ip.includes(':')) return 'IPv6 / Other';
  const parts = ip.split('.');
  if (parts.length >= 3) {
    return `${parts[0]}.` + `${parts[1]}.` + `${parts[2]}.0/24`;
  }
  return 'Unknown Subnet';
}

function getOsColor(osFamily) {
  const fam = (osFamily || '').toLowerCase();
  if (fam.includes('linux') || fam.includes('ubuntu') || fam.includes('debian')) return '#22c55e'; // Green
  if (fam.includes('windows') || fam.includes('microsoft')) return '#0ea5e9'; // Cyan/Blue
  if (fam.includes('mac') || fam.includes('apple') || fam.includes('ios') || fam.includes('darwin')) return '#a855f7'; // Purple
  if (fam.includes('cisco') || fam.includes('router') || fam.includes('switch')) return '#f59e0b'; // Amber
  if (fam.includes('bsd')) return '#ef4444'; // Red
  if (fam.includes('android')) return '#10b981'; // Emerald
  return '#94a3b8'; // Slate/Gray
}

/**
 * Generate a full topology graph from an Nmap scan.
 * @param {Object} scan Structured NmapRun object
 * @param {Object} [options]
 * @returns {Object} TopologyGraph { nodes: [], links: [], subnets: [] }
 */
export function generateTopology(scan, options = {}) {
  const { width = 1200, height = 800, layout = 'force2d' } = options;
  const nodesMap = new Map();
  const linksMap = new Map();
  const subnetsSet = new Set();

  // 1. Create Scanner Origin Node
  const scannerNodeId = 'scanner-origin';
  const scannerNode = {
    id: scannerNodeId,
    label: 'Nmap Scanner (Local)',
    ip: '127.0.0.1',
    hostname: 'nmap-scanner',
    nodeType: 'scanner',
    status: 'up',
    osFamily: 'Local Host',
    osName: 'Scanner Host',
    deviceType: 'security scanner',
    openPorts: [],
    openPortDetails: [],
    latencyMs: 0,
    hopsAway: 0,
    subnet: '127.0.0.0/8',
    x: width / 2,
    y: height / 2,
    radius: 26,
    color: '#6366f1' // Indigo
  };
  nodesMap.set(scannerNodeId, scannerNode);

  // 2. Iterate through all hosts in scan
  for (const host of scan.hosts || []) {
    const ip = host.ipv4 || host.ipv6 || host.id;
    const subnet = getSubnetFromIp(ip);
    subnetsSet.add(subnet);

    const openPorts = (host.ports || []).filter((p) => p.state === 'open').map((p) => p.portid);
    const openPortDetails = (host.ports || []).filter((p) => p.state === 'open');
    const hopsAway = host.distance || (host.trace?.hops ? host.trace.hops.length : 1);

    const hostNode = {
      id: ip,
      label: host.primaryHostname || ip,
      ip,
      hostname: host.primaryHostname,
      nodeType: host.deviceType === 'router' ? 'router' : 'host',
      status: host.status?.state === 'up' ? 'up' : 'down',
      osFamily: host.osFamily || 'Unknown',
      osName: host.primaryOs || 'Unknown OS',
      deviceType: host.deviceType || 'general purpose',
      openPorts,
      openPortDetails,
      latencyMs: host.latencyMs,
      hopsAway,
      subnet,
      hostRef: host,
      geolocation: host.geolocation,
      x: width / 2,
      y: height / 2,
      radius: Math.max(14, Math.min(24, 14 + openPorts.length)),
      color: getOsColor(host.osFamily)
    };
    nodesMap.set(ip, hostNode);

    // 3. Connect Traceroute Hops or Subnet links
    if (host.trace && host.trace.hops && host.trace.hops.length > 0) {
      let prevHopId = scannerNodeId;
      for (const hop of host.trace.hops) {
        const hopId = hop.ipaddr || `hop-${hop.ttl}`;
        if (!nodesMap.has(hopId)) {
          const hopNode = {
            id: hopId,
            label: hop.host || hop.ipaddr || `Hop ${hop.ttl}`,
            ip: hop.ipaddr,
            hostname: hop.host,
            nodeType: 'hop',
            status: 'up',
            osFamily: 'Router/Gateway',
            osName: 'Intermediate Hop',
            deviceType: 'router',
            openPorts: [],
            openPortDetails: [],
            latencyMs: hop.rtt ? parseFloat(hop.rtt) : undefined,
            hopsAway: hop.ttl,
            subnet: getSubnetFromIp(hop.ipaddr),
            x: width / 2,
            y: height / 2,
            radius: 12,
            color: '#f59e0b' // Amber
          };
          nodesMap.set(hopId, hopNode);
        }

        const linkKey = `${prevHopId}->${hopId}`;
        if (!linksMap.has(linkKey)) {
          linksMap.set(linkKey, {
            id: linkKey,
            source: prevHopId,
            target: hopId,
            type: 'traceroute',
            rtt: hop.rtt ? parseFloat(hop.rtt) : undefined,
            label: hop.rtt ? `${hop.rtt}ms` : undefined
          });
        }
        prevHopId = hopId;
      }

      // Link final hop to target host
      if (prevHopId !== ip) {
        const finalLinkKey = `${prevHopId}->${ip}`;
        if (!linksMap.has(finalLinkKey)) {
          linksMap.set(finalLinkKey, {
            id: finalLinkKey,
            source: prevHopId,
            target: ip,
            type: 'traceroute'
          });
        }
      }
    } else {
      // Default direct link from scanner to host
      const directKey = `${scannerNodeId}->${ip}`;
      linksMap.set(directKey, {
        id: directKey,
        source: scannerNodeId,
        target: ip,
        type: 'subnet',
        label: subnet
      });
    }
  }

  const nodes = Array.from(nodesMap.values());
  const links = Array.from(linksMap.values());

  // 4. Compute Layout Coordinates
  applyLayoutCoordinates(nodes, links, { layout, width, height });

  return {
    nodes,
    links,
    subnets: Array.from(subnetsSet)
  };
}

/**
 * Calculates (x, y) coordinates for nodes according to chosen layout.
 */
function applyLayoutCoordinates(nodes, links, { layout, width, height }) {
  const centerX = width / 2;
  const centerY = height / 2;

  if (layout === 'radial') {
    // Concentric rings by hopsAway
    const scanner = nodes.find((n) => n.id === 'scanner-origin') || nodes[0];
    if (scanner) {
      scanner.x = centerX;
      scanner.y = centerY;
    }

    const otherNodes = nodes.filter((n) => n.id !== scanner?.id);
    const hopGroups = new Map();

    for (const node of otherNodes) {
      const hop = node.hopsAway || 1;
      if (!hopGroups.has(hop)) hopGroups.set(hop, []);
      hopGroups.get(hop).push(node);
    }

    const maxRadius = Math.min(width, height) * 0.42;
    const maxHop = Math.max(...Array.from(hopGroups.keys()), 1);

    for (const [hop, group] of hopGroups.entries()) {
      const ringRadius = (hop / maxHop) * maxRadius;
      const angleStep = (2 * Math.PI) / group.length;

      group.forEach((node, idx) => {
        const angle = idx * angleStep;
        node.x = centerX + ringRadius * Math.cos(angle);
        node.y = centerY + ringRadius * Math.sin(angle);
      });
    }
  } else if (layout === 'tree') {
    // Hierarchical top-down tree layout
    const levels = new Map();
    for (const node of nodes) {
      const level = node.hopsAway || 0;
      if (!levels.has(level)) levels.set(level, []);
      levels.get(level).push(node);
    }

    const sortedLevels = Array.from(levels.keys()).sort((a, b) => a - b);
    const levelHeight = (height - 120) / Math.max(sortedLevels.length - 1, 1);

    sortedLevels.forEach((lvl, rowIdx) => {
      const rowNodes = levels.get(lvl) || [];
      const colWidth = (width - 160) / (rowNodes.length + 1);

      rowNodes.forEach((node, colIdx) => {
        node.x = 80 + (colIdx + 1) * colWidth;
        node.y = 60 + rowIdx * levelHeight;
      });
    });
  } else {
    // Default 2D Radial / Force-directed layout
    const scanner = nodes.find((n) => n.id === 'scanner-origin') || nodes[0];
    if (scanner) {
      scanner.x = centerX;
      scanner.y = centerY;
    }

    const nonScanner = nodes.filter((n) => n.id !== scanner?.id);
    const total = nonScanner.length;
    const radius = Math.min(width, height) * 0.38;

    nonScanner.forEach((node, idx) => {
      const angle = (idx / (total || 1)) * 2 * Math.PI;
      // Stagger slightly by hop count for organic spread
      const hopOffset = ((node.hopsAway || 1) % 3) * 20;
      node.x = centerX + (radius + hopOffset) * Math.cos(angle);
      node.y = centerY + (radius + hopOffset) * Math.sin(angle);
    });
  }
}
