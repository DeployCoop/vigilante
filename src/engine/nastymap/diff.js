/**
 * NastyMap Scan Diffing Engine
 * Compares baseline and target Nmap scans for breach analysis and change detection.
 */

function compareHostPorts(portsA = [], portsB = []) {
  const mapA = new Map();
  const mapB = new Map();

  for (const p of portsA) mapA.set(p.portid, p);
  for (const p of portsB) mapB.set(p.portid, p);

  const allPortIds = Array.from(new Set([...mapA.keys(), ...mapB.keys()])).sort((a, b) => a - b);
  const diffs = [];

  for (const pid of allPortIds) {
    const pA = mapA.get(pid);
    const pB = mapB.get(pid);

    if (!pA && pB) {
      // Port was added in scan B
      diffs.push({
        portid: pid,
        protocol: pB.protocol,
        changeType: 'added',
        newPort: pB
      });
    } else if (pA && !pB) {
      // Port was removed in scan B
      diffs.push({
        portid: pid,
        protocol: pA.protocol,
        changeType: 'removed',
        oldPort: pA
      });
    } else if (pA && pB) {
      // Check if state, service, or version changed
      const stateChanged = pA.state !== pB.state;
      const serviceChanged = (pA.service?.name || '') !== (pB.service?.name || '');
      const versionChanged = (pA.service?.version || '') !== (pB.service?.version || '');

      if (stateChanged || serviceChanged || versionChanged) {
        diffs.push({
          portid: pid,
          protocol: pB.protocol,
          changeType: 'modified',
          oldPort: pA,
          newPort: pB,
          details: { stateChanged, serviceChanged, versionChanged }
        });
      } else {
        diffs.push({
          portid: pid,
          protocol: pB.protocol,
          changeType: 'unchanged',
          oldPort: pA,
          newPort: pB
        });
      }
    }
  }

  return diffs;
}

/**
 * Compare two Nmap scans and produce a structured diff with summary statistics.
 * @param {Object} scanA Baseline scan
 * @param {Object} scanB Target / Current scan
 * @returns {Object} NmapScanDiff
 */
export function compareNmapScans(scanA, scanB) {
  if (!scanA || !scanB) {
    throw new Error('Both baseline scan (scanA) and target scan (scanB) are required for comparison.');
  }

  const mapA = new Map();
  const mapB = new Map();

  for (const h of scanA.hosts || []) {
    const key = h.ipv4 || h.ipv6 || h.id;
    mapA.set(key, h);
  }

  for (const h of scanB.hosts || []) {
    const key = h.ipv4 || h.ipv6 || h.id;
    mapB.set(key, h);
  }

  const allHostKeys = Array.from(new Set([...mapA.keys(), ...mapB.keys()]));

  const addedHosts = [];
  const removedHosts = [];
  const modifiedHosts = [];
  const unchangedHosts = [];

  let portsAddedCount = 0;
  let portsRemovedCount = 0;
  let portsModifiedCount = 0;

  for (const key of allHostKeys) {
    const hA = mapA.get(key);
    const hB = mapB.get(key);

    if (!hA && hB) {
      // Rogue / Newly discovered host
      const portDiffs = (hB.ports || []).map((p) => ({
        portid: p.portid,
        protocol: p.protocol,
        changeType: 'added',
        newPort: p
      }));
      portsAddedCount += hB.ports?.length || 0;

      addedHosts.push({
        ip: key,
        hostname: hB.primaryHostname,
        changeType: 'added',
        newHost: hB,
        portDiffs
      });
    } else if (hA && !hB) {
      // Decommissioned / Offline host
      const portDiffs = (hA.ports || []).map((p) => ({
        portid: p.portid,
        protocol: p.protocol,
        changeType: 'removed',
        oldPort: p
      }));
      portsRemovedCount += hA.ports?.length || 0;

      removedHosts.push({
        ip: key,
        hostname: hA.primaryHostname,
        changeType: 'removed',
        oldHost: hA,
        portDiffs
      });
    } else if (hA && hB) {
      // Host in both scans - compare ports and state
      const portDiffs = compareHostPorts(hA.ports, hB.ports);
      const hostAddedPorts = portDiffs.filter((p) => p.changeType === 'added').length;
      const hostRemovedPorts = portDiffs.filter((p) => p.changeType === 'removed').length;
      const hostModifiedPorts = portDiffs.filter((p) => p.changeType === 'modified').length;

      portsAddedCount += hostAddedPorts;
      portsRemovedCount += hostRemovedPorts;
      portsModifiedCount += hostModifiedPorts;

      const stateChanged = (hA.status?.state || (hA.isUp ? 'up' : 'down')) !== (hB.status?.state || (hB.isUp ? 'up' : 'down'));
      const osChanged = Boolean(hA.primaryOs && hB.primaryOs && hA.primaryOs !== hB.primaryOs);

      if (hostAddedPorts > 0 || hostRemovedPorts > 0 || hostModifiedPorts > 0 || stateChanged || osChanged) {
        modifiedHosts.push({
          ip: key,
          hostname: hB.primaryHostname || hA.primaryHostname,
          changeType: 'modified',
          oldHost: hA,
          newHost: hB,
          portDiffs,
          details: { stateChanged, osChanged }
        });
      } else {
        unchangedHosts.push({
          ip: key,
          hostname: hB.primaryHostname,
          changeType: 'unchanged',
          oldHost: hA,
          newHost: hB,
          portDiffs
        });
      }
    }
  }

  return {
    scanA: {
      filename: scanA.filename,
      timestamp: scanA.startstr || String(scanA.start),
      hostsCount: scanA.hosts?.length || 0
    },
    scanB: {
      filename: scanB.filename,
      timestamp: scanB.startstr || String(scanB.start),
      hostsCount: scanB.hosts?.length || 0
    },
    summary: {
      hostsAdded: addedHosts.length,
      hostsRemoved: removedHosts.length,
      hostsModified: modifiedHosts.length,
      hostsUnchanged: unchangedHosts.length,
      portsAdded: portsAddedCount,
      portsRemoved: portsRemovedCount,
      portsModified: portsModifiedCount
    },
    addedHosts,
    removedHosts,
    modifiedHosts,
    unchangedHosts
  };
}
