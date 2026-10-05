import { execa } from 'execa';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilantePcapDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

/**
 * Parse Suricata eve.json output (NDJSON string or file path)
 * @param {string} contentOrPath - Path to eve.json or raw string content
 * @returns {Object} Parsed Suricata events and statistics
 */
export function parseSuricataEve(contentOrPath) {
  let content = contentOrPath;
  if (typeof contentOrPath === 'string' && fsSync.existsSync(contentOrPath)) {
    try {
      content = fsSync.readFileSync(contentOrPath, 'utf8');
    } catch (err) {
      logger.error('TRAFFIC', `Failed to read eve.json at ${contentOrPath}: ${err.message}`);
      return { totalEvents: 0, alerts: [], statistics: {} };
    }
  }

  if (!content || typeof content !== 'string') {
    return { totalEvents: 0, alerts: [], statistics: {} };
  }

  const lines = content.split('\n').filter(l => l.trim().length > 0);
  const alerts = [];
  const dnsEvents = [];
  const httpEvents = [];
  const tlsEvents = [];
  const flowEvents = [];
  const anomalyEvents = [];

  const categoryCounts = {};
  const signatureCounts = {};
  const srcIpCounts = {};
  const destIpCounts = {};
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };

  for (const line of lines) {
    try {
      const ev = JSON.parse(line);
      const evType = ev.event_type || 'unknown';

      if (evType === 'alert') {
        const alertData = ev.alert || {};
        // Suricata severities: 1 = High/Critical, 2 = Medium/High, 3 = Low/Medium, 4 = Info
        let normSev = 'medium';
        if (alertData.severity === 1) normSev = 'critical';
        else if (alertData.severity === 2) normSev = 'high';
        else if (alertData.severity === 3) normSev = 'medium';
        else if (alertData.severity >= 4) normSev = 'low';

        severityCounts[normSev] = (severityCounts[normSev] || 0) + 1;

        const cat = alertData.category || 'Uncategorized';
        categoryCounts[cat] = (categoryCounts[cat] || 0) + 1;

        const sig = alertData.signature || 'Generic Detection';
        signatureCounts[sig] = (signatureCounts[sig] || 0) + 1;

        if (ev.src_ip) srcIpCounts[ev.src_ip] = (srcIpCounts[ev.src_ip] || 0) + 1;
        if (ev.dest_ip) destIpCounts[ev.dest_ip] = (destIpCounts[ev.dest_ip] || 0) + 1;

        alerts.push({
          timestamp: ev.timestamp,
          eventType: 'alert',
          srcIp: ev.src_ip,
          srcPort: ev.src_port,
          destIp: ev.dest_ip,
          destPort: ev.dest_port,
          proto: ev.proto,
          severity: normSev,
          rawSeverity: alertData.severity,
          signature: sig,
          signatureId: alertData.signature_id,
          category: cat,
          action: alertData.action,
          metadata: alertData.metadata || {}
        });
      } else if (evType === 'dns') {
        dnsEvents.push({
          timestamp: ev.timestamp,
          srcIp: ev.src_ip,
          destIp: ev.dest_ip,
          type: ev.dns?.type,
          rrname: ev.dns?.rrname,
          rrtype: ev.dns?.rrtype,
          rcode: ev.dns?.rcode
        });
      } else if (evType === 'http') {
        httpEvents.push({
          timestamp: ev.timestamp,
          srcIp: ev.src_ip,
          destIp: ev.dest_ip,
          hostname: ev.http?.hostname,
          url: ev.http?.url,
          httpMethod: ev.http?.http_method,
          status: ev.http?.status,
          userAgent: ev.http?.http_user_agent
        });
      } else if (evType === 'tls') {
        tlsEvents.push({
          timestamp: ev.timestamp,
          srcIp: ev.src_ip,
          destIp: ev.dest_ip,
          subject: ev.tls?.subject,
          issuerdn: ev.tls?.issuerdn,
          sni: ev.tls?.sni,
          version: ev.tls?.version
        });
      } else if (evType === 'flow') {
        flowEvents.push({
          timestamp: ev.timestamp,
          srcIp: ev.src_ip,
          destIp: ev.dest_ip,
          proto: ev.proto,
          bytesToServer: ev.flow?.bytes_toserver,
          bytesToClient: ev.flow?.bytes_toclient
        });
      } else if (evType === 'anomaly') {
        anomalyEvents.push({
          timestamp: ev.timestamp,
          srcIp: ev.src_ip,
          destIp: ev.dest_ip,
          anomaly: ev.anomaly
        });
      }
    } catch {
      // Skip malformed NDJSON line
    }
  }

  return {
    totalEvents: lines.length,
    alerts,
    dnsEvents: dnsEvents.slice(0, 100),
    httpEvents: httpEvents.slice(0, 100),
    tlsEvents: tlsEvents.slice(0, 100),
    flowEvents: flowEvents.slice(0, 100),
    anomalyEvents,
    statistics: {
      alertCount: alerts.length,
      severityCounts,
      topCategories: Object.entries(categoryCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([cat, count]) => ({ category: cat, count })),
      topSignatures: Object.entries(signatureCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([sig, count]) => ({ signature: sig, count })),
      topSources: Object.entries(srcIpCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count })),
      topDestinations: Object.entries(destIpCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }))
    }
  };
}

/**
 * Parse Zeek conn.log (TSV or JSON format)
 * @param {string} contentOrPath - Path to conn.log or raw string content
 * @returns {Object} Parsed Zeek connection records and network statistics
 */
export function parseZeekConnLogs(contentOrPath) {
  let content = contentOrPath;
  if (typeof contentOrPath === 'string' && fsSync.existsSync(contentOrPath)) {
    try {
      content = fsSync.readFileSync(contentOrPath, 'utf8');
    } catch (err) {
      logger.error('TRAFFIC', `Failed to read Zeek conn.log at ${contentOrPath}: ${err.message}`);
      return { totalConnections: 0, connections: [], statistics: {} };
    }
  }

  if (!content || typeof content !== 'string') {
    return { totalConnections: 0, connections: [], statistics: {} };
  }

  const lines = content.split('\n').filter(l => l.trim().length > 0);
  const connections = [];
  const serviceCounts = {};
  const origIpCounts = {};
  const respIpCounts = {};
  let totalBytes = 0;
  const suspiciousConns = [];

  // Check if JSON format
  if (lines.length > 0 && lines[0].trim().startsWith('{')) {
    for (const line of lines) {
      try {
        const item = JSON.parse(line);
        const srcIp = item['id.orig_h'] || item.orig_h || item.src_ip;
        const srcPort = item['id.orig_p'] || item.orig_p || item.src_port;
        const destIp = item['id.resp_h'] || item.resp_h || item.dest_ip;
        const destPort = item['id.resp_p'] || item.resp_p || item.dest_port;
        const proto = item.proto || 'tcp';
        const service = item.service || '-';
        const connState = item.conn_state || '-';
        const duration = parseFloat(item.duration) || 0;
        const origBytes = parseInt(item.orig_bytes, 10) || 0;
        const respBytes = parseInt(item.resp_bytes, 10) || 0;

        if (service !== '-') serviceCounts[service] = (serviceCounts[service] || 0) + 1;
        if (srcIp) origIpCounts[srcIp] = (origIpCounts[srcIp] || 0) + 1;
        if (destIp) respIpCounts[destIp] = (respIpCounts[destIp] || 0) + 1;
        totalBytes += (origBytes + respBytes);

        const connObj = {
          timestamp: item.ts,
          uid: item.uid,
          srcIp,
          srcPort,
          destIp,
          destPort,
          proto,
          service,
          duration,
          origBytes,
          respBytes,
          connState,
          history: item.history || ''
        };
        connections.push(connObj);

        // Flag suspicious states (e.g. S0: syn with no reply, REJ: rejected, scanning)
        if (['S0', 'REJ', 'RSTO', 'RSTR'].includes(connState) || (destPort < 1024 && !['80', '443', '53', '22'].includes(String(destPort)))) {
          suspiciousConns.push(connObj);
        }
      } catch {
        // Skip
      }
    }
  } else {
    // Standard Zeek TSV format
    let fields = [];
    for (const line of lines) {
      if (line.startsWith('#fields')) {
        fields = line.substring(7).trim().split(/\s+/);
        continue;
      }
      if (line.startsWith('#')) {
        continue;
      }

      const values = line.split(/\s+/);
      if (fields.length > 0 && values.length >= fields.length) {
        const row = {};
        for (let i = 0; i < fields.length; i++) {
          row[fields[i]] = values[i];
        }

        const srcIp = row['id.orig_h'];
        const srcPort = parseInt(row['id.orig_p'], 10);
        const destIp = row['id.resp_h'];
        const destPort = parseInt(row['id.resp_p'], 10);
        const proto = row.proto || 'tcp';
        const service = row.service === '-' ? null : row.service;
        const connState = row.conn_state || '-';
        const duration = parseFloat(row.duration) || 0;
        const origBytes = parseInt(row.orig_bytes, 10) || 0;
        const respBytes = parseInt(row.resp_bytes, 10) || 0;

        if (service) serviceCounts[service] = (serviceCounts[service] || 0) + 1;
        if (srcIp) origIpCounts[srcIp] = (origIpCounts[srcIp] || 0) + 1;
        if (destIp) respIpCounts[destIp] = (respIpCounts[destIp] || 0) + 1;
        totalBytes += (origBytes + respBytes);

        const connObj = {
          timestamp: row.ts,
          uid: row.uid,
          srcIp,
          srcPort,
          destIp,
          destPort,
          proto,
          service: service || 'unknown',
          duration,
          origBytes,
          respBytes,
          connState,
          history: row.history || ''
        };
        connections.push(connObj);

        if (['S0', 'REJ', 'RSTO'].includes(connState) || (destPort && destPort === 4444)) {
          suspiciousConns.push(connObj);
        }
      }
    }
  }

  return {
    totalConnections: connections.length,
    connections: connections.slice(0, 500),
    suspiciousConnections: suspiciousConns.slice(0, 100),
    statistics: {
      totalBytes,
      uniqueServices: Object.keys(serviceCounts).length,
      topServices: Object.entries(serviceCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([svc, count]) => ({ service: svc, count })),
      topSources: Object.entries(origIpCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count })),
      topDestinations: Object.entries(respIpCounts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([ip, count]) => ({ ip, count }))
    }
  };
}

/**
 * Summarize and correlate Suricata Eve alerts and Zeek connections
 * @param {Object} options
 * @param {Object} [options.suricataResult]
 * @param {Object} [options.zeekResult]
 * @returns {Object} Composite network threat intelligence summary
 */
export function summarizeTrafficAlerts({ suricataResult, zeekResult } = {}) {
  const alerts = suricataResult?.alerts || [];
  const conns = zeekResult?.connections || [];
  const suspiciousConns = zeekResult?.suspiciousConnections || [];

  const threatScores = [];
  if (suricataResult?.statistics?.severityCounts?.critical > 0) threatScores.push(95);
  else if (suricataResult?.statistics?.severityCounts?.high > 0) threatScores.push(75);
  else if (suricataResult?.statistics?.severityCounts?.medium > 0) threatScores.push(45);
  else if (alerts.length > 0) threatScores.push(20);

  if (suspiciousConns.length > 10) threatScores.push(60);
  else if (suspiciousConns.length > 0) threatScores.push(30);

  const compositeScore = threatScores.length > 0
    ? Math.max(...threatScores)
    : 0;

  let riskTier = 'CLEAN';
  if (compositeScore >= 80) riskTier = 'CRITICAL';
  else if (compositeScore >= 60) riskTier = 'HIGH';
  else if (compositeScore >= 35) riskTier = 'MEDIUM';
  else if (compositeScore > 0) riskTier = 'LOW';

  return {
    score: compositeScore,
    riskTier,
    suricata: {
      alertCount: alerts.length,
      severityCounts: suricataResult?.statistics?.severityCounts || {},
      topSignatures: suricataResult?.statistics?.topSignatures || []
    },
    zeek: {
      connectionCount: conns.length,
      suspiciousCount: suspiciousConns.length,
      totalBytes: zeekResult?.statistics?.totalBytes || 0,
      topServices: zeekResult?.statistics?.topServices || []
    },
    analyzedAt: new Date().toISOString()
  };
}

/**
 * Replay a PCAP file by dropping it into the Vigilante PCAP directory
 * and dispatching to cluster pod spoolers if available
 * @param {string} pcapFilePath - Path to local .pcap or .pcapng file
 * @param {Object} [options]
 * @param {string} [options.namespace] - Namespace where suricata/zeek runs (default: 'vigilante')
 * @param {boolean} [options.copyToPod=true] - Attempt kubectl cp to pod spooler
 * @returns {Promise<Object>} Replay status and analysis results
 */
export function replayPcap(pcapFilePath, options = {}) {
  return (async () => {
    await ensureVigilanteConfig();
    const pcapDir = getVigilantePcapDir();

    if (!pcapFilePath || !fsSync.existsSync(pcapFilePath)) {
      throw new Error(`PCAP file not found at: ${pcapFilePath}`);
    }

    const fileName = path.basename(pcapFilePath);
    const destPcap = path.join(pcapDir, fileName);

    // Copy to vigilante dropzone
    if (pcapFilePath !== destPcap) {
      await fs.copyFile(pcapFilePath, destPcap);
      logger.info('TRAFFIC', `Copied PCAP to local dropzone: ${destPcap}`);
    }

    const stats = await fs.stat(destPcap);
    const result = {
      id: `pcap-${Date.now()}`,
      fileName,
      filePath: destPcap,
      sizeBytes: stats.size,
      copiedToPods: false,
      timestamp: new Date().toISOString(),
      status: 'staged'
    };

    // If kubectl is accessible and cluster is active, attempt to copy to running suricata/zeek pod
    const namespace = options.namespace || 'vigilante';
    if (options.copyToPod !== false) {
      try {
        const { stdout } = await execa('kubectl', [
          'get', 'pods', '-n', namespace,
          '-l', 'app.kubernetes.io/name in (suricata,zeek)',
          '-o', 'jsonpath={.items[*].metadata.name}'
        ], { timeout: 4000 });

        const pods = stdout.trim().split(/\s+/).filter(Boolean);
        if (pods.length > 0) {
          for (const pod of pods) {
            try {
              await execa('kubectl', [
                'cp', destPcap,
                `${namespace}/${pod}:/var/log/vigilante/pcap-spool/${fileName}`
              ], { timeout: 6000 });
              logger.info('TRAFFIC', `Dispatched ${fileName} to ${pod}:/var/log/vigilante/pcap-spool/`);
            } catch (cpErr) {
              logger.warn('TRAFFIC', `Failed to copy PCAP to ${pod}: ${cpErr.message}`);
            }
          }
          result.copiedToPods = true;
          result.status = 'dispatched_to_pods';
        }
      } catch {
        // Cluster unreachable or no pods, keep staged locally
        result.status = 'staged_locally';
      }
    }

    // Save evidence artifact
    try {
      const evidenceContent = JSON.stringify(result, null, 2);
      await saveEvidenceFile('traffic', 'network-pcap', `${result.id}.json`, evidenceContent);
      await autoSignIfConfigured(path.join(getHostEvidenceDir('traffic', 'network-pcap'), `${result.id}.json`));
    } catch (evErr) {
      logger.warn('TRAFFIC', `Failed to save signed evidence: ${evErr.message}`);
    }

    return result;
  })();
}

/**
 * List all staged PCAP files in the local dropzone
 * @returns {Promise<Array<Object>>}
 */
export async function listPcapRecordings() {
  await ensureVigilanteConfig();
  const pcapDir = getVigilantePcapDir();

  try {
    const files = await fs.readdir(pcapDir);
    const pcaps = [];
    for (const f of files) {
      if (f.endsWith('.pcap') || f.endsWith('.pcapng') || f.endsWith('.cap')) {
        const p = path.join(pcapDir, f);
        const st = await fs.stat(p);
        pcaps.push({
          name: f,
          path: p,
          sizeBytes: st.size,
          mtime: st.mtime
        });
      }
    }
    return pcaps.sort((a, b) => b.mtime - a.mtime);
  } catch (err) {
    logger.warn('TRAFFIC', `Failed to list PCAPs: ${err.message}`);
    return [];
  }
}
