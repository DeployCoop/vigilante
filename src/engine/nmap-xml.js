import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteNmapsDir, ensureVigilanteConfig } from './config.js';
import { logger } from '../utils/logger.js';
import { parseNmapXml as nastymapParse } from './nastymap/parser.js';
import { generateTopology } from './nastymap/topology.js';
import { compareNmapScans } from './nastymap/diff.js';
import { generateHeadlessSvg, generateHtmlReport } from './nastymap/exporter.js';
import { geocodeIp } from './nastymap/geoip.js';

export {
  generateTopology,
  compareNmapScans,
  generateHeadlessSvg,
  generateHtmlReport,
  geocodeIp
};

/**
 * Robust XML parser specifically tailored for Nmap XML output powered by NastyMap
 * @param {string} xmlContent
 * @param {string} [filename='']
 * @returns {Object} Structured Nmap scan report
 */
export function parseNmapXml(xmlContent, filename = '') {
  if (!xmlContent || typeof xmlContent !== 'string') {
    return {
      isValid: false,
      error: 'Empty or invalid XML content',
      filename,
      hosts: [],
      runStats: {}
    };
  }

  try {
    const parsed = nastymapParse(xmlContent, filename);
    if (!parsed.isValid) {
      return parsed;
    }

    const hosts = (parsed.hosts || []).map((h) => {
      const ports = (h.ports || []).map((p) => ({
        port: p.portid,
        portid: p.portid,
        protocol: p.protocol,
        state: p.state,
        reason: p.reason || '',
        service: p.service?.name || 'unknown',
        product: p.service?.product || '',
        version: p.service?.version || '',
        extraInfo: p.service?.extrainfo || '',
        cpe: p.service?.cpe ? (Array.isArray(p.service.cpe) ? p.service.cpe[0] : p.service.cpe) : null,
        scripts: p.scripts || []
      }));

      const openPorts = ports.filter((p) => p.state === 'open');
      const osMatches = (h.osMatch || []).map((m) => ({
        name: m.name,
        accuracy: m.accuracy,
        line: m.line || ''
      }));

      return {
        ...h,
        ip: h.id,
        macVendor: h.vendor,
        ports,
        openPorts,
        openPortsCount: openPorts.length,
        osMatches,
        bestOsMatch: osMatches.length > 0 ? osMatches[0] : null,
        status: {
          state: h.status?.state || (h.isUp ? 'up' : 'down'),
          reason: h.status?.reason || '',
          latency: h.latencyMs !== undefined ? `${h.latencyMs}ms` : null
        }
      };
    });

    const totalOpenPorts = hosts.reduce((acc, h) => acc + h.openPortsCount, 0);
    const totalScripts = hosts.reduce((acc, h) => acc + (h.ports || []).reduce((pAcc, p) => pAcc + (p.scripts?.length || 0), 0), 0);
    const isCidr = parsed.target.includes('/') || hosts.length > 1 || (parsed.runStats?.hosts?.total && parsed.runStats.hosts.total > 1);

    return {
      ...parsed,
      hosts,
      liveHosts: hosts.filter((h) => h.isUp),
      totalOpenPorts,
      totalScripts,
      isCidr,
      summary: isCidr
        ? `${hosts.filter((h) => h.isUp).length} active hosts (${totalOpenPorts} open ports, ${totalScripts} script findings)`
        : `${totalOpenPorts} open ports on ${parsed.target} (${totalScripts} script findings)`
    };
  } catch (err) {
    logger.error('NMAP_XML:PARSE_ERROR', `Failed to parse XML with NastyMap: ${err.message}`, err);
    return {
      isValid: false,
      error: err.message,
      filename,
      hosts: [],
      runStats: {}
    };
  }
}

/**
 * List all saved Nmap XML reports in $XDG_CONFIG_HOME/vigilante/nmaps/
 * @returns {Promise<Array<Object>>}
 */
export async function listSavedXmlScans() {
  await ensureVigilanteConfig();
  const nmapsDir = getVigilanteNmapsDir();
  const xmlScans = [];

  try {
    const files = await fs.readdir(nmapsDir);
    const xmlFiles = files.filter(f => f.endsWith('.xml'));

    for (const file of xmlFiles) {
      const filePath = path.join(nmapsDir, file);
      try {
        const stats = await fs.stat(filePath);
        const content = await fs.readFile(filePath, 'utf8');
        const parsed = parseNmapXml(content, file);

        if (parsed.isValid) {
          xmlScans.push({
            ...parsed,
            id: file.replace(/\.xml$/, ''),
            filePath,
            sizeBytes: stats.size,
            mtime: stats.mtime,
            createdAt: stats.birthtime || stats.mtime
          });
        }
      } catch (err) {
        logger.warn('NMAP_XML:LIST', `Failed to parse XML scan ${file}: ${err.message}`);
      }
    }
  } catch (err) {
    logger.warn('NMAP_XML:LIST', `Failed to read XML files from nmaps dir: ${err.message}`);
  }

  return xmlScans.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Read and parse a single XML scan report by path
 * @param {string} filePath
 * @returns {Promise<Object>}
 */
export async function readXmlScan(filePath) {
  const content = await fs.readFile(filePath, 'utf8');
  return parseNmapXml(content, path.basename(filePath));
}
