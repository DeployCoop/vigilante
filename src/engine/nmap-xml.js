import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteNmapsDir, ensureVigilanteConfig } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Robust XML parser specifically tailored for Nmap XML output
 * @param {string} xmlContent
 * @param {string} [filename='']
 * @returns {Object} Structured Nmap scan report
 */
export function parseNmapXml(xmlContent, filename = '') {
  if (!xmlContent || typeof xmlContent !== 'string') {
    return {
      isValid: false,
      error: 'Empty or invalid XML content',
      hosts: [],
      runStats: {}
    };
  }

  try {
    // 1. Parse <nmaprun> attributes
    const nmaprunMatch = xmlContent.match(/<nmaprun\s+([^>]+)>/i);
    const nmapAttrs = nmaprunMatch ? parseXmlAttributes(nmaprunMatch[1]) : {};

    // 2. Parse <scaninfo>
    const scanInfoMatch = xmlContent.match(/<scaninfo\s+([^>]+)\/?>/i);
    const scanInfo = scanInfoMatch ? parseXmlAttributes(scanInfoMatch[1]) : {};

    // 3. Parse <runstats>
    const runstatsMatch = xmlContent.match(/<runstats>([\s\S]*?)<\/runstats>/i);
    let runStats = {};
    if (runstatsMatch) {
      const finishedMatch = runstatsMatch[1].match(/<finished\s+([^>]+)\/?>/i);
      const hostsMatch = runstatsMatch[1].match(/<hosts\s+([^>]+)\/?>/i);
      const finishedAttrs = finishedMatch ? parseXmlAttributes(finishedMatch[1]) : {};
      const hostsAttrs = hostsMatch ? parseXmlAttributes(hostsMatch[1]) : {};

      runStats = {
        time: finishedAttrs.time,
        timestr: finishedAttrs.timestr,
        elapsedSec: parseFloat(finishedAttrs.elapsed || '0'),
        summary: finishedAttrs.summary || '',
        exit: finishedAttrs.exit || 'success',
        hostsUp: parseInt(hostsAttrs.up || '0', 10),
        hostsDown: parseInt(hostsAttrs.down || '0', 10),
        hostsTotal: parseInt(hostsAttrs.total || '0', 10)
      };
    }

    // 4. Parse all <host> blocks
    const hostRegex = /<host(?:\s+[^>]*?)?>([\s\S]*?)<\/host>/gi;
    const hosts = [];
    let hostMatch;

    while ((hostMatch = hostRegex.exec(xmlContent)) !== null) {
      const hostBlock = hostMatch[1];

      // Parse status
      const statusMatch = hostBlock.match(/<status\s+([^>]+)\/?>/i);
      const statusAttrs = statusMatch ? parseXmlAttributes(statusMatch[1]) : {};
      const isUp = (statusAttrs.state || '').toLowerCase() === 'up';

      // Parse addresses (IPv4, IPv6, MAC)
      let ipv4 = null;
      let ipv6 = null;
      let mac = null;
      let macVendor = null;

      const addressRegex = /<address\s+([^>]+)\/?>/gi;
      let addrMatch;
      while ((addrMatch = addressRegex.exec(hostBlock)) !== null) {
        const attrs = parseXmlAttributes(addrMatch[1]);
        if (attrs.addrtype === 'ipv4') ipv4 = attrs.addr;
        else if (attrs.addrtype === 'ipv6') ipv6 = attrs.addr;
        else if (attrs.addrtype === 'mac') {
          mac = attrs.addr;
          macVendor = attrs.vendor || null;
        }
      }

      const ip = ipv4 || ipv6 || 'unknown-ip';

      // Parse hostnames
      const hostnames = [];
      const hostnamesBlock = hostBlock.match(/<hostnames>([\s\S]*?)<\/hostnames>/i);
      if (hostnamesBlock) {
        const hostnameRegex = /<hostname\s+([^>]+)\/?>/gi;
        let hMatch;
        while ((hMatch = hostnameRegex.exec(hostnamesBlock[1])) !== null) {
          const hAttrs = parseXmlAttributes(hMatch[1]);
          if (hAttrs.name) {
            hostnames.push({ name: hAttrs.name, type: hAttrs.type || 'user' });
          }
        }
      }
      const primaryHostname = hostnames.length > 0 ? hostnames[0].name : ip;

      // Parse ports
      const ports = [];
      const portsBlock = hostBlock.match(/<ports>([\s\S]*?)<\/ports>/i);
      if (portsBlock) {
        const portRegex = /<port\s+([^>]+)>([\s\S]*?)<\/port>/gi;
        let pMatch;
        while ((pMatch = portRegex.exec(portsBlock[1])) !== null) {
          const portAttrs = parseXmlAttributes(pMatch[1]);
          const portInner = pMatch[2];

          const stateMatch = portInner.match(/<state\s+([^>]+)\/?>/i);
          const stateAttrs = stateMatch ? parseXmlAttributes(stateMatch[1]) : {};

          const serviceMatch = portInner.match(/<service\s+([^>]+)>(?:[\s\S]*?)<\/service>|<service\s+([^>]+)\/?>/i);
          const serviceAttrs = serviceMatch ? parseXmlAttributes(serviceMatch[1] || serviceMatch[2]) : {};

          // Parse scripts
          const scripts = [];
          const scriptRegex = /<script\s+([^>]+)(?:>([\s\S]*?)<\/script>|\/?>)/gi;
          let sMatch;
          while ((sMatch = scriptRegex.exec(portInner)) !== null) {
            const sAttrs = parseXmlAttributes(sMatch[1]);
            const sOutput = sAttrs.output || (sMatch[2] ? stripXmlTags(sMatch[2]).trim() : '');
            if (sAttrs.id) {
              scripts.push({ id: sAttrs.id, output: sOutput });
            }
          }

          // Parse CPE
          const cpeMatch = portInner.match(/<cpe>([\s\S]*?)<\/cpe>/i);
          const cpe = cpeMatch ? cpeMatch[1].trim() : null;

          ports.push({
            port: parseInt(portAttrs.portid || '0', 10),
            protocol: portAttrs.protocol || 'tcp',
            state: stateAttrs.state || 'unknown',
            reason: stateAttrs.reason || '',
            service: serviceAttrs.name || 'unknown',
            product: serviceAttrs.product || '',
            version: serviceAttrs.version || '',
            extraInfo: serviceAttrs.extrainfo || '',
            method: serviceAttrs.method || 'table',
            conf: serviceAttrs.conf || '',
            cpe,
            scripts
          });
        }
      }

      // Parse OS Matches
      const osMatches = [];
      const osBlock = hostBlock.match(/<os>([\s\S]*?)<\/os>/i);
      if (osBlock) {
        const osMatchRegex = /<osmatch\s+([^>]+)>/gi;
        let oMatch;
        while ((oMatch = osMatchRegex.exec(osBlock[1])) !== null) {
          const oAttrs = parseXmlAttributes(oMatch[1]);
          if (oAttrs.name) {
            osMatches.push({
              name: oAttrs.name,
              accuracy: parseInt(oAttrs.accuracy || '0', 10),
              line: oAttrs.line || ''
            });
          }
        }
      }

      // Parse Times / Latency
      const timesMatch = hostBlock.match(/<times\s+([^>]+)\/?>/i);
      const timesAttrs = timesMatch ? parseXmlAttributes(timesMatch[1]) : {};
      const latencyMs = timesAttrs.srtt ? (parseInt(timesAttrs.srtt, 10) / 1000).toFixed(2) + 'ms' : null;

      const openPorts = ports.filter(p => p.state === 'open');

      hosts.push({
        ip,
        mac,
        macVendor,
        hostnames,
        primaryHostname,
        isUp,
        status: {
          state: statusAttrs.state || (isUp ? 'up' : 'down'),
          reason: statusAttrs.reason || '',
          latency: latencyMs
        },
        ports,
        openPorts,
        openPortsCount: openPorts.length,
        osMatches,
        bestOsMatch: osMatches.length > 0 ? osMatches[0] : null
      });
    }

    // Extract target
    const target = nmapAttrs.args
      ? nmapAttrs.args.split(' ').pop()
      : (hosts.length > 0 ? hosts[0].ip : path.basename(filename).replace(/^nmap-/, '').replace(/-\d+\.xml$/, '').replace(/_/g, '/'));

    const totalOpenPorts = hosts.reduce((acc, h) => acc + h.openPortsCount, 0);
    const totalScripts = hosts.reduce((acc, h) => acc + h.ports.reduce((pAcc, p) => pAcc + p.scripts.length, 0), 0);
    const isCidr = target.includes('/') || hosts.length > 1 || (runStats.hostsTotal && runStats.hostsTotal > 1);

    return {
      isValid: true,
      filename,
      scanner: nmapAttrs.scanner || 'nmap',
      version: nmapAttrs.version || 'unknown',
      args: nmapAttrs.args || '',
      startStr: nmapAttrs.startstr || '',
      target,
      isCidr,
      scanInfo: {
        type: scanInfo.type || 'syn',
        protocol: scanInfo.protocol || 'tcp',
        numServices: parseInt(scanInfo.numservices || '0', 10)
      },
      runStats: {
        ...runStats,
        hostsUp: runStats.hostsUp || hosts.filter(h => h.isUp).length,
        hostsTotal: runStats.hostsTotal || hosts.length
      },
      hosts,
      liveHosts: hosts.filter(h => h.isUp),
      totalOpenPorts,
      totalScripts,
      summary: isCidr
        ? `${hosts.filter(h => h.isUp).length} active hosts (${totalOpenPorts} open ports, ${totalScripts} script findings)`
        : `${totalOpenPorts} open ports on ${target} (${totalScripts} script findings)`
    };
  } catch (err) {
    logger.error('NMAP_XML:PARSE_ERROR', `Failed to parse XML: ${err.message}`, err);
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
 * Helper to parse attribute key="value" pairs from an XML tag string
 */
function parseXmlAttributes(attrString) {
  const attrs = {};
  if (!attrString) return attrs;
  const regex = /([a-zA-Z0-9_:-]+)="([^"]*)"/g;
  let match;
  while ((match = regex.exec(attrString)) !== null) {
    attrs[match[1]] = match[2];
  }
  return attrs;
}

/**
 * Strip XML/HTML tags from a string
 */
function stripXmlTags(str) {
  return str.replace(/<[^>]*>/g, '');
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
