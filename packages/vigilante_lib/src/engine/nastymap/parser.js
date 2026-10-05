import { XMLParser } from 'fast-xml-parser';
import { geocodeIp } from './geoip.js';

const arrayTags = new Set([
  'host',
  'address',
  'hostname',
  'port',
  'osmatch',
  'osclass',
  'hop',
  'script',
  'scaninfo',
  'cpe',
  'portused'
]);

const xmlParserOptions = {
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  allowBooleanAttributes: true,
  parseNodeValue: true,
  parseAttributeValue: true,
  trimValues: true,
  isArray: (tagName) => arrayTags.has(tagName.toLowerCase())
};

function ensureArray(val) {
  if (!val) return [];
  return Array.isArray(val) ? val : [val];
}

function parseScriptElement(rawScript) {
  if (!rawScript) return null;
  const id = rawScript['@_id'] || 'unknown-script';
  const output = rawScript['@_output'] || (typeof rawScript === 'string' ? rawScript : '');
  const elements = {};

  if (rawScript.elem) {
    const rawElems = ensureArray(rawScript.elem);
    for (const elem of rawElems) {
      const key = elem['@_key'] || 'val';
      elements[key] = String(elem['#text'] || elem || '');
    }
  }

  return { id, output, elements: Object.keys(elements).length > 0 ? elements : undefined };
}

function parseServiceElement(rawService) {
  if (!rawService) return undefined;

  const cpeList = [];
  if (rawService.cpe) {
    const cpes = ensureArray(rawService.cpe);
    for (const cpe of cpes) {
      if (typeof cpe === 'string') cpeList.push(cpe);
      else if (cpe && cpe['#text']) cpeList.push(cpe['#text']);
    }
  }

  return {
    name: rawService['@_name'] || 'unknown',
    product: rawService['@_product'],
    version: rawService['@_version'] ? String(rawService['@_version']) : undefined,
    extrainfo: rawService['@_extrainfo'],
    method: rawService['@_method'],
    conf: rawService['@_conf'] ? String(rawService['@_conf']) : undefined,
    cpe: cpeList.length > 0 ? cpeList : undefined,
    tunnel: rawService['@_tunnel'],
    proto: rawService['@_proto'],
    rpcnum: rawService['@_rpcnum'] ? String(rawService['@_rpcnum']) : undefined,
    ostype: rawService['@_ostype'],
    devicetype: rawService['@_devicetype'],
    servicefp: rawService['@_servicefp']
  };
}

function parsePortElement(rawPort) {
  const portid = Number(rawPort['@_portid']) || 0;
  const protocol = (rawPort['@_protocol'] || 'tcp').toLowerCase();
  
  const stateObj = rawPort.state || {};
  const state = (stateObj['@_state'] || 'unknown');
  const reason = stateObj['@_reason'];
  const reason_ttl = stateObj['@_reason_ttl'] ? Number(stateObj['@_reason_ttl']) : undefined;

  const service = parseServiceElement(rawPort.service);

  const scripts = [];
  if (rawPort.script) {
    const rawScripts = ensureArray(rawPort.script);
    for (const s of rawScripts) {
      const parsed = parseScriptElement(s);
      if (parsed) scripts.push(parsed);
    }
  }

  return {
    portid,
    protocol,
    state,
    reason,
    reason_ttl,
    service,
    scripts: scripts.length > 0 ? scripts : undefined
  };
}

function parseHostElement(rawHost) {
  const statusObj = rawHost.status || {};
  const status = {
    state: statusObj['@_state'] || 'unknown',
    reason: statusObj['@_reason'],
    reason_ttl: statusObj['@_reason_ttl'] ? Number(statusObj['@_reason_ttl']) : undefined
  };

  const addresses = [];
  let ipv4 = null;
  let ipv6 = null;
  let mac = null;
  let vendor = undefined;

  if (rawHost.address) {
    const rawAddresses = ensureArray(rawHost.address);
    for (const addr of rawAddresses) {
      const addrStr = addr['@_addr'] || '';
      const addrtype = (addr['@_addrtype'] || 'ipv4');
      const v = addr['@_vendor'];

      addresses.push({ addr: addrStr, addrtype, vendor: v });

      if (addrtype === 'ipv4') ipv4 = addrStr;
      else if (addrtype === 'ipv6') ipv6 = addrStr;
      else if (addrtype === 'mac') {
        mac = addrStr;
        if (v) vendor = v;
      }
    }
  }

  const hostnames = [];
  if (rawHost.hostnames && rawHost.hostnames.hostname) {
    const rawHostnames = ensureArray(rawHost.hostnames.hostname);
    for (const h of rawHostnames) {
      if (h['@_name']) {
        hostnames.push({
          name: h['@_name'],
          type: (h['@_type'] || 'user')
        });
      }
    }
  }

  const primaryHostname = hostnames.length > 0 ? hostnames[0].name : undefined;

  const ports = [];
  if (rawHost.ports && rawHost.ports.port) {
    const rawPorts = ensureArray(rawHost.ports.port);
    for (const p of rawPorts) {
      ports.push(parsePortElement(p));
    }
  }

  let osMatch = undefined;
  let osClasses = undefined;
  if (rawHost.os) {
    if (rawHost.os.osmatch) {
      const rawMatches = ensureArray(rawHost.os.osmatch);
      osMatch = rawMatches.map((m) => ({
        name: m['@_name'] || 'Unknown OS',
        accuracy: Number(m['@_accuracy']) || 0,
        line: m['@_line'] ? Number(m['@_line']) : undefined
      }));
    }

    if (rawHost.os.osclass) {
      const rawClasses = ensureArray(rawHost.os.osclass);
      osClasses = rawClasses.map((c) => ({
        type: c['@_type'],
        vendor: c['@_vendor'],
        osfamily: c['@_osfamily'],
        osgen: c['@_osgen'],
        accuracy: Number(c['@_accuracy']) || 0
      }));
    }
  }

  let distance = undefined;
  if (rawHost.distance) {
    distance = Number(rawHost.distance['@_value']) || undefined;
  }

  let uptime = undefined;
  if (rawHost.uptime) {
    uptime = {
      seconds: Number(rawHost.uptime['@_seconds']) || 0,
      lastboot: rawHost.uptime['@_lastboot']
    };
  }

  let trace = undefined;
  if (rawHost.trace && rawHost.trace.hop) {
    const rawHops = ensureArray(rawHost.trace.hop);
    trace = {
      port: rawHost.trace['@_port'] ? Number(rawHost.trace['@_port']) : undefined,
      protocol: rawHost.trace['@_proto'],
      hops: rawHops.map((h) => ({
        ttl: Number(h['@_ttl']) || 0,
        rtt: h['@_rtt'] ? Number(h['@_rtt']) : undefined,
        ipaddr: h['@_ipaddr'] || '',
        host: h['@_host']
      }))
    };
  }

  let times = undefined;
  if (rawHost.times) {
    times = {
      srtt: rawHost.times['@_srtt'] ? Number(rawHost.times['@_srtt']) : undefined,
      rttvar: rawHost.times['@_rttvar'] ? Number(rawHost.times['@_rttvar']) : undefined,
      to: rawHost.times['@_to'] ? Number(rawHost.times['@_to']) : undefined
    };
  }

  // Derive helper properties
  const targetIp = ipv4 || ipv6 || (addresses[0] ? addresses[0].addr : 'unknown');
  let primaryOs = undefined;
  let osFamily = undefined;
  let deviceType = undefined;

  if (osMatch && osMatch.length > 0) {
    primaryOs = osMatch[0].name;
  }
  if (osClasses && osClasses.length > 0) {
    osFamily = osClasses[0].osfamily;
    deviceType = osClasses[0].type;
  }

  // Fallback heuristics for OS family
  if (!osFamily && primaryOs) {
    const low = primaryOs.toLowerCase();
    if (low.includes('linux') || low.includes('ubuntu') || low.includes('debian')) osFamily = 'Linux';
    else if (low.includes('windows') || low.includes('microsoft')) osFamily = 'Windows';
    else if (low.includes('mac') || low.includes('apple') || low.includes('darwin')) osFamily = 'macOS';
    else if (low.includes('cisco') || low.includes('ios')) osFamily = 'Cisco IOS';
    else if (low.includes('bsd')) osFamily = 'BSD';
    else if (low.includes('android')) osFamily = 'Android';
  }

  const openPortsCount = ports.filter((p) => p.state === 'open').length;
  const filteredPortsCount = ports.filter((p) => p.state === 'filtered').length;
  const closedPortsCount = ports.filter((p) => p.state === 'closed').length;

  let vulnerabilitiesCount = 0;
  for (const p of ports) {
    if (p.scripts) {
      for (const s of p.scripts) {
        if (s.id.includes('vuln') || s.id.includes('cve') || s.output.toLowerCase().includes('vulnerable')) {
          vulnerabilitiesCount++;
        }
      }
    }
  }

  const latencyMs = times && times.srtt !== undefined ? Math.round(times.srtt / 1000) : undefined;
  const geolocation = geocodeIp(targetIp);

  return {
    id: targetIp,
    startTime: rawHost['@_starttime'] ? Number(rawHost['@_starttime']) : undefined,
    endTime: rawHost['@_endtime'] ? Number(rawHost['@_endtime']) : undefined,
    status,
    addresses,
    ipv4: ipv4 || undefined,
    ipv6: ipv6 || undefined,
    mac: mac || undefined,
    vendor,
    hostnames,
    primaryHostname,
    ports,
    osMatch,
    osClasses,
    primaryOs,
    osFamily,
    deviceType,
    distance,
    uptime,
    trace,
    times,
    geolocation,
    openPortsCount,
    filteredPortsCount,
    closedPortsCount,
    vulnerabilitiesCount,
    latencyMs,
    isUp: status.state.toLowerCase() === 'up'
  };
}

/**
 * Parses full Nmap XML string into a typed, structured NmapRun object.
 * @param {string} xmlString
 * @param {string} [filename='']
 * @returns {Object} Structured NmapRun
 */
export function parseNmapXml(xmlString, filename = '') {
  if (!xmlString || typeof xmlString !== 'string') {
    return {
      isValid: false,
      error: 'Empty XML input',
      filename,
      scanner: 'nmap',
      args: '',
      start: 0,
      startstr: '',
      version: '0.0',
      hosts: [],
      scanInfo: [],
      runStats: {
        finished: { time: 0, timestr: '', elapsed: 0, summary: '', exit: 'error' },
        hosts: { up: 0, down: 0, total: 0 }
      },
      verbose: 0,
      debugging: 0
    };
  }

  const parser = new XMLParser(xmlParserOptions);
  let parsed;
  try {
    parsed = parser.parse(xmlString);
  } catch (err) {
    return {
      isValid: false,
      error: `XML Parsing Error: ${err.message}`,
      filename,
      scanner: 'nmap',
      args: '',
      start: 0,
      startstr: '',
      version: '0.0',
      hosts: [],
      scanInfo: [],
      runStats: {
        finished: { time: 0, timestr: '', elapsed: 0, summary: '', exit: 'error' },
        hosts: { up: 0, down: 0, total: 0 }
      },
      verbose: 0,
      debugging: 0
    };
  }

  const nmaprun = parsed.nmaprun;
  if (!nmaprun) {
    return {
      isValid: false,
      error: 'Root <nmaprun> element not found in XML',
      filename,
      scanner: 'nmap',
      args: '',
      start: 0,
      startstr: '',
      version: '0.0',
      hosts: [],
      scanInfo: [],
      runStats: {
        finished: { time: 0, timestr: '', elapsed: 0, summary: '', exit: 'error' },
        hosts: { up: 0, down: 0, total: 0 }
      },
      verbose: 0,
      debugging: 0
    };
  }

  const scanner = nmaprun['@_scanner'] || 'nmap';
  const args = nmaprun['@_args'] || '';
  const start = Number(nmaprun['@_start']) || 0;
  const startstr = nmaprun['@_startstr'] || '';
  const version = nmaprun['@_version'] || '1.0';

  const scanInfo = [];
  if (nmaprun.scaninfo) {
    const rawScanInfos = ensureArray(nmaprun.scaninfo);
    for (const info of rawScanInfos) {
      scanInfo.push({
        type: info['@_type'] || 'syn',
        protocol: info['@_protocol'] || 'tcp',
        numservices: Number(info['@_numservices']) || 0,
        services: info['@_services'] || ''
      });
    }
  }

  const hosts = [];
  if (nmaprun.host) {
    const rawHosts = ensureArray(nmaprun.host);
    for (const h of rawHosts) {
      hosts.push(parseHostElement(h));
    }
  }

  let runStats = {
    finished: { time: 0, timestr: '', elapsed: 0, summary: '', exit: 'success' },
    hosts: { up: hosts.filter(h => h.isUp).length, down: hosts.filter(h => !h.isUp).length, total: hosts.length }
  };

  if (nmaprun.runstats) {
    const rs = nmaprun.runstats;
    const fin = rs.finished || {};
    const hs = rs.hosts || {};
    runStats = {
      finished: {
        time: Number(fin['@_time']) || 0,
        timestr: fin['@_timestr'] || '',
        elapsed: Number(fin['@_elapsed']) || 0,
        summary: fin['@_summary'] || '',
        exit: fin['@_exit'] || 'success'
      },
      hosts: {
        up: Number(hs['@_up']) || hosts.filter(h => h.isUp).length,
        down: Number(hs['@_down']) || hosts.filter(h => !h.isUp).length,
        total: Number(hs['@_total']) || hosts.length
      }
    };
  }

  const verbose = nmaprun.verbose ? Number(nmaprun.verbose['@_level']) || 0 : 0;
  const debugging = nmaprun.debugging ? Number(nmaprun.debugging['@_level']) || 0 : 0;

  // Determine target summary
  let target = 'Unknown Target';
  if (args) {
    const parts = args.split(/\s+/);
    target = parts[parts.length - 1] || 'Network';
  } else if (hosts.length > 0) {
    target = hosts[0].id;
  }

  return {
    isValid: true,
    filename,
    target,
    scanner,
    args,
    start,
    startstr,
    version,
    hosts,
    scanInfo,
    runStats,
    verbose,
    debugging
  };
}
