#!/usr/bin/env node
import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ReadResourceRequestSchema,
  ListToolsRequestSchema,
  ListResourceTemplatesRequestSchema
} from '@modelcontextprotocol/sdk/types.js';

import { listSavedXmlScans, readXmlScan, parseNmapXml } from '../engine/nmap-xml.js';
import { listSavedNmapScans, readSavedScan, runNmapScan, SCAN_PROFILES, detectNetworkSubnets } from '../engine/nmap.js';
import { listEvidenceVault, listHostEvidence, readEvidenceFile, readEvidenceContent, saveEvidenceFile } from '../engine/evidence.js';
import { verifyFileSignature, listSecretKeys } from '../engine/gpg.js';
import { runPing, runBenchmark, runMtr, runCurlHeaders, runDnsLookup, runTlsCertDump, runArpNeighLookup as runArpCheck, runFullTriageCapture } from '../engine/diagnostics.js';
import { getPodsWide, getPodLogs, describePod } from '../engine/pods.js';
import { listInstances, loadInstanceMetadata, getDeployedNamespaces } from '../engine/instances.js';
import { listK3dClusters, getClusterInfo } from '../engine/cluster.js';
import { checkCertificates } from '../engine/certs.js';
import { loadConfig } from '../engine/config.js';
import { globalModuleRegistry } from '../modules/registry.js';

/**
 * Creates and configures the Vigilante MCP Server
 */
export function createVigilanteMcpServer() {
  const server = new Server(
    {
      name: 'vigilante-mcp-server',
      version: '0.1.0'
    },
    {
      capabilities: {
        resources: {},
        tools: {}
      }
    }
  );

  // -------------------------------------------------------------
  // 1. Resources: Static & Listable Data Feeds for LLMs
  // -------------------------------------------------------------
  server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
      resources: [
        {
          uri: 'vigilante://hosts',
          name: 'Discovered Network Hosts',
          description: 'Aggregated list of all discovered hosts with IP addresses, hostnames, status, open ports, OS guesses, and MAC vendors from Nmap XML scans.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://topology',
          name: 'Network Topology & Subnet Map',
          description: 'Hierarchical network topology grouped by CIDR subnets with live host counts and service matrices.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://evidence',
          name: 'Incident Response Evidence Vault Hierarchy',
          description: 'Forensic evidence hierarchy (net/host/data.ext) containing triage dumps, traces, and GPG signature records.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://pods',
          name: 'Live Kubernetes Pods (-A -o wide)',
          description: 'Real-time list of all pods across all Kubernetes namespaces with status, ready count, IP, node, and restarts.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://clusters',
          name: 'Configured k3d Cluster Instances',
          description: 'All local k3d cluster instances, directory paths, and deployed namespaces.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://modules',
          name: 'Vigilante Security Modules & Services',
          description: 'Security modules (OpenSearch SIEM, Vigil AI SOC) with their live ingress URLs and internal Kubernetes DNS endpoints.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://scans',
          name: 'Saved Nmap Scan Reports',
          description: 'List of all saved raw XML and text Nmap scan reports in $XDG_CONFIG_HOME/vigilante/nmaps.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://config',
          name: 'Vigilante Configuration & Settings',
          description: 'Current configuration settings, default domain, cluster name, hostr sync, and GPG signing identity.',
          mimeType: 'application/json'
        }
      ]
    };
  });

  // -------------------------------------------------------------
  // 2. Resource Templates: Parameterized URIs for LLMs
  // -------------------------------------------------------------
  server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
    return {
      resourceTemplates: [
        {
          uriTemplate: 'vigilante://hosts/{hostIp}',
          name: 'Specific Host Profile',
          description: 'Detailed report for a specific host including all open ports, version banners, OS matches, and NSE script outputs.',
          mimeType: 'application/json'
        },
        {
          uriTemplate: 'vigilante://evidence/{network}/{hostIp}',
          name: 'Host Forensic Evidence Triage Bundle',
          description: 'All forensic evidence artifacts captured for a specific host within a subnet (ping, mtr, dns, tls, http headers, arp).',
          mimeType: 'application/json'
        },
        {
          uriTemplate: 'vigilante://evidence/{network}/{hostIp}/{filename}',
          name: 'Raw Forensic Evidence File',
          description: 'Raw content of a specific forensic artifact file in the evidence vault.',
          mimeType: 'text/plain'
        },
        {
          uriTemplate: 'vigilante://scans/{filename}',
          name: 'Raw Nmap Scan Report',
          description: 'Raw text or XML content of a saved Nmap scan report.',
          mimeType: 'text/plain'
        }
      ]
    };
  });

  // -------------------------------------------------------------
  // 3. Read Resource Handlers
  // -------------------------------------------------------------
  server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const uri = request.params.uri;

    // A. Discovered Hosts Aggregation
    if (uri === 'vigilante://hosts') {
      const xmlScans = await listSavedXmlScans();
      const hostMap = new Map();

      for (const scan of xmlScans) {
        try {
          const report = await readXmlScan(scan.filePath);
          for (const host of report.hosts) {
            if (!hostMap.has(host.ip) || (host.ports && host.ports.length > 0)) {
              hostMap.set(host.ip, {
                ...host,
                lastSeenScan: scan.filename,
                scanTime: report.summary?.finishedTime || scan.time
              });
            }
          }
        } catch {
          // Ignore unreadable individual scans
        }
      }

      const hosts = Array.from(hostMap.values());
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ totalHosts: hosts.length, hosts }, null, 2)
          }
        ]
      };
    }

    // B. Network Topology Map
    if (uri === 'vigilante://topology') {
      const xmlScans = await listSavedXmlScans();
      const subnets = {};

      for (const scan of xmlScans) {
        try {
          const report = await readXmlScan(scan.filePath);
          const netTarget = report.summary?.target || 'unknown';
          if (!subnets[netTarget]) {
            subnets[netTarget] = {
              target: netTarget,
              scanFile: scan.filename,
              scanTime: report.summary?.finishedTime || scan.time,
              hostsCount: report.hosts.length,
              totalOpenPorts: report.hosts.reduce((acc, h) => acc + (h.ports?.length || 0), 0),
              hosts: report.hosts
            };
          }
        } catch {
          // Ignore
        }
      }

      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ subnetsCount: Object.keys(subnets).length, subnets }, null, 2)
          }
        ]
      };
    }

    // C. Evidence Vault Hierarchy
    if (uri === 'vigilante://evidence') {
      const vault = await listEvidenceVault();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(vault, null, 2)
          }
        ]
      };
    }

    // D. Live Kubernetes Pods
    if (uri === 'vigilante://pods') {
      const pods = await getPodsWide();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ count: pods.length, pods }, null, 2)
          }
        ]
      };
    }

    // E. Cluster Instances
    if (uri === 'vigilante://clusters') {
      const instances = await listInstances();
      const k3dClusters = await listK3dClusters();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ instances, activeK3dClusters: k3dClusters }, null, 2)
          }
        ]
      };
    }

    // F. Security Modules & Endpoints
    if (uri === 'vigilante://modules') {
      const cfg = loadConfig();
      const domain = cfg.defaults?.domain || 'vigilante.local';
      const allModules = globalModuleRegistry.getAll();
      const modules = await Promise.all(
        allModules.map(async (m) => {
          const endpoints = await m.getEndpoints({ domain, namespace: 'default' });
          return {
            id: m.id,
            name: m.name,
            description: m.description,
            category: m.category,
            endpoints
          };
        })
      );
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ domain, modules }, null, 2)
          }
        ]
      };
    }

    // G. Saved Scans List
    if (uri === 'vigilante://scans') {
      const xmlScans = await listSavedXmlScans();
      const textScans = await listSavedNmapScans();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ xmlScans, textScans }, null, 2)
          }
        ]
      };
    }

    // H. Config Settings
    if (uri === 'vigilante://config') {
      const cfg = loadConfig();
      const gpgKeys = await listSecretKeys();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ config: cfg, availableGpgKeys: gpgKeys }, null, 2)
          }
        ]
      };
    }

    // Parameterized URI: Specific Host Profile (vigilante://hosts/{hostIp})
    const hostMatch = uri.match(/^vigilante:\/\/hosts\/([a-zA-Z0-9.:_-]+)$/);
    if (hostMatch) {
      const targetIp = hostMatch[1];
      const xmlScans = await listSavedXmlScans();
      let matchedHost = null;

      for (const scan of xmlScans) {
        try {
          const report = await readXmlScan(scan.filePath);
          const found = report.hosts.find(h => h.ip === targetIp || (h.hostnames && h.hostnames.includes(targetIp)));
          if (found) {
            matchedHost = {
              ...found,
              scanReport: scan.filename,
              networkTarget: report.summary?.target
            };
            break;
          }
        } catch {
          // Ignore
        }
      }

      if (!matchedHost) {
        throw new Error(`Host '${targetIp}' not found in any saved Nmap XML reports`);
      }

      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(matchedHost, null, 2)
          }
        ]
      };
    }

    // Parameterized URI: Host Evidence Directory (vigilante://evidence/{network}/{hostIp})
    const evidenceHostMatch = uri.match(/^vigilante:\/\/evidence\/([^/]+)\/([^/]+)$/);
    if (evidenceHostMatch) {
      const network = decodeURIComponent(evidenceHostMatch[1]);
      const hostIp = decodeURIComponent(evidenceHostMatch[2]);
      const hostEvidence = await listHostEvidence(network, hostIp);

      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(hostEvidence, null, 2)
          }
        ]
      };
    }

    // Parameterized URI: Raw Evidence File (vigilante://evidence/{network}/{hostIp}/{filename})
    const evidenceFileMatch = uri.match(/^vigilante:\/\/evidence\/([^/]+)\/([^/]+)\/([^/]+)$/);
    if (evidenceFileMatch) {
      const network = decodeURIComponent(evidenceFileMatch[1]);
      const hostIp = decodeURIComponent(evidenceFileMatch[2]);
      const filename = decodeURIComponent(evidenceFileMatch[3]);
      const content = await readEvidenceFile(network, hostIp, filename);

      return {
        contents: [
          {
            uri,
            mimeType: 'text/plain',
            text: content
          }
        ]
      };
    }

    // Parameterized URI: Raw Scan Report (vigilante://scans/{filename})
    const scanFileMatch = uri.match(/^vigilante:\/\/scans\/([^/]+)$/);
    if (scanFileMatch) {
      const filename = decodeURIComponent(scanFileMatch[1]);
      const xmlScans = await listSavedXmlScans();
      const textScans = await listSavedNmapScans();
      const found = [...xmlScans, ...textScans].find(s => s.filename === filename);

      if (!found) {
        throw new Error(`Scan report '${filename}' not found in XDG nmaps directory`);
      }

      const content = await readSavedScan(found.filePath);
      return {
        contents: [
          {
            uri,
            mimeType: filename.endsWith('.xml') ? 'application/xml' : 'text/plain',
            text: content
          }
        ]
      };
    }

    throw new Error(`Resource URI not found: ${uri}`);
  });

  // -------------------------------------------------------------
  // 4. Tools: Callable Operations and Diagnostics for LLMs
  // -------------------------------------------------------------
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: 'list_hosts',
          description: 'Query discovered network hosts across Nmap XML scans with optional filtering by IP, CIDR subnet, open port, service name, or state (up/down).',
          inputSchema: {
            type: 'object',
            properties: {
              subnet: {
                type: 'string',
                description: 'Filter hosts by CIDR subnet (e.g. 10.0.1.0/24, 192.168.1.0/24)'
              },
              port: {
                type: 'number',
                description: 'Filter hosts that have a specific open port (e.g. 80, 443, 9200)'
              },
              service: {
                type: 'string',
                description: 'Filter hosts running a specific service (e.g. http, ssh, https, opensearch)'
              },
              state: {
                type: 'string',
                enum: ['all', 'up', 'down'],
                description: 'Filter by host status (default: up)'
              }
            }
          }
        },
        {
          name: 'get_host_details',
          description: 'Retrieve complete in-depth profile for a target host IP, including open ports, banners, OS match guesses, NSE vulnerability script outputs, and existing evidence artifacts.',
          inputSchema: {
            type: 'object',
            properties: {
              host: {
                type: 'string',
                description: 'Target IP address or hostname of the host to inspect (e.g. 10.0.1.5, 127.0.0.1)'
              }
            },
            required: ['host']
          }
        },
        {
          name: 'query_topology',
          description: 'Get structured network topology tree grouped by subnet CIDRs, live host IP addresses, and open service ports.',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'list_evidence',
          description: 'Browse the Incident Response Evidence Vault (net/host/data.ext), listing all forensic artifacts, triage bundles, and cryptographic GPG signatures.',
          inputSchema: {
            type: 'object',
            properties: {
              network: {
                type: 'string',
                description: 'Optional network identifier (e.g. 10.0.1.0_24, 127.0.0.0_30)'
              },
              host: {
                type: 'string',
                description: 'Optional host IP address'
              }
            }
          }
        },
        {
          name: 'run_diagnostic',
          description: 'Execute a live forensic network diagnostic probe against a target host (ping, mtr, curl headers, dns lookup, tls cert dump, or ab benchmark).',
          inputSchema: {
            type: 'object',
            properties: {
              tool: {
                type: 'string',
                enum: ['ping', 'mtr', 'curl', 'dns', 'tls', 'ab', 'arp'],
                description: 'Diagnostic tool to execute against the host'
              },
              host: {
                type: 'string',
                description: 'Target host IP address or hostname'
              },
              port: {
                type: 'number',
                description: 'Target port number (applicable for curl, tls, ab, default: 443 or 80)'
              },
              path: {
                type: 'string',
                description: 'HTTP path for curl/ab probes (default: /)'
              },
              count: {
                type: 'number',
                description: 'Ping count (default: 4) or MTR report cycles (default: 5)'
              },
              network: {
                type: 'string',
                description: 'Optional CIDR network string to automatically record artifact in the Evidence Vault (e.g. 10.0.1.0/24)'
              }
            },
            required: ['tool', 'host']
          }
        },
        {
          name: 'run_triage_capture',
          description: 'Execute a full parallel incident response forensic triage bundle against a host (ping, mtr, dns, tls certificates, http headers, arp), save all structured artifacts in net/host/data.ext, and sign with GPG if configured.',
          inputSchema: {
            type: 'object',
            properties: {
              network: {
                type: 'string',
                description: 'Target CIDR network (e.g. 10.0.1.0/24, 127.0.0.0/8)'
              },
              host: {
                type: 'string',
                description: 'Target host IP address (e.g. 10.0.1.5, 127.0.0.1)'
              },
              ports: {
                type: 'array',
                items: { type: 'number' },
                description: 'Optional list of target ports to probe for HTTP/TLS headers'
              }
            },
            required: ['network', 'host']
          }
        },
        {
          name: 'run_nmap_scan',
          description: 'Launch an Nmap reconnaissance scan against a target IP or CIDR range, save results as XML and Nmap text, and return parsed host data.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target IP, hostname, or CIDR network range (e.g. 127.0.0.1, 10.0.1.0/24)'
              },
              profile: {
                type: 'string',
                enum: ['sweep', 'net-quick', 'net-service', 'quick', 'service', 'vuln', 'full', 'custom'],
                description: 'Scan profile preset (default: quick)'
              },
              customArgs: {
                type: 'string',
                description: 'Custom Nmap command-line arguments when using profile="custom"'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'verify_evidence_signature',
          description: 'Verify the cryptographic GPG detached signature (.asc) for an artifact in the Evidence Vault to confirm evidence authenticity and non-repudiation.',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: {
                type: 'string',
                description: 'Path to the evidence artifact file (the .asc signature file is expected alongside it)'
              },
              signaturePath: {
                type: 'string',
                description: 'Optional explicit path to the detached .asc signature file'
              }
            },
            required: ['filePath']
          }
        },
        {
          name: 'get_pods',
          description: 'Query live Kubernetes pods across all namespaces (-A -o wide) with pod IP, node, status, restart count, and age.',
          inputSchema: {
            type: 'object',
            properties: {
              namespace: {
                type: 'string',
                description: 'Filter pods by specific Kubernetes namespace (e.g. default, vigil-soc, kube-system)'
              },
              clusterName: {
                type: 'string',
                description: 'Target k3d cluster instance name (default: active cluster)'
              }
            }
          }
        },
        {
          name: 'get_pod_logs',
          description: 'Retrieve live log tail from a specific Kubernetes pod container.',
          inputSchema: {
            type: 'object',
            properties: {
              podName: {
                type: 'string',
                description: 'Name of the pod'
              },
              namespace: {
                type: 'string',
                description: 'Kubernetes namespace containing the pod (default: default)'
              },
              container: {
                type: 'string',
                description: 'Optional container name within the pod'
              },
              tailLines: {
                type: 'number',
                description: 'Number of recent log lines to retrieve (default: 100)'
              },
              clusterName: {
                type: 'string',
                description: 'Target cluster name'
              }
            },
            required: ['podName']
          }
        },
        {
          name: 'describe_pod',
          description: 'Fetch detailed Kubernetes pod description, containers, volumes, conditions, and lifecycle events.',
          inputSchema: {
            type: 'object',
            properties: {
              podName: {
                type: 'string',
                description: 'Name of the pod'
              },
              namespace: {
                type: 'string',
                description: 'Namespace of the pod (default: default)'
              },
              clusterName: {
                type: 'string',
                description: 'Target cluster name'
              }
            },
            required: ['podName']
          }
        },
        {
          name: 'get_cluster_status',
          description: 'Check health and status of prerequisites, k3d clusters, TLS certificates, local DNS host mappings, and deployed security modules.',
          inputSchema: {
            type: 'object',
            properties: {
              clusterName: {
                type: 'string',
                description: 'Cluster instance name (default: vigilante-dev)'
              },
              domain: {
                type: 'string',
                description: 'Top-level domain (default: vigilante.local)'
              },
              namespace: {
                type: 'string',
                description: 'Target namespace to check module status in (default: default)'
              }
            }
          }
        }
      ]
    };
  });

  // -------------------------------------------------------------
  // 5. Tool Execution Dispatcher
  // -------------------------------------------------------------
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    // Tool: list_hosts
    if (name === 'list_hosts') {
      const xmlScans = await listSavedXmlScans();
      const hostMap = new Map();

      for (const scan of xmlScans) {
        try {
          const report = await readXmlScan(scan.filePath);
          for (const h of report.hosts) {
            if (!hostMap.has(h.ip) || (h.ports && h.ports.length > 0)) {
              hostMap.set(h.ip, {
                ...h,
                scanSource: scan.filename,
                networkTarget: report.summary?.target
              });
            }
          }
        } catch {
          // Ignore
        }
      }

      let results = Array.from(hostMap.values());

      if (args.state && args.state !== 'all') {
        results = results.filter(h => h.state === args.state);
      }
      if (args.port) {
        const targetPort = Number(args.port);
        results = results.filter(h => h.ports && h.ports.some(p => p.portId === targetPort && p.state === 'open'));
      }
      if (args.service) {
        const targetSvc = String(args.service).toLowerCase();
        results = results.filter(h => h.ports && h.ports.some(p => p.service && p.service.toLowerCase().includes(targetSvc)));
      }
      if (args.subnet) {
        const subnetPrefix = args.subnet.split('/')[0].replace(/\.[0-9]+$/, '');
        results = results.filter(h => h.ip.startsWith(subnetPrefix));
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ total: results.length, hosts: results }, null, 2)
          }
        ]
      };
    }

    // Tool: get_host_details
    if (name === 'get_host_details') {
      const targetHost = String(args.host).trim();
      const xmlScans = await listSavedXmlScans();
      let matchedHost = null;
      let matchedReport = null;

      for (const scan of xmlScans) {
        try {
          const report = await readXmlScan(scan.filePath);
          const found = report.hosts.find(h => h.ip === targetHost || (h.hostnames && h.hostnames.includes(targetHost)));
          if (found) {
            matchedHost = found;
            matchedReport = report;
            break;
          }
        } catch {
          // Ignore
        }
      }

      const networkTarget = matchedReport?.summary?.target || 'default';
      const evidence = await listHostEvidence(networkTarget, targetHost);

      const responsePayload = {
        host: targetHost,
        foundInScan: !!matchedHost,
        scanReport: matchedReport ? {
          filename: matchedReport.summary?.scanName,
          target: matchedReport.summary?.target,
          args: matchedReport.summary?.nmapArgs,
          scanTime: matchedReport.summary?.finishedTime
        } : null,
        nmapData: matchedHost,
        evidenceVault: evidence
      };

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(responsePayload, null, 2)
          }
        ]
      };
    }

    // Tool: query_topology
    if (name === 'query_topology') {
      const xmlScans = await listSavedXmlScans();
      const topology = [];

      for (const scan of xmlScans) {
        try {
          const report = await readXmlScan(scan.filePath);
          topology.push({
            scanFile: scan.filename,
            targetNetwork: report.summary?.target,
            startTime: report.summary?.startTime,
            finishedTime: report.summary?.finishedTime,
            hostsUp: report.summary?.hostsUp || report.hosts.filter(h => h.state === 'up').length,
            totalHosts: report.hosts.length,
            hosts: report.hosts.map(h => ({
              ip: h.ip,
              hostnames: h.hostnames,
              mac: h.mac,
              vendor: h.vendor,
              os: h.osMatches?.[0]?.name || null,
              openPorts: (h.ports || []).filter(p => p.state === 'open').map(p => ({
                port: p.portId,
                protocol: p.protocol,
                service: p.service,
                product: p.product,
                version: p.version
              }))
            }))
          });
        } catch {
          // Ignore
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ networksCount: topology.length, topology }, null, 2)
          }
        ]
      };
    }

    // Tool: list_evidence
    if (name === 'list_evidence') {
      if (args.network && args.host) {
        const hostEvidence = await listHostEvidence(args.network, args.host);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(hostEvidence, null, 2)
            }
          ]
        };
      }

      const vault = await listEvidenceVault();
      let networks = Array.isArray(vault) ? vault : [];
      if (args.network) {
        const cleanNet = args.network.replace(/\//g, '_');
        networks = networks.filter(n => n.dirName === cleanNet || n.network === args.network || n.name === args.network);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ totalNetworks: networks.length, networks }, null, 2)
          }
        ]
      };
    }

    // Tool: run_diagnostic
    if (name === 'run_diagnostic') {
      const { tool, host, port, path: httpPath = '/', count = 4, network } = args;
      let result;

      switch (tool) {
        case 'ping':
          result = await runPing(host, count);
          break;
        case 'mtr':
          result = await runMtr(host);
          break;
        case 'curl':
          result = await runCurlHeaders(host, { port: port || 80, isHttps: port === 443 });
          break;
        case 'dns':
          result = await runDnsLookup(host);
          break;
        case 'tls':
          result = await runTlsCertDump(host, port || 443);
          break;
        case 'ab':
          result = await runBenchmark(host, { port: port || 80, path: httpPath, count: count || 100, concurrency: 10 });
          break;
        case 'arp':
          result = await runArpCheck(host);
          break;
        default:
          throw new Error(`Unsupported diagnostic tool: '${tool}'`);
      }

      // Automatically persist to evidence vault if network is specified
      let savedArtifact = null;
      if (network && result) {
        const filenameMap = {
          ping: 'ping.txt',
          mtr: 'mtr.txt',
          curl: 'http_headers.txt',
          dns: 'dns_records.json',
          tls: 'tls_certificates.pem',
          ab: 'ab_benchmark.txt',
          arp: 'arp.txt'
        };
        const fname = filenameMap[tool] || `${tool}_output.txt`;
        const contentToSave = typeof result.output === 'string' ? result.output : JSON.stringify(result, null, 2);
        savedArtifact = await saveEvidenceFile(network, host, fname, contentToSave);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ diagnostic: tool, host, result, savedArtifact }, null, 2)
          }
        ]
      };
    }

    // Tool: run_triage_capture
    if (name === 'run_triage_capture') {
      const { network, host, ports = [] } = args;
      const triage = await runFullTriageCapture(host, { ports, networkCidr: network || 'default' });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(triage, null, 2)
          }
        ]
      };
    }

    // Tool: run_nmap_scan
    if (name === 'run_nmap_scan') {
      const { target, profile = 'quick', customArgs = '' } = args;
      const scanRes = await runNmapScan({
        target,
        profile,
        customArgs
      });

      // Parse output XML if generated
      let parsed = null;
      if (scanRes.xmlFilePath) {
        try {
          parsed = await parseNmapXml(scanRes.xmlFilePath);
        } catch {
          // Ignore
        }
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              scanResult: scanRes,
              parsedSummary: parsed?.summary || null,
              hostsDiscovered: parsed?.hosts || []
            }, null, 2)
          }
        ]
      };
    }

    // Tool: verify_evidence_signature
    if (name === 'verify_evidence_signature') {
      const { filePath, signaturePath } = args;
      const verification = await verifyFileSignature(filePath, signaturePath);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(verification, null, 2)
          }
        ]
      };
    }

    // Tool: get_pods
    if (name === 'get_pods') {
      const { namespace, clusterName } = args;
      let pods = await getPodsWide({ clusterName });
      if (namespace && namespace !== 'all') {
        pods = pods.filter(p => p.namespace === namespace);
      }

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ total: pods.length, pods }, null, 2)
          }
        ]
      };
    }

    // Tool: get_pod_logs
    if (name === 'get_pod_logs') {
      const { podName, namespace = 'default', container, tailLines = 100, clusterName } = args;
      const logs = await getPodLogs({
        podName,
        namespace,
        container,
        tailLines,
        clusterName
      });

      return {
        content: [
          {
            type: 'text',
            text: logs || '(No log output returned)'
          }
        ]
      };
    }

    // Tool: describe_pod
    if (name === 'describe_pod') {
      const { podName, namespace = 'default', clusterName } = args;
      const description = await describePod({
        podName,
        namespace,
        clusterName
      });

      return {
        content: [
          {
            type: 'text',
            text: description || '(No describe output returned)'
          }
        ]
      };
    }

    // Tool: get_cluster_status
    if (name === 'get_cluster_status') {
      const cfg = loadConfig();
      const clusterName = args.clusterName || cfg.defaults?.clusterName || 'vigilante-dev';
      const domain = args.domain || cfg.defaults?.domain || 'vigilante.local';
      const namespace = args.namespace || 'default';

      const clusterInfo = await getClusterInfo(clusterName);
      const certsInfo = await checkCertificates(domain, { clusterName, instanceName: clusterName });
      const deployedNamespaces = await getDeployedNamespaces(clusterName);
      const allModules = globalModuleRegistry.getAll();

      const moduleStatuses = await Promise.all(
        allModules.map(async (m) => {
          const st = await m.status({ domain, clusterName, namespace });
          const endpoints = await m.getEndpoints({ domain, namespace });
          return { ...st, endpoints };
        })
      );

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              cluster: clusterInfo,
              domain,
              certs: certsInfo,
              namespace,
              deployedNamespaces,
              modules: moduleStatuses
            }, null, 2)
          }
        ]
      };
    }

    throw new Error(`Tool not recognized: '${name}'`);
  });

  return server;
}

/**
 * CLI Main execution entrypoint for stdio MCP Transport
 */
export async function runMcpServer() {
  const server = createVigilanteMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Log to stderr so stdout remains strictly reserved for JSON-RPC MCP framing
  console.error('🛡️ Vigilante MCP Server running on stdio transport.');
}

// Auto-run if executed directly as entrypoint
if (process.argv[1] && (process.argv[1].endsWith('mcp/server.js') || process.argv[1].endsWith('server.js'))) {
  runMcpServer().catch((err) => {
    console.error('Fatal MCP Server error:', err);
    process.exit(1);
  });
}
