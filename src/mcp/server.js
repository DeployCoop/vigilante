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

import {
  listSavedXmlScans,
  readXmlScan,
  parseNmapXml,
  generateTopology,
  generateHeadlessSvg,
  generateHtmlReport,
  compareNmapScans
} from '../engine/nmap-xml.js';
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
import { listAvailablePlaybooks, executeThreatPlaybook } from '../engine/threats.js';
import {
  NIST_ATTACK_VECTORS,
  NIST_LIFECYCLE_PHASES,
  NIST_EVIDENCE_VOLATILITY,
  NIST_IMPACT_LEVELS,
  calculateNistIncidentScore,
  generateNistIncidentRecord,
  generateNistPostMortemMarkdown,
  listNistIncidents
} from '../engine/nist.js';
import {
  checkOpenVasStatus,
  runHostVulnerabilityScan,
  listSavedOpenVasReports,
  SCAN_PROFILES as OPENVAS_SCAN_PROFILES
} from '../engine/openvas.js';
import {
  CHALLENGE_TEMPLATES,
  listActiveChallenges,
  spinUpChallenge,
  deleteChallenge,
  testChallengeConnection
} from '../engine/kctf.js';
import {
  checkOobscanInstalled,
  runOobScan,
  listSavedOobScans,
  readSavedOobScan,
  deleteSavedOobScan,
  exportRakpHashes,
  OOB_SCAN_PROFILES
} from '../engine/oobscan.js';
import { runReconScan, listSavedReconScans, checkReconToolsInstalled } from '../engine/recon.js';
import { runNucleiScan, listSavedNucleiScans, checkNucleiInstalled } from '../engine/nuclei.js';
import { runTrivyAudit, listSavedTrivyScans, checkTrivyInstalled } from '../engine/trivy.js';
import { runKubeAudit, listSavedKubeAudits, checkKubeAuditToolsInstalled } from '../engine/kubeaudit.js';
import { runNetexecAudit, listSavedNetexecAudits, checkNetexecInstalled } from '../engine/netexec.js';
import { runZapScan, listSavedZapScans, checkZapAvailable } from '../engine/zap.js';
import { getHostDossier, buildHostDossier, listHostDossiers } from '../engine/dossier.js';
import { replayPcap, listPcapRecordings, parseSuricataEve, parseZeekConnLogs, summarizeTrafficAlerts } from '../engine/traffic.js';
import { ingestBloodhoundData, listBloodhoundIngests, checkBloodhoundAvailable } from '../engine/bloodhound.js';
import { generateMitreCoverageMatrix, generateMitreMarkdownReport, saveMitreReport } from '../engine/mitre.js';
import {
  isolatePod,
  freezePod,
  blockIp,
  quarantineAccount,
  listActiveContainments,
  releaseContainment
} from '../engine/soar.js';
import { runAgentSocInvestigation } from '../engine/agent-soc.js';
import { syncFeodoTrackerC2, syncUrlhausThreats, matchCtiIndicators, updateSuricataRules } from '../engine/cti.js';
import { generateKspmScorecard, saveKspmReport } from '../engine/kspm.js';
import { runPipelineAudit, generateSarifReport } from '../engine/audit.js';
import { listActiveCanaries, generateCanaryServiceAccount, generateCanarySecret, generateDecoyDeploymentYaml, registerCanaryAsset } from '../engine/deception.js';
import { runPurpleTeamSimulation, calculatePurpleScorecard, savePurpleReport } from '../engine/purpleteam.js';
import { generatePatchForFinding, applyPatchToFile, generateUnifiedDiff } from '../engine/remediation.js';
import { queryDataLake, runRetrospectiveThreatHunt, getDataLakeBackend } from '../engine/datalake.js';
import { auditWorkloadIdentity, auditCloudStorageExposure, calculateCloudRiskScore, generateCloudSecReport } from '../engine/cloudsec.js';
import { listCarvedFiles } from '../engine/forensics.js';
import { transpileSigmaToSql, runSigmaThreatHunt } from '../engine/sigma.js';
import { simulateDynamicAttackChain } from '../engine/adversary.js';
import { detectMemoryAnomalies, parseProcessMemoryMaps } from '../engine/memdump.js';
import { generateCloudHoneytoken, startCanaryWebhookListener } from '../engine/deception.js';
import { generateCycloneDxSbom, generateSpdxSbom, verifyCosignSignature } from '../engine/supplychain.js';
import { buildSocketConnectionMatrix, detectAnomalousSocketConnections } from '../engine/observability.js';
import { createFederationNode, signThreatRecord, broadcastThreatIndicator, ingestFederatedThreatRecord } from '../engine/federation.js';
import { generateBpfLsmPolicy, simulateLsmPolicyEvaluation, exportLsmCSource } from '../engine/lsm.js';
import { detectBeaconingPeriodicity, detectDnsTunneling } from '../engine/beaconing.js';
import { calculateFileEntropy, generateRansomwareCanaryFiles, detectRansomwareEncryption } from '../engine/ransomware.js';
import { conveneIncidentWarRoom, generateWarRoomTranscript } from '../engine/warroom.js';
import { semanticThreatSearch } from '../engine/vectorcti.js';
import { appendLedgerEntry, verifyLedgerIntegrity, exportLegalChainOfCustody } from '../engine/ledger.js';
import { calculateBlastRadius, renderAsciiAttackGraph, buildCompositeAttackGraph, findShortestAttackPath } from '../engine/attackgraph.js';
import { parseKallsyms, detectSyscallHooking, detectHiddenModules, analyzeKernelTaint, scanRootkitArtifacts, generateRootkitReport } from '../engine/rootkit.js';
import { compileYaraRule, scanBufferWithRules, extractCobaltStrikeConfig, scanProcessMemory, generateYaraMemoryReport } from '../engine/yarascan.js';
import { buildCausalTimeline, identifyRootCause, calculateDwellTime, renderAsciiTimeline } from '../engine/timeline.js';
import { createSwarmDuel, executeDuelRound, runFullDuelSimulation, evaluateDuelMetrics, generateDuelTranscript } from '../engine/swarmduel.js';
import { generateStixId, parseStixBundle, convertMispToStix, convertStixToMisp, mergeThreatFeeds, filterIndicators } from '../engine/stixmisp.js';
import { startDecoyService, createHoneynetMesh, plantBreadcrumbs } from '../engine/honeynet.js';
import { captureContainerVolatiles, captureContainerDiff, createForensicsSnapshot, verifySnapshotIntegrity, listSavedSnapshots } from '../engine/snapshot.js';
import { generateRfc3161Timestamp, generateChainOfCustodyRecord, createEvidenceBundle, verifyEvidenceBundle } from '../engine/evidencepack.js';
import { dissectEthernetFrame, dissectIpPacket, dissectTcpSegment, dissectUdpDatagram, dissectDnsPayload, dissectTlsPayload, dissectFullPacket, filterPacket, formatHexDump, exportToPcap, generateSyntheticPacketStream } from '../engine/sniffer.js';

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
        },
        {
          uri: 'vigilante://threats',
          name: 'Threat Simulation Playbooks',
          description: 'List of all available built-in and custom attack simulation playbooks with MITRE techniques, severity, and event metadata.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://nist/framework',
          name: 'NIST SP 800-61 Rev. 2 Framework & Taxonomy Reference',
          description: 'Authoritative reference definitions for NIST Attack Vectors, Lifecycle Phases, Order of Volatility, and Impact Scoring.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://nist/incidents',
          name: 'Active NIST SP 800-61 Incident Records',
          description: 'List of all active and archived incident manifests from the Evidence Vault with 3D impact scores and GPG verification.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://topology/svg',
          name: 'NastyMap Headless SVG Network Topology',
          description: 'Vector SVG diagram visualizing live host topology, nodes, traceroute hops, and subnet boundaries.',
          mimeType: 'image/svg+xml'
        },
        {
          uri: 'vigilante://topology/html',
          name: 'NastyMap Standalone Interactive HTML Report',
          description: 'Complete standalone HTML report containing SVG map, host matrix, and service fingerprints.',
          mimeType: 'text/html'
        },
        {
          uri: 'vigilante://kctf/challenges',
          name: 'kCTF Cyber Range Challenges & Templates',
          description: 'List of deployed kCTF challenges and available challenge archetypes (Web, Pwn/nsjail, Crypto, Rev, Forensics, Misc).',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://oob/scans',
          name: 'Saved Out-of-Band (OOB) Scans',
          description: 'List of all archived BMC / IPMI / Redfish out-of-band management scan reports in $XDG_CONFIG_HOME/vigilante/oobscans.',
          mimeType: 'application/json'
        },
        {
          uri: 'vigilante://oob/hashes',
          name: 'IPMI RAKP-2 Hashes Vault',
          description: 'Aggregated RAKP-2 password authentication hashes extracted from IPMI 2.0 services, formatted for Hashcat (-m 7300).',
          mimeType: 'text/plain'
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
        },
        {
          uriTemplate: 'vigilante://oob/scan/{filename}',
          name: 'Out-of-Band Scan Report Details',
          description: 'Parsed BMC hardware inventory, discovered management protocols, CVEs, default credentials, and raw NDJSON events for a specific OOB scan report.',
          mimeType: 'application/json'
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

    // I. Threat Simulation Playbooks
    if (uri === 'vigilante://threats' || uri === 'vigilante://playbooks') {
      const playbooks = await listAvailablePlaybooks();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ count: playbooks.length, playbooks }, null, 2)
          }
        ]
      };
    }

    // J. NIST SP 800-61 Rev. 2 Framework & Taxonomy Reference
    if (uri === 'vigilante://nist/framework' || uri === 'vigilante://nist') {
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              standard: 'NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)',
              lifecyclePhases: NIST_LIFECYCLE_PHASES,
              attackVectors: NIST_ATTACK_VECTORS,
              orderOfVolatility: NIST_EVIDENCE_VOLATILITY,
              impactLevels: NIST_IMPACT_LEVELS
            }, null, 2)
          }
        ]
      };
    }

    // K. Active NIST SP 800-61 Incidents
    if (uri === 'vigilante://nist/incidents') {
      const incidents = await listNistIncidents();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              count: incidents.length,
              incidents
            }, null, 2)
          }
        ]
      };
    }

    // L. NastyMap SVG Topology
    if (uri === 'vigilante://topology/svg') {
      const scans = await listSavedXmlScans();
      if (scans.length === 0) {
        throw new Error('No saved Nmap XML scans found to generate SVG topology.');
      }
      const activeScan = scans[0];
      const graph = generateTopology(activeScan);
      const svg = generateHeadlessSvg(graph, { title: `Vigilante Topology: ${activeScan.target}` });
      return {
        contents: [
          {
            uri,
            mimeType: 'image/svg+xml',
            text: svg
          }
        ]
      };
    }

    // M. NastyMap Standalone Interactive HTML Report
    if (uri === 'vigilante://topology/html') {
      const scans = await listSavedXmlScans();
      if (scans.length === 0) {
        throw new Error('No saved Nmap XML scans found to generate HTML report.');
      }
      const activeScan = scans[0];
      const graph = generateTopology(activeScan);
      const html = generateHtmlReport(activeScan, graph);
      return {
        contents: [
          {
            uri,
            mimeType: 'text/html',
            text: html
          }
        ]
      };
    }

    // N. kCTF Cyber Range Challenges & Templates
    if (uri === 'vigilante://kctf/challenges') {
      const active = await listActiveChallenges({ namespace: 'kctf' });
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({
              count: active.length,
              activeChallenges: active,
              templates: CHALLENGE_TEMPLATES
            }, null, 2)
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

    // OOB Scans List (vigilante://oob/scans)
    if (uri === 'vigilante://oob/scans') {
      const scans = await listSavedOobScans();
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify({ total: scans.length, scans }, null, 2)
          }
        ]
      };
    }

    // OOB RAKP Hashes (vigilante://oob/hashes)
    if (uri === 'vigilante://oob/hashes') {
      const scans = await listSavedOobScans();
      const allHashes = [];
      for (const s of scans) {
        if (s.rakpHashes && s.rakpHashes.length > 0) {
          allHashes.push(...s.rakpHashes.map(h => h.hashcatLine));
        }
      }
      return {
        contents: [
          {
            uri,
            mimeType: 'text/plain',
            text: allHashes.join('\n')
          }
        ]
      };
    }

    // Parameterized URI: OOB Scan Detail (vigilante://oob/scan/{filename})
    const oobScanMatch = uri.match(/^vigilante:\/\/oob\/scan\/([^/]+)$/);
    if (oobScanMatch) {
      const filename = decodeURIComponent(oobScanMatch[1]);
      const scan = await readSavedOobScan(filename);
      return {
        contents: [
          {
            uri,
            mimeType: 'application/json',
            text: JSON.stringify(scan, null, 2)
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
        },
        {
          name: 'list_threat_playbooks',
          description: 'List all built-in and custom threat simulation scenarios with descriptions, MITRE ATT&CK techniques, severity levels, and event counts.',
          inputSchema: {
            type: 'object',
            properties: {
              customDir: {
                type: 'string',
                description: 'Optional custom directory path to scan for user-defined YAML/JSON playbooks'
              }
            }
          }
        },
        {
          name: 'run_threat_simulation',
          description: 'Inject a simulated network threat scenario or custom playbook into OpenSearch SIEM within the Kubernetes cluster.',
          inputSchema: {
            type: 'object',
            properties: {
              scenario: {
                type: 'string',
                description: 'Scenario ID or custom playbook file path (e.g. recon-sweep, credential-bruteforce, dns-tunneling-exfil, ransomware-lateral, k8s-pod-escape, web-cve-rce, arp-poison-mitm)'
              },
              namespace: {
                type: 'string',
                description: 'Target Kubernetes namespace containing OpenSearch SIEM (default: opensearch)'
              },
              clusterName: {
                type: 'string',
                description: 'Target k3d cluster instance name (default: vigilante-dev)'
              }
            },
            required: ['scenario']
          }
        },
        {
          name: 'assess_nist_incident',
          description: 'Perform an authoritative NIST SP 800-61 Rev. 2 incident evaluation for a target host, calculating 3D impact score, attack vector, and containment SLA.',
          inputSchema: {
            type: 'object',
            properties: {
              host: {
                type: 'string',
                description: 'Target compromised or suspicious host IP address (e.g. 10.0.1.15)'
              },
              network: {
                type: 'string',
                description: 'CIDR network subnet containing the host (e.g. 10.0.1.0/24)'
              },
              functionalImpact: {
                type: 'string',
                enum: ['NONE', 'LOW', 'MEDIUM', 'HIGH'],
                description: 'NIST Functional Impact on operational systems (default: MEDIUM)'
              },
              informationImpact: {
                type: 'string',
                enum: ['NONE', 'PRIVACY_BREACH', 'PROPRIETARY_BREACH', 'INTEGRITY_LOSS'],
                description: 'NIST Information Impact on data confidentiality/integrity (default: PRIVACY_BREACH)'
              },
              recoverabilityEffort: {
                type: 'string',
                enum: ['REGULAR', 'SUPPLEMENTED', 'EXTENDED', 'NOT_RECOVERABLE'],
                description: 'NIST Recoverability Effort for CSIRT remediation (default: REGULAR)'
              },
              rootCause: {
                type: 'string',
                description: 'Initial access vector hypothesis or confirmed entry point'
              }
            },
            required: ['host']
          }
        },
        {
          name: 'generate_nist_postmortem',
          description: 'Generate an official NIST SP 800-61 Rev. 2 incident post-mortem markdown report, save it to the Evidence Vault, and optionally sign with GPG.',
          inputSchema: {
            type: 'object',
            properties: {
              host: {
                type: 'string',
                description: 'Target compromised host IP address'
              },
              network: {
                type: 'string',
                description: 'CIDR network subnet (default: 10.0.1.0_24)'
              },
              incidentId: {
                type: 'string',
                description: 'Optional incident ID to associate with the post-mortem report'
              },
              rootCause: {
                type: 'string',
                description: 'Summary of initial access vector and adversary actions'
              }
            },
            required: ['host']
          }
        },
        {
          name: 'diff_nmap_scans',
          description: 'Compare two Nmap XML scans to produce a structured security diff showing added/removed hosts, newly opened ports, service version drifts, and rogue listeners.',
          inputSchema: {
            type: 'object',
            properties: {
              baselineScan: {
                type: 'string',
                description: 'Baseline / older scan filename or full file path (optional, defaults to second latest scan)'
              },
              targetScan: {
                type: 'string',
                description: 'Target / newer scan filename or full file path (optional, defaults to latest scan)'
              }
            }
          }
        },
        {
          name: 'generate_topology_map',
          description: 'Generate a NastyMap SVG diagram or standalone interactive HTML report for an Nmap scan.',
          inputSchema: {
            type: 'object',
            properties: {
              scanFilename: {
                type: 'string',
                description: 'Specific XML scan filename or path (defaults to latest scan)'
              },
              format: {
                type: 'string',
                enum: ['svg', 'html', 'json'],
                description: 'Output format (svg, html, or json topology graph)'
              },
              layout: {
                type: 'string',
                enum: ['force2d', 'radial', 'tree', 'subnet'],
                description: 'Graph topology layout algorithm (default: force2d)'
              }
            }
          }
        },
        {
          name: 'openvas_status',
          description: 'Check health of the OpenVAS / Greenbone Community Edition vulnerability management suite running on the cluster.',
          inputSchema: {
            type: 'object',
            properties: {
              namespace: {
                type: 'string',
                description: 'Kubernetes namespace where OpenVAS is deployed (default: openvas)'
              },
              clusterName: {
                type: 'string',
                description: 'Cluster name (default: vigilante-dev)'
              }
            }
          }
        },
        {
          name: 'run_openvas_scan',
          description: 'Execute an OpenVAS / Greenbone vulnerability scan against a target host IP, return CVE findings with CVSS scores and remediation, and save the report to the evidence vault.',
          inputSchema: {
            type: 'object',
            properties: {
              host: {
                type: 'string',
                description: 'Target host IP address or hostname to audit for vulnerabilities'
              },
              profile: {
                type: 'string',
                enum: ['full-and-fast', 'host-discovery', 'system-discovery', 'web-app-audit', 'critical-cves'],
                description: 'Scan profile (default: full-and-fast)'
              },
              networkTarget: {
                type: 'string',
                description: 'Network CIDR / identifier for evidence saving (default: local_network)'
              },
              namespace: {
                type: 'string',
                description: 'Kubernetes namespace of OpenVAS cluster deployment (default: openvas)'
              }
            },
            required: ['host']
          }
        },
        {
          name: 'list_openvas_reports',
          description: 'List saved OpenVAS vulnerability scan reports and findings from the incident evidence vault.',
          inputSchema: {
            type: 'object',
            properties: {
              networkTarget: {
                type: 'string',
                description: 'Network CIDR identifier (default: local_network)'
              },
              hostIp: {
                type: 'string',
                description: 'Optional host IP address to filter reports'
              }
            }
          }
        },
        {
          name: 'kctf_status',
          description: 'Check health of the Google kCTF challenge platform, CRDs, controller, portal, and active challenge deployments in Kubernetes.',
          inputSchema: {
            type: 'object',
            properties: {
              namespace: {
                type: 'string',
                description: 'Target Kubernetes namespace (default: kctf)'
              },
              clusterName: {
                type: 'string',
                description: 'Cluster name (default: vigilante-dev)'
              }
            }
          }
        },
        {
          name: 'list_ctf_challenges',
          description: 'List all deployed kCTF challenges running in the cluster as well as the complete library of available challenge templates (Web, Pwn with nsjail, Crypto, Rev, Forensics, Misc).',
          inputSchema: {
            type: 'object',
            properties: {
              namespace: {
                type: 'string',
                description: 'Target Kubernetes namespace (default: kctf)'
              },
              clusterName: {
                type: 'string',
                description: 'Cluster name (default: vigilante-dev)'
              }
            }
          }
        },
        {
          name: 'spin_up_challenge',
          description: 'Spin up and deploy a sandboxed CTF challenge (Web, Pwn with nsjail, Crypto, Rev, Forensics, or Misc) into the kCTF Kubernetes cluster namespace.',
          inputSchema: {
            type: 'object',
            properties: {
              templateId: {
                type: 'string',
                description: 'ID of the starter challenge template (e.g. pwn-nsjail-echo, web-flag-leak, crypto-oracle-rsa, misc-pyjail-escape)'
              },
              customName: {
                type: 'string',
                description: 'Optional custom challenge name'
              },
              customCategory: {
                type: 'string',
                enum: ['web', 'pwn', 'crypto', 'rev', 'forensics', 'misc'],
                description: 'Challenge category'
              },
              customPort: {
                type: 'integer',
                description: 'Network port to expose for contestants (e.g. 31337, 8080)'
              },
              customFlag: {
                type: 'string',
                description: 'Custom CTF flag string (e.g. VIGILANTE{...})'
              },
              powDifficultySeconds: {
                type: 'integer',
                description: 'Proof of Work difficulty in seconds (0 = disabled)'
              },
              namespace: {
                type: 'string',
                description: 'Kubernetes namespace (default: kctf)'
              }
            }
          }
        },
        {
          name: 'delete_ctf_challenge',
          description: 'Delete and tear down a deployed kCTF challenge and its Kubernetes deployment, service, and CRD resources.',
          inputSchema: {
            type: 'object',
            properties: {
              challengeName: {
                type: 'string',
                description: 'Name of the challenge to delete'
              },
              namespace: {
                type: 'string',
                description: 'Kubernetes namespace (default: kctf)'
              }
            },
            required: ['challengeName']
          }
        },
        {
          name: 'uninstall_module',
          description: 'Uninstall an individual security or platform module from the Kubernetes cluster (e.g. wazuh, openvas, kctf, opensearch, vigil-soc, vigil-local).',
          inputSchema: {
            type: 'object',
            properties: {
              moduleId: {
                type: 'string',
                description: 'Unique ID of the module to uninstall (e.g. wazuh, openvas, kctf, vigil-soc, opensearch, vigil-local)'
              },
              namespace: {
                type: 'string',
                description: 'Target Kubernetes namespace'
              },
              clusterName: {
                type: 'string',
                description: 'Target cluster name (default: vigilante-dev)'
              },
              deleteNamespace: {
                type: 'boolean',
                description: 'Whether to delete the entire Kubernetes namespace (default: false)'
              }
            },
            required: ['moduleId']
          }
        },
        {
          name: 'reset_module',
          description: 'Reset and cleanly reinstall an individual module in-place without tearing down the cluster or running full up.',
          inputSchema: {
            type: 'object',
            properties: {
              moduleId: {
                type: 'string',
                description: 'Unique ID of the module to reset (e.g. wazuh, openvas, kctf, vigil-soc, opensearch, vigil-local)'
              },
              namespace: {
                type: 'string',
                description: 'Target Kubernetes namespace'
              },
              clusterName: {
                type: 'string',
                description: 'Target cluster name (default: vigilante-dev)'
              },
              domain: {
                type: 'string',
                description: 'Cluster domain (default: vigilante.local)'
              }
            },
            required: ['moduleId']
          }
        },
        {
          name: 'check_oobscan',
          description: 'Check whether the out-of-band management scanner (oobscan) binary is installed on the host and return path and version.',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'run_oob_scan',
          description: 'Run an out-of-band management scan using runZero oobscan against BMCs, IPMI, Redfish, iLO, iDRAC, or IPv6 multicast.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target IP, hostname, CIDR subnet, or IPv6 multicast group (e.g. 192.168.1.0/24 or ff02::1%eth0)'
              },
              profile: {
                type: 'string',
                description: 'Scan profile: quick, standard, ipmi, ipv6, passive',
                enum: ['quick', 'standard', 'ipmi', 'ipv6', 'passive']
              },
              customArgs: {
                type: 'string',
                description: 'Additional custom CLI arguments to pass to oobscan'
              },
              disableLogins: {
                type: 'boolean',
                description: 'Disable default credential checks (safety mode)'
              },
              ipmiFull: {
                type: 'boolean',
                description: 'Enable full IPMI cipher probing and RAKP hash retrieval'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'list_oob_scans',
          description: 'List all saved out-of-band management scans from $XDG_CONFIG_HOME/vigilante/oobscans.',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'get_oob_scan_details',
          description: 'Retrieve full parsed BMC inventory, CVEs, default credentials, and RAKP hashcat lines from a saved OOB scan report.',
          inputSchema: {
            type: 'object',
            properties: {
              scanId: {
                type: 'string',
                description: 'Filename or scan ID of the saved scan (e.g. oob-2026-09-25T12-00-00-000Z.jsonl)'
              }
            },
            required: ['scanId']
          }
        },
        {
          name: 'export_rakp_hashes',
          description: 'Export all IPMI 2.0 RAKP-2 authentication hashes from saved OOB scans into a single Hashcat -m 7300 crackable text file.',
          inputSchema: {
            type: 'object',
            properties: {
              outputFile: {
                type: 'string',
                description: 'Custom output file path (defaults to $XDG_CONFIG_HOME/vigilante/oobscans/hashes_all.txt)'
              }
            }
          }
        },
        {
          name: 'run_recon_scan',
          description: 'High-speed asynchronous port discovery and HTTP service probing using Naabu & Httpx engines.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target IP, hostname, or URL to probe'
              },
              profile: {
                type: 'string',
                enum: ['fast-ports', 'full-ports', 'web-probe', 'deep-recon'],
                description: 'Recon scan profile to execute'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'run_nuclei_scan',
          description: 'Template-driven vulnerability and CVE scanning against targets using the Nuclei engine.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target URL or IP to scan with Nuclei'
              },
              profile: {
                type: 'string',
                enum: ['cves', 'critical-high', 'misconfigs', 'default-logins', 'ssl'],
                description: 'Nuclei scan profile'
              },
              severity: {
                type: 'string',
                description: 'Filter findings by severity (e.g. critical,high,medium)'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'run_trivy_audit',
          description: 'Security audit of container images, Kubernetes workloads, and secret leaks using Trivy.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Container image name (e.g. alpine:latest) or target'
              },
              profile: {
                type: 'string',
                enum: ['image', 'k8s', 'secrets', 'sbom'],
                description: 'Trivy audit profile'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'run_kube_audit',
          description: 'Audit Kubernetes cluster security against CIS benchmarks (Kube-Bench) or penetration test exposure (Kube-Hunter).',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Cluster identifier or node IP (default: cluster)'
              },
              profile: {
                type: 'string',
                enum: ['kube-bench', 'kube-hunter'],
                description: 'KubeAudit profile to run'
              }
            }
          }
        },
        {
          name: 'run_netexec_audit',
          description: 'Network protocol and authentication security audit (SMB signing, null sessions, password policies) using NetExec.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target IP or hostname to audit'
              },
              profile: {
                type: 'string',
                enum: ['smb-signing', 'null-sessions', 'pass-policy', 'protocol-sweep'],
                description: 'NetExec audit profile'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'run_zap_scan',
          description: 'Automated DAST spidering and web application security scanning with OWASP ZAP.',
          inputSchema: {
            type: 'object',
            properties: {
              targetUrl: {
                type: 'string',
                description: 'Target web application URL to crawl and audit'
              },
              profile: {
                type: 'string',
                enum: ['spider', 'active', 'quick'],
                description: 'ZAP scan profile'
              }
            },
            required: ['targetUrl']
          }
        },
        {
          name: 'get_host_dossier',
          description: 'Retrieve or build a Unified Host Dossier ("Vigilante Brain") aggregating Nmap, Naabu, Httpx, Nuclei, Trivy, oobscan, NetExec, ZAP, and runtime alerts into a composite 0-100 risk score.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target IP address or hostname to evaluate'
              },
              refresh: {
                type: 'boolean',
                description: 'Force re-compilation of dossier across local evidence sources'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'replay_pcap',
          description: 'Drop and replay a PCAP file through Vigilante dropzone and dispatch to Suricata/Zeek in-cluster sensor pods for IDS/NSM inspection.',
          inputSchema: {
            type: 'object',
            properties: {
              pcapFilePath: {
                type: 'string',
                description: 'Local file path to .pcap or .pcapng recording'
              },
              namespace: {
                type: 'string',
                description: 'Kubernetes namespace where Suricata and Zeek run (default: vigilante)'
              }
            },
            required: ['pcapFilePath']
          }
        },
        {
          name: 'ingest_bloodhound_data',
          description: 'Ingest BloodHound / SharpHound Active Directory JSON data, identify privilege escalation paths, and cross-correlate against Flamingo captured credentials.',
          inputSchema: {
            type: 'object',
            properties: {
              filePath: {
                type: 'string',
                description: 'Path to SharpHound JSON export (users.json, computers.json, or zip extract)'
              }
            },
            required: ['filePath']
          }
        },
        {
          name: 'generate_mitre_report',
          description: 'Generate comprehensive MITRE ATT&CK coverage matrix and gap analysis comparing simulation playbooks and deployed sensors (Suricata, Zeek, Falco, Wazuh).',
          inputSchema: {
            type: 'object',
            properties: {
              saveEvidence: {
                type: 'boolean',
                description: 'Save signed JSON and Markdown evidence records (default: true)'
              }
            }
          }
        },
        {
          name: 'isolate_workload',
          description: 'Apply an immediate zero-trust quarantine NetworkPolicy to a Kubernetes pod, severing all ingress and egress.',
          inputSchema: {
            type: 'object',
            properties: {
              podName: {
                type: 'string',
                description: 'Name of the compromised Kubernetes pod'
              },
              namespace: {
                type: 'string',
                description: 'Target Kubernetes namespace (default: default)'
              },
              reason: {
                type: 'string',
                description: 'Operational justification for emergency containment'
              }
            },
            required: ['podName']
          }
        },
        {
          name: 'release_isolation',
          description: 'Release an active SOAR containment policy on a Kubernetes pod or IP.',
          inputSchema: {
            type: 'object',
            properties: {
              containmentId: {
                type: 'string',
                description: 'Unique containment ID (e.g. cont-...) to revoke'
              }
            },
            required: ['containmentId']
          }
        },
        {
          name: 'investigate_incident',
          description: 'Trigger autonomous ReAct Agentic SOC investigation loop with tool-use, MITRE mapping, automated containment, and signed NIST post-mortem artifact creation.',
          inputSchema: {
            type: 'object',
            properties: {
              target: {
                type: 'string',
                description: 'Target IP, hostname, or Kubernetes pod name'
              },
              incidentId: {
                type: 'string',
                description: 'Optional incident identifier (auto-generated if omitted)'
              },
              triggerAlert: {
                type: 'object',
                description: 'Alert metadata including source, title, severity, details'
              },
              automatedContainment: {
                type: 'boolean',
                description: 'Whether to automatically isolate target if classified as CRITICAL (default: true)'
              }
            },
            required: ['target']
          }
        },
        {
          name: 'query_cti',
          description: 'Check indicators of compromise (IPs, domains, hashes) against synchronized Feodo C2, URLhaus, and Emerging Threats threat intelligence.',
          inputSchema: {
            type: 'object',
            properties: {
              indicators: {
                type: 'array',
                items: { type: 'string' },
                description: 'List of IP addresses, hostnames, or URLs to evaluate'
              }
            },
            required: ['indicators']
          }
        },
        {
          name: 'generate_kspm_scorecard',
          description: 'Evaluate live Kubernetes workloads against CIS Benchmarks and Pod Security Standards (PSS), generating posture grade, score, and remediation steps.',
          inputSchema: {
            type: 'object',
            properties: {
              namespace: {
                type: 'string',
                description: 'Kubernetes namespace filter (optional)'
              },
              saveEvidence: {
                type: 'boolean',
                description: 'Save signed JSON and Markdown evidence records (default: true)'
              }
            }
          }
        },
        {
          name: 'run_pipeline_audit',
          description: 'Execute shift-left security audit across Kubernetes manifests, Helm templates, and Dockerfiles with SARIF v2.1.0 output and policy failure gating.',
          inputSchema: {
            type: 'object',
            properties: {
              targetPath: {
                type: 'string',
                description: 'Path to directory or manifest file to audit (default: .)'
              },
              failOn: {
                type: 'string',
                enum: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                description: 'Severity threshold that triggers a failed gate (default: HIGH)'
              }
            },
            required: ['targetPath']
          }
        },
        {
          name: 'list_canary_tokens',
          description: 'Enumerate all active deception canary assets (ServiceAccounts, Secrets, and network honeypots) with trip status.',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'deploy_canary_asset',
          description: 'Deploy a new deception asset: decoy ServiceAccount (sa), deceptive credentials Secret (secret), or honeypot (decoy).',
          inputSchema: {
            type: 'object',
            properties: {
              type: {
                type: 'string',
                enum: ['sa', 'secret', 'decoy'],
                description: 'Type of canary to deploy'
              },
              name: {
                type: 'string',
                description: 'Name of the canary asset'
              },
              namespace: {
                type: 'string',
                description: 'Target namespace (default: default)'
              }
            },
            required: ['type']
          }
        },
        {
          name: 'run_purple_simulation',
          description: 'Execute an autonomous adversarial Purple Team wargame simulation between Red Adversary and Blue ReAct SOC.',
          inputSchema: {
            type: 'object',
            properties: {
              scenario: {
                type: 'string',
                enum: ['lateral-smb-exfil', 'container-escape-privileged'],
                description: 'Adversary scenario to execute (default: lateral-smb-exfil)'
              }
            }
          }
        },
        {
          name: 'auto_remediate_finding',
          description: 'Generate an automated unified patch for a Kubernetes manifest or Dockerfile finding, hardening securityContext and pinning images.',
          inputSchema: {
            type: 'object',
            properties: {
              finding: {
                type: 'object',
                description: 'Finding object { ruleId, message }'
              },
              fileContent: {
                type: 'string',
                description: 'Raw content of the file to remediate'
              },
              fileType: {
                type: 'string',
                enum: ['k8s', 'dockerfile'],
                description: 'Format of the file'
              }
            },
            required: ['finding', 'fileContent']
          }
        },
        {
          name: 'query_security_datalake',
          description: 'Execute high-performance analytical SQL query across ingested security telemetry events (Falco, Zeek, Suricata, Audit).',
          inputSchema: {
            type: 'object',
            properties: {
              sql: {
                type: 'string',
                description: 'SQL query to execute (e.g. SELECT event_type, count(*) FROM security_events GROUP BY event_type)'
              }
            },
            required: ['sql']
          }
        },
        {
          name: 'audit_cloud_security',
          description: 'Audit multi-cloud workload identity (AWS IRSA, GCP Workload Identity, Azure Client ID) and cloud bucket posture.',
          inputSchema: {
            type: 'object',
            properties: {
              workloads: {
                type: 'array',
                description: 'Optional list of K8s workload manifests to audit'
              },
              storageConfigs: {
                type: 'array',
                description: 'Optional list of bucket configurations to audit'
              }
            }
          }
        },
        {
          name: 'transpile_sigma_to_sql',
          description: 'Transpile SIGMA YAML or JSON detection rule into ANSI SQL query for SQLite or DuckDB.',
          inputSchema: {
            type: 'object',
            properties: {
              rule: {
                type: 'string',
                description: 'SIGMA rule YAML or JSON string or file path'
              },
              targetBackend: {
                type: 'string',
                enum: ['sqlite', 'duckdb'],
                description: 'Target database SQL dialect (default: sqlite)'
              }
            },
            required: ['rule']
          }
        },
        {
          name: 'run_sigma_threat_hunt',
          description: 'Execute automated SIGMA rule threat hunt against historical telemetry in the Security Data Lake.',
          inputSchema: {
            type: 'object',
            properties: {
              rule: {
                type: 'string',
                description: 'SIGMA rule YAML/JSON string or object'
              },
              targetBackend: {
                type: 'string',
                enum: ['sqlite', 'duckdb'],
                description: 'SQL backend engine'
              }
            },
            required: ['rule']
          }
        },
        {
          name: 'run_dynamic_adversary_simulation',
          description: 'Simulate multi-step dynamic adversary attack chain traversing BloodHound identity paths and evaluating resilience.',
          inputSchema: {
            type: 'object',
            properties: {
              attackGraph: {
                type: 'object',
                description: 'BloodHound graph nodes and edges'
              },
              targetPrincipal: {
                type: 'string',
                description: 'High-value target principal (e.g. DOMAIN ADMINS)'
              },
              autoContain: {
                type: 'boolean',
                description: 'Trigger automated SOAR containment upon compromise'
              }
            },
            required: ['attackGraph', 'targetPrincipal']
          }
        },
        {
          name: 'inspect_process_memory',
          description: 'Perform live in-memory triage of process maps (/proc/$PID/maps), detecting RWX regions, unlinked binaries, and fileless execution.',
          inputSchema: {
            type: 'object',
            properties: {
              pid: {
                type: 'number',
                description: 'Target process ID to inspect'
              },
              mapsContent: {
                type: 'string',
                description: 'Optional raw /proc/$PID/maps text content'
              }
            },
            required: ['pid']
          }
        },
        {
          name: 'generate_cloud_honeytoken',
          description: 'Generate realistic decoy cloud credentials (AWS STS, GitHub PAT, Slack webhook, Kubeconfig) to lure adversaries.',
          inputSchema: {
            type: 'object',
            properties: {
              provider: {
                type: 'string',
                enum: ['aws', 'github', 'slack', 'kubeconfig'],
                description: 'Cloud honeytoken credential provider'
              },
              accountId: {
                type: 'string',
                description: 'Optional AWS account ID or org'
              }
            },
            required: ['provider']
          }
        },
        {
          name: 'start_canary_webhook_listener',
          description: 'Start in-process HTTP webhook honeytoken trap server to catch live decoy triggers.',
          inputSchema: {
            type: 'object',
            properties: {
              port: {
                type: 'number',
                description: 'Port to bind canary listener (default: 9099)'
              },
              webhookPath: {
                type: 'string',
                description: 'URL path for canary trap (default: /api/v1/trap)'
              }
            }
          }
        },
        {
          name: 'generate_container_sbom',
          description: 'Generate standard CycloneDX v1.5 or SPDX v2.3 Software Bill of Materials (SBOM) for containers.',
          inputSchema: {
            type: 'object',
            properties: {
              format: {
                type: 'string',
                enum: ['cyclonedx', 'spdx'],
                description: 'SBOM format standard (default: cyclonedx)'
              },
              manifests: {
                type: 'array',
                description: 'List of package manifests or dependency items'
              },
              componentName: {
                type: 'string',
                description: 'Container or component name'
              }
            }
          }
        },
        {
          name: 'verify_cosign_signature',
          description: 'Verify digital signatures and Rekor transparency log receipts on container images using Cosign/Sigstore.',
          inputSchema: {
            type: 'object',
            properties: {
              imageDigest: {
                type: 'string',
                description: 'Container image digest (e.g. sha256:...)'
              },
              signaturePayload: {
                type: 'object',
                description: 'Cosign signature envelope containing payload and signature'
              },
              publicKeyPem: {
                type: 'string',
                description: 'Cosign public key in PEM format'
              }
            },
            required: ['imageDigest', 'signaturePayload', 'publicKeyPem']
          }
        },
        {
          name: 'get_socket_connection_matrix',
          description: 'Build real-time socket connection matrix and detect anomalous lateral connections and C2 egress.',
          inputSchema: {
            type: 'object',
            properties: {
              networkEvents: {
                type: 'array',
                description: 'Optional list of raw network socket events to aggregate'
              }
            }
          }
        },
        {
          name: 'render_mitre_heatmap',
          description: 'Render ANSI colored MITRE ATT&CK coverage heatmap grid with detection gap analysis.',
          inputSchema: {
            type: 'object',
            properties: {
              coverageMap: {
                type: 'object',
                description: 'Optional MITRE coverage mapping'
              }
            }
          }
        },
        {
          name: 'broadcast_mesh_threat',
          description: 'Cryptographically sign and broadcast a threat indicator across multi-cluster defense federation mesh.',
          inputSchema: {
            type: 'object',
            properties: {
              indicator: {
                type: 'string',
                description: 'Malicious IP, domain, hash, or container signature'
              },
              type: {
                type: 'string',
                description: 'Threat type (e.g. IP, DOMAIN, HASH)'
              },
              severity: {
                type: 'string',
                enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
                description: 'Severity level'
              },
              reason: {
                type: 'string',
                description: 'Detection reason or trigger context'
              },
              peers: {
                type: 'array',
                description: 'Optional list of peer node addresses'
              }
            },
            required: ['indicator']
          }
        },
        {
          name: 'get_mesh_peers_status',
          description: 'Inspect status of multi-cluster federation defense mesh and local Ed25519 node identity.',
          inputSchema: {
            type: 'object',
            properties: {}
          }
        },
        {
          name: 'synthesize_bpf_lsm_policy',
          description: 'Synthesize Linux Security Module (eBPF LSM) declarative security rules into C kernel hooks or YAML policies.',
          inputSchema: {
            type: 'object',
            properties: {
              rules: { type: 'array', description: 'Array of rule objects defining bprm, file_open, or socket_connect constraints' },
              format: { type: 'string', description: 'Output format: yaml or c', default: 'yaml' }
            }
          }
        },
        {
          name: 'evaluate_bpf_lsm_event',
          description: 'Simulate high-speed evaluation of process execution or file open event against synthesized LSM policies.',
          inputSchema: {
            type: 'object',
            properties: {
              policy: { type: 'object', description: 'Synthesized LSM policy object' },
              event: { type: 'object', description: 'Security event with comm, uid, path, destPort, etc.' }
            },
            required: ['event']
          }
        },
        {
          name: 'detect_c2_beaconing',
          description: 'Statistical C2 beaconing and discrete Fourier transform (DFT) periodicity detector for network connection intervals.',
          inputSchema: {
            type: 'object',
            properties: {
              intervals: { type: 'array', description: 'Array of inter-arrival timestamp deltas or event timestamps' },
              jitterPercent: { type: 'number', description: 'Expected beacon jitter tolerance percentage (default: 15)' }
            },
            required: ['intervals']
          }
        },
        {
          name: 'detect_dns_tunneling',
          description: 'Detect covert data exfiltration and DNS tunneling using Shannon entropy analysis on query domains.',
          inputSchema: {
            type: 'object',
            properties: {
              queries: { type: 'array', description: 'Array of domain string queries or DNS event objects' },
              entropyThreshold: { type: 'number', description: 'Entropy threshold (default: 4.0)' }
            },
            required: ['queries']
          }
        },
        {
          name: 'scan_file_entropy',
          description: 'Calculate 8-bit Shannon entropy across file bytes to detect ransomware encryption spikes or encrypted payloads.',
          inputSchema: {
            type: 'object',
            properties: {
              content: { type: 'string', description: 'String or base64 file content' },
              filePath: { type: 'string', description: 'Path to file on disk to evaluate' }
            }
          }
        },
        {
          name: 'deploy_ransomware_canaries',
          description: 'Deploy honeypot canary decoy files with known entropy baseline to detect ransomware encryption attempts.',
          inputSchema: {
            type: 'object',
            properties: {
              targetDirectory: { type: 'string', description: 'Directory to plant canary files in' },
              count: { type: 'number', description: 'Number of canaries to plant (default: 4)' }
            }
          }
        },
        {
          name: 'convene_agent_warroom',
          description: 'Convene an autonomous multi-agent incident war room (Forensics, Threat Intel, SRE Blast Radius, Incident Commander) to debate consensus containment verdict.',
          inputSchema: {
            type: 'object',
            properties: {
              incidentId: { type: 'string', description: 'Unique incident ID' },
              evidence: { type: 'object', description: 'Incident evidence, alerts, or telemetry' },
              quorumThreshold: { type: 'number', description: 'Quorum consensus percentage (default: 75)' }
            }
          }
        },
        {
          name: 'search_semantic_cti',
          description: 'Perform air-gapped semantic vector search across MITRE ATT&CK techniques and Sigma rules.',
          inputSchema: {
            type: 'object',
            properties: {
              query: { type: 'string', description: 'Natural language threat description or query' },
              topK: { type: 'number', description: 'Number of ranked matches to return (default: 5)' }
            },
            required: ['query']
          }
        },
        {
          name: 'append_audit_ledger',
          description: 'Append an immutable, SHA-256 hash-chained entry to the cryptographic evidence ledger.',
          inputSchema: {
            type: 'object',
            properties: {
              entryType: { type: 'string', description: 'Type of audit record (e.g. INCIDENT_VERDICT, CONTAINMENT_ACTION)' },
              payload: { type: 'object', description: 'Evidence or event payload' },
              signerRole: { type: 'string', description: 'Signer role (default: IncidentCommander)' }
            },
            required: ['entryType', 'payload']
          }
        },
        {
          name: 'verify_ledger_integrity',
          description: 'Traverse the cryptographic Merkle ledger to verify hash chaining, signatures, and tamper-free audit integrity.',
          inputSchema: {
            type: 'object',
            properties: {
              ledgerDir: { type: 'string', description: 'Ledger directory to verify (default: .vigilante/ledger)' }
            }
          }
        },
        {
          name: 'calculate_attack_blast_radius',
          description: 'Calculate downstream blast radius impact and discover shortest pivot paths to high-value Crown Jewels from a compromised asset.',
          inputSchema: {
            type: 'object',
            properties: {
              nodeId: { type: 'string', description: 'Node ID in the attack graph (e.g. ext-attacker, web-frontend, api-gateway)' }
            },
            required: ['nodeId']
          }
        },
        {
          name: 'render_terminal_attack_graph',
          description: 'Render ANSI/ASCII terminal composite attack graph with colored node tiers and highlighted shortest attack paths.',
          inputSchema: {
            type: 'object',
            properties: {
              highlightFrom: { type: 'string', description: 'Optional starting node to trace path' },
              highlightTo: { type: 'string', description: 'Optional target crown jewel node to trace path' }
            }
          }
        },
        {
          name: 'scan_kernel_rootkits',
          description: 'Audit Linux kernel symbols, detect syscall table hooking, check hidden LKM modules, and decode kernel taint bitmasks.',
          inputSchema: {
            type: 'object',
            properties: {
              kallsymsContent: { type: 'string', description: 'Optional raw /proc/kallsyms content' },
              procModulesContent: { type: 'string', description: 'Optional raw /proc/modules content' },
              sysModuleList: { type: 'array', description: 'Optional list of /sys/module names' },
              taintValue: { type: 'number', description: 'Optional /proc/sys/kernel/tainted bitmask value' }
            }
          }
        },
        {
          name: 'scan_process_yara',
          description: 'Scan process memory or binary buffer using YARA rules supporting text, hex wildcards, and boolean conditions.',
          inputSchema: {
            type: 'object',
            properties: {
              pid: { type: 'number', description: 'Target process ID' },
              rule: { type: 'string', description: 'YARA rule definition string or rule object' },
              bufferBase64: { type: 'string', description: 'Optional base64 memory buffer' }
            },
            required: ['rule']
          }
        },
        {
          name: 'extract_cobaltstrike_config',
          description: 'Locate, decrypt, and parse Cobalt Strike Beacon configuration blocks (XOR 0x2e/0x69) from memory dump.',
          inputSchema: {
            type: 'object',
            properties: {
              bufferBase64: { type: 'string', description: 'Base64 encoded process memory buffer or raw dump' }
            },
            required: ['bufferBase64']
          }
        },
        {
          name: 'synthesize_attack_dag',
          description: 'Synthesize multi-modal incident causality DAG, pinpoint initial root cause, and calculate attacker dwell time.',
          inputSchema: {
            type: 'object',
            properties: {
              events: { type: 'array', description: 'Array of security alert/telemetry event objects' }
            },
            required: ['events']
          }
        },
        {
          name: 'run_swarm_duel',
          description: 'Simulate autonomous Red Team vs Blue Team cyber range battle with MTTD/MTTR metrics and round transcripts.',
          inputSchema: {
            type: 'object',
            properties: {
              maxRounds: { type: 'number', description: 'Maximum rounds to simulate (default: 5)' },
              crownJewel: { type: 'string', description: 'Target asset name' },
              stealthMode: { type: 'boolean', description: 'Enable stealthy APT mode' }
            }
          }
        },
        {
          name: 'import_stix_bundle',
          description: 'Parse, validate, and extract indicators and relationships from an OASIS STIX 2.1 JSON threat intelligence bundle.',
          inputSchema: {
            type: 'object',
            properties: {
              bundleJson: { type: 'string', description: 'STIX 2.1 JSON bundle string or object' }
            },
            required: ['bundleJson']
          }
        },
        {
          name: 'convert_misp_event',
          description: 'Bidirectional conversion between MISP 2.4 Event JSON and STIX 2.1 Threat Intelligence Bundle.',
          inputSchema: {
            type: 'object',
            properties: {
              data: { type: 'object', description: 'MISP Event object or STIX Bundle object' },
              direction: { type: 'string', description: 'misp_to_stix or stix_to_misp', default: 'misp_to_stix' }
            },
            required: ['data']
          }
        },
        {
          name: 'deploy_honeynet_mesh',
          description: 'Spin up ephemeral high/low-interaction deception services (SSH, Redis, HTTP) and configure trap listeners.',
          inputSchema: {
            type: 'object',
            properties: {
              services: { type: 'array', description: 'Array of services to spin up: SSH, REDIS, HTTP' }
            }
          }
        },
        {
          name: 'plant_deception_breadcrumbs',
          description: 'Plant high-attractiveness canary breadcrumbs (fake AWS credentials, Kubeconfig, bash history lures).',
          inputSchema: {
            type: 'object',
            properties: {
              targetDir: { type: 'string', description: 'Directory to place breadcrumb lure files' },
              types: { type: 'array', description: 'Breadcrumb types: aws, kube, history' }
            },
            required: ['targetDir']
          }
        },
        {
          name: 'capture_container_snapshot',
          description: 'Capture live container volatile memory state, overlayfs upper disk differential, and create sealed forensic archive.',
          inputSchema: {
            type: 'object',
            properties: {
              podName: { type: 'string', description: 'Kubernetes pod name' },
              containerId: { type: 'string', description: 'Container ID' },
              pid: { type: 'number', description: 'Target process PID' },
              rootfsDir: { type: 'string', description: 'Optional overlayfs upper rootfs directory' }
            },
            required: ['podName']
          }
        },
        {
          name: 'export_rfc3161_evidence_pack',
          description: 'Export ISO/IEC 27037 and RFC 3161 compliant court-admissible forensic evidence bundle with offline verifiers.',
          inputSchema: {
            type: 'object',
            properties: {
              caseNumber: { type: 'string', description: 'Legal case number' },
              title: { type: 'string', description: 'Incident case title' },
              evidenceItems: { type: 'array', description: 'Array of evidence item objects: { filename, content, type }' }
            },
            required: ['caseNumber', 'evidenceItems']
          }
        },
        {
          name: 'dissect_network_packet',
          description: 'Dissect raw network packet bytes through Ethernet II, IPv4, TCP/UDP, DNS, and TLS protocol layers.',
          inputSchema: {
            type: 'object',
            properties: {
              packetHex: { type: 'string', description: 'Hex-encoded raw network packet bytes' }
            },
            required: ['packetHex']
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

    // Tool: list_threat_playbooks
    if (name === 'list_threat_playbooks') {
      const { customDir } = args;
      const playbooks = await listAvailablePlaybooks({ customDir });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ count: playbooks.length, playbooks }, null, 2)
          }
        ]
      };
    }

    // Tool: run_threat_simulation
    if (name === 'run_threat_simulation') {
      const { scenario, namespace = 'opensearch', clusterName = 'vigilante-dev' } = args;
      const logs = [];
      const result = await executeThreatPlaybook({
        playbook: scenario,
        namespace,
        clusterName,
        onLog: (msg) => logs.push(msg)
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              success: result.success,
              scenarioId: result.playbook?.id,
              scenarioName: result.playbook?.name,
              eventsIngested: result.eventsCount,
              namespace: result.namespace,
              logs
            }, null, 2)
          }
        ]
      };
    }

    // Tool: assess_nist_incident
    if (name === 'assess_nist_incident') {
      const {
        host,
        network = '10.0.1.0_24',
        functionalImpact = 'MEDIUM',
        informationImpact = 'PRIVACY_BREACH',
        recoverabilityEffort = 'REGULAR',
        rootCause = 'Evaluated via MCP assess_nist_incident tool'
      } = args;

      const record = generateNistIncidentRecord({
        host,
        network,
        functionalImpact,
        informationImpact,
        recoverabilityEffort,
        rootCause
      });

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(record, null, 2)
          }
        ]
      };
    }

    // Tool: generate_nist_postmortem
    if (name === 'generate_nist_postmortem') {
      const {
        host,
        network = '10.0.1.0_24',
        incidentId = null,
        rootCause = 'Incident evaluated and contained'
      } = args;

      const record = generateNistIncidentRecord({
        incidentId,
        host,
        network,
        rootCause
      });

      const markdown = generateNistPostMortemMarkdown(record);
      const saveRes = await saveEvidenceFile(network, host, `postmortem-${record.incidentId}.md`, markdown);

      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              incidentId: record.incidentId,
              filePath: saveRes.filePath,
              isSigned: saveRes.isSigned,
              signaturePath: saveRes.signaturePath,
              markdownReport: markdown
            }, null, 2)
          }
        ]
      };
    }

    // Tool: diff_nmap_scans
    if (name === 'diff_nmap_scans') {
      const { baselineScan, targetScan } = args;
      const scans = await listSavedXmlScans();
      if (scans.length < 2 && (!baselineScan || !targetScan)) {
        throw new Error('At least 2 saved Nmap XML scans are required to compute a security diff.');
      }

      let scanA = null;
      let scanB = null;

      if (baselineScan) {
        scanA = scans.find(s => s.filePath === baselineScan || s.filename === baselineScan || s.id === baselineScan);
        if (!scanA) {
          const raw = await readXmlScan(baselineScan);
          scanA = raw;
        }
      } else {
        scanA = scans[1];
      }

      if (targetScan) {
        scanB = scans.find(s => s.filePath === targetScan || s.filename === targetScan || s.id === targetScan);
        if (!scanB) {
          const raw = await readXmlScan(targetScan);
          scanB = raw;
        }
      } else {
        scanB = scans[0];
      }

      const diff = compareNmapScans(scanA, scanB);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(diff, null, 2)
          }
        ]
      };
    }

    // Tool: generate_topology_map
    if (name === 'generate_topology_map') {
      const { scanFilename, format = 'svg', layout = 'force2d' } = args;
      const scans = await listSavedXmlScans();
      if (scans.length === 0 && !scanFilename) {
        throw new Error('No saved Nmap XML scans found to generate topology map.');
      }

      let scan = scans[0];
      if (scanFilename) {
        const found = scans.find(s => s.filePath === scanFilename || s.filename === scanFilename || s.id === scanFilename);
        if (found) scan = found;
        else scan = await readXmlScan(scanFilename);
      }

      const graph = generateTopology(scan, { layout });

      if (format === 'json') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(graph, null, 2)
            }
          ]
        };
      }

      if (format === 'html') {
        const html = generateHtmlReport(scan, graph);
        return {
          content: [
            {
              type: 'text',
              text: html
            }
          ]
        };
      }

      // Default: SVG
      const svg = generateHeadlessSvg(graph, { title: `Vigilante Topology: ${scan.target}` });
      return {
        content: [
          {
            type: 'text',
            text: svg
          }
        ]
      };
    }

    // Tool: openvas_status
    if (name === 'openvas_status') {
      const { namespace = 'openvas', clusterName = 'vigilante-dev' } = args;
      const status = await checkOpenVasStatus({ namespace, clusterName });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(status, null, 2)
          }
        ]
      };
    }

    // Tool: run_openvas_scan
    if (name === 'run_openvas_scan') {
      const { host, profile = 'full-and-fast', networkTarget = 'local_network', namespace = 'openvas' } = args;
      if (!host) {
        throw new Error("Argument 'host' is required.");
      }
      const scanResult = await runHostVulnerabilityScan({
        host,
        profile,
        networkTarget,
        namespace
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(scanResult, null, 2)
          }
        ]
      };
    }

    // Tool: list_openvas_reports
    if (name === 'list_openvas_reports') {
      const { networkTarget = 'local_network', hostIp = null } = args;
      const reports = await listSavedOpenVasReports(networkTarget, hostIp);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(reports, null, 2)
          }
        ]
      };
    }

    // Tool: kctf_status
    if (name === 'kctf_status') {
      const { namespace = 'kctf', clusterName = 'vigilante-dev' } = args;
      const challenges = await listActiveChallenges({ namespace, clusterName });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              namespace,
              clusterName,
              activeCount: challenges.length,
              challenges
            }, null, 2)
          }
        ]
      };
    }

    // Tool: list_ctf_challenges
    if (name === 'list_ctf_challenges') {
      const { namespace = 'kctf', clusterName = 'vigilante-dev' } = args;
      const active = await listActiveChallenges({ namespace, clusterName });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              activeChallenges: active,
              availableTemplates: CHALLENGE_TEMPLATES
            }, null, 2)
          }
        ]
      };
    }

    // Tool: spin_up_challenge
    if (name === 'spin_up_challenge') {
      const {
        templateId = 'pwn-nsjail-echo',
        customName = null,
        customCategory = null,
        customPort = null,
        customFlag = null,
        powDifficultySeconds = 0,
        namespace = 'kctf'
      } = args;
      const result = await spinUpChallenge({
        templateId,
        customName,
        customCategory,
        customPort,
        customFlag,
        powDifficultySeconds,
        namespace
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: delete_ctf_challenge
    if (name === 'delete_ctf_challenge') {
      const { challengeName, namespace = 'kctf' } = args;
      if (!challengeName) {
        throw new Error("Argument 'challengeName' is required.");
      }
      const result = await deleteChallenge({ challengeName, namespace });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: uninstall_module
    if (name === 'uninstall_module') {
      const { moduleId, namespace = 'default', clusterName = 'vigilante-dev', deleteNamespace = false } = args;
      if (!moduleId) {
        throw new Error("Argument 'moduleId' is required.");
      }
      const result = await globalModuleRegistry.uninstallModule({
        moduleId,
        namespace,
        clusterName,
        deleteNamespace
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: reset_module
    if (name === 'reset_module') {
      const { moduleId, namespace = 'default', clusterName = 'vigilante-dev', domain = 'vigilante.local' } = args;
      if (!moduleId) {
        throw new Error("Argument 'moduleId' is required.");
      }
      const result = await globalModuleRegistry.resetModule({
        moduleId,
        domain,
        namespace,
        clusterName
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: check_oobscan
    if (name === 'check_oobscan') {
      const status = await checkOobscanInstalled();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(status, null, 2)
          }
        ]
      };
    }

    // Tool: run_oob_scan
    if (name === 'run_oob_scan') {
      const { target, profile = 'standard', customArgs = '', disableLogins = false, ipmiFull = true } = args;
      if (!target) {
        throw new Error("Argument 'target' is required.");
      }
      const scanResult = await runOobScan({
        target,
        profile,
        customArgs,
        disableLogins,
        ipmiFull
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(scanResult, null, 2)
          }
        ]
      };
    }

    // Tool: list_oob_scans
    if (name === 'list_oob_scans') {
      const scans = await listSavedOobScans();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ total: scans.length, scans }, null, 2)
          }
        ]
      };
    }

    // Tool: get_oob_scan_details
    if (name === 'get_oob_scan_details') {
      const { scanId } = args;
      if (!scanId) {
        throw new Error("Argument 'scanId' is required.");
      }
      const details = await readSavedOobScan(scanId);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(details, null, 2)
          }
        ]
      };
    }

    // Tool: export_rakp_hashes
    if (name === 'export_rakp_hashes') {
      const result = await exportRakpHashes(args.outputFile);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: run_recon_scan
    if (name === 'run_recon_scan') {
      const { target, profile = 'fast-ports' } = args;
      if (!target) throw new Error("Argument 'target' is required.");
      const result = await runReconScan(target, profile);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'success',
              id: result.id,
              target: result.target,
              profile: result.profile,
              openPorts: result.openPorts,
              webServices: result.webServices,
              filePath: result.filePath
            }, null, 2)
          }
        ]
      };
    }

    // Tool: run_nuclei_scan
    if (name === 'run_nuclei_scan') {
      const { target, profile = 'cves', severity } = args;
      if (!target) throw new Error("Argument 'target' is required.");
      const result = await runNucleiScan(target, profile, { severity });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'success',
              id: result.id,
              target: result.target,
              profile: result.profile,
              stats: result.stats,
              findingsCount: result.findings.length,
              findingsSample: result.findings.slice(0, 10),
              filePath: result.filePath
            }, null, 2)
          }
        ]
      };
    }

    // Tool: run_trivy_audit
    if (name === 'run_trivy_audit') {
      const { target, profile = 'image' } = args;
      if (!target) throw new Error("Argument 'target' is required.");
      const result = await runTrivyAudit(target, profile);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'success',
              id: result.id,
              target: result.target,
              profile: result.profile,
              summary: result.summary,
              vulnerabilitiesCount: result.vulnerabilities.length,
              misconfigurationsCount: result.misconfigurations.length,
              secretsCount: result.secrets.length,
              filePath: result.filePath
            }, null, 2)
          }
        ]
      };
    }

    // Tool: run_kube_audit
    if (name === 'run_kube_audit') {
      const { target = 'cluster', profile = 'kube-bench' } = args;
      const result = await runKubeAudit(target, profile);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'success',
              id: result.id,
              target: result.target,
              tool: result.tool,
              profile: result.profile,
              totals: result.totals,
              filePath: result.filePath
            }, null, 2)
          }
        ]
      };
    }

    // Tool: run_netexec_audit
    if (name === 'run_netexec_audit') {
      const { target, profile = 'smb-signing' } = args;
      if (!target) throw new Error("Argument 'target' is required.");
      const result = await runNetexecAudit(target, profile);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'success',
              id: result.id,
              target: result.target,
              profile: result.profile,
              findingsCount: result.findings.length,
              findings: result.findings,
              filePath: result.filePath
            }, null, 2)
          }
        ]
      };
    }

    // Tool: run_zap_scan
    if (name === 'run_zap_scan') {
      const { targetUrl, profile = 'spider' } = args;
      if (!targetUrl) throw new Error("Argument 'targetUrl' is required.");
      const result = await runZapScan(targetUrl, profile);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              status: 'success',
              id: result.id,
              target: result.target,
              profile: result.profile,
              alertsCount: result.alerts.length,
              alerts: result.alerts,
              filePath: result.filePath
            }, null, 2)
          }
        ]
      };
    }

    // Tool: get_host_dossier
    if (name === 'get_host_dossier') {
      const { target, refresh = false } = args;
      if (!target) throw new Error("Argument 'target' is required.");
      const dossier = refresh ? await buildHostDossier(target) : await getHostDossier(target);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(dossier, null, 2)
          }
        ]
      };
    }

    // Tool: replay_pcap
    if (name === 'replay_pcap') {
      const { pcapFilePath, namespace = 'vigilante' } = args;
      if (!pcapFilePath) throw new Error("Argument 'pcapFilePath' is required.");
      const result = await replayPcap(pcapFilePath, { namespace });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: ingest_bloodhound_data
    if (name === 'ingest_bloodhound_data') {
      const { filePath } = args;
      if (!filePath) throw new Error("Argument 'filePath' is required.");
      const result = await ingestBloodhoundData(filePath);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: generate_mitre_report
    if (name === 'generate_mitre_report') {
      const { saveEvidence = true } = args;
      const result = saveEvidence
        ? await saveMitreReport()
        : { matrix: generateMitreCoverageMatrix(), markdown: generateMitreMarkdownReport(generateMitreCoverageMatrix()) };
      return {
        content: [
          {
            type: 'text',
            text: result.markdown || JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: isolate_workload
    if (name === 'isolate_workload') {
      const { podName, namespace = 'default', reason = 'Emergency containment via MCP' } = args;
      const result = await isolatePod({ podName, namespace, reason });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: release_isolation
    if (name === 'release_isolation') {
      const { containmentId } = args;
      const result = await releaseContainment(containmentId);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: investigate_incident
    if (name === 'investigate_incident') {
      const { target, incidentId, triggerAlert, automatedContainment = true } = args;
      const result = await runAgentSocInvestigation({
        target,
        incidentId,
        triggerAlert,
        automatedContainment
      });
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: query_cti
    if (name === 'query_cti') {
      const { indicators } = args;
      const result = await matchCtiIndicators(indicators);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    }

    // Tool: generate_kspm_scorecard
    if (name === 'generate_kspm_scorecard') {
      const { namespace, saveEvidence = true } = args;
      const scorecard = await generateKspmScorecard({ namespace });
      const report = saveEvidence ? await saveKspmReport(scorecard) : null;
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ scorecard, reportPath: report?.reportPath }, null, 2)
          }
        ]
      };
    }

    // Tool: run_pipeline_audit
    if (name === 'run_pipeline_audit') {
      const { targetPath, failOn = 'HIGH' } = args;
      const result = await runPipelineAudit(targetPath, { failOn });
      const sarif = generateSarifReport(result.findings);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ auditResult: result, sarif }, null, 2)
          }
        ]
      };
    }

    // Tool: list_canary_tokens
    if (name === 'list_canary_tokens') {
      const canaries = await listActiveCanaries();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ total: canaries.length, canaries }, null, 2)
          }
        ]
      };
    }

    // Tool: deploy_canary_asset
    if (name === 'deploy_canary_asset') {
      const { type, name: assetName, namespace = 'default' } = args;
      let asset;
      if (type === 'secret') asset = generateCanarySecret(assetName || 'vault-prod-creds', namespace, 'aws_key');
      else if (type === 'decoy') asset = generateDecoyDeploymentYaml('smb', { name: assetName, namespace });
      else asset = generateCanaryServiceAccount(assetName || 'cluster-admin-decoy', namespace);

      await registerCanaryAsset(asset.canary);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ canary: asset.canary, yaml: asset.yaml }, null, 2)
          }
        ]
      };
    }

    // Tool: run_purple_simulation
    if (name === 'run_purple_simulation') {
      const { scenario = 'lateral-smb-exfil' } = args;
      const sim = await runPurpleTeamSimulation(scenario);
      const scorecard = calculatePurpleScorecard(sim);
      const reportPath = await savePurpleReport(sim, scorecard);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ simulationId: sim.simulationId, scorecard, reportPath, timeline: sim.timeline }, null, 2)
          }
        ]
      };
    }

    // Tool: auto_remediate_finding
    if (name === 'auto_remediate_finding') {
      const { finding, fileContent, fileType = 'k8s' } = args;
      const patchRes = generatePatchForFinding(finding, fileContent, fileType);
      const diff = generateUnifiedDiff(fileContent, patchRes.patchedContent);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ modified: patchRes.modified, description: patchRes.description, diff, patchedContent: patchRes.patchedContent }, null, 2)
          }
        ]
      };
    }

    // Tool: query_security_datalake
    if (name === 'query_security_datalake') {
      const { sql } = args;
      const rows = queryDataLake(sql);
      const backend = getDataLakeBackend();
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ backend, rowCount: rows.length, rows }, null, 2)
          }
        ]
      };
    }

    // Tool: audit_cloud_security
    if (name === 'audit_cloud_security') {
      const { workloads = [], storageConfigs = [] } = args;
      const idFindings = auditWorkloadIdentity(workloads);
      const storageFindings = auditCloudStorageExposure(storageConfigs);
      const risk = calculateCloudRiskScore([...idFindings, ...storageFindings]);
      const report = generateCloudSecReport(idFindings, storageFindings);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ risk, idFindings, storageFindings, report }, null, 2)
          }
        ]
      };
    }

    // Tool: transpile_sigma_to_sql
    if (name === 'transpile_sigma_to_sql') {
      const { rule, targetBackend = 'sqlite' } = args;
      const transpiled = transpileSigmaToSql(rule, targetBackend);
      return {
        content: [{ type: 'text', text: JSON.stringify(transpiled, null, 2) }]
      };
    }

    // Tool: run_sigma_threat_hunt
    if (name === 'run_sigma_threat_hunt') {
      const { rule, targetBackend = 'sqlite' } = args;
      const hunt = runSigmaThreatHunt(rule, null, targetBackend);
      return {
        content: [{ type: 'text', text: JSON.stringify(hunt, null, 2) }]
      };
    }

    // Tool: run_dynamic_adversary_simulation
    if (name === 'run_dynamic_adversary_simulation') {
      const { attackGraph, targetPrincipal, autoContain = false } = args;
      const result = await simulateDynamicAttackChain(attackGraph, targetPrincipal, { apply: autoContain });
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    }

    // Tool: inspect_process_memory
    if (name === 'inspect_process_memory') {
      const { pid, mapsContent } = args;
      const anomalies = detectMemoryAnomalies(pid, mapsContent);
      return {
        content: [{ type: 'text', text: JSON.stringify({ pid, anomaliesCount: anomalies.length, anomalies }, null, 2) }]
      };
    }

    // Tool: generate_cloud_honeytoken
    if (name === 'generate_cloud_honeytoken') {
      const { provider, ...opts } = args;
      const honeytoken = generateCloudHoneytoken(provider, opts);
      return {
        content: [{ type: 'text', text: JSON.stringify(honeytoken, null, 2) }]
      };
    }

    // Tool: start_canary_webhook_listener
    if (name === 'start_canary_webhook_listener') {
      const { port = 9099, webhookPath = '/api/v1/trap' } = args;
      const listener = await startCanaryWebhookListener({ port, path: webhookPath, autoContain: false });
      return {
        content: [{ type: 'text', text: JSON.stringify({ status: 'LISTENING', port: listener.port, path: listener.path }, null, 2) }]
      };
    }

    // Tool: generate_container_sbom
    if (name === 'generate_container_sbom') {
      const { format = 'cyclonedx', manifests = [], componentName = 'vigilante-container' } = args;
      const sbom = format === 'spdx'
        ? generateSpdxSbom(manifests, { documentName: componentName })
        : generateCycloneDxSbom(manifests, { componentName });
      return {
        content: [{ type: 'text', text: JSON.stringify(sbom, null, 2) }]
      };
    }

    // Tool: verify_cosign_signature
    if (name === 'verify_cosign_signature') {
      const { imageDigest, signaturePayload, publicKeyPem } = args;
      const verification = verifyCosignSignature(imageDigest, signaturePayload, publicKeyPem);
      return {
        content: [{ type: 'text', text: JSON.stringify(verification, null, 2) }]
      };
    }

    // Tool: get_socket_connection_matrix
    if (name === 'get_socket_connection_matrix') {
      const { networkEvents = [] } = args;
      const matrix = buildSocketConnectionMatrix(networkEvents);
      const anomalies = detectAnomalousSocketConnections(matrix);
      return {
        content: [{ type: 'text', text: JSON.stringify({ matrix, anomalies }, null, 2) }]
      };
    }

    // Tool: render_mitre_heatmap
    if (name === 'render_mitre_heatmap') {
      const { coverageMap = {} } = args;
      const rendered = renderMitreHeatmapGrid(coverageMap);
      return {
        content: [{ type: 'text', text: rendered }]
      };
    }

    // Tool: broadcast_mesh_threat
    if (name === 'broadcast_mesh_threat') {
      const { indicator, type = 'IP', severity = 'CRITICAL', reason = 'Manual alert', peers = [] } = args;
      const node = await createFederationNode({ peers });
      const envelope = signThreatRecord({ indicator, type, severity, reason }, node.privateKey, { nodeId: node.nodeId, publicKey: node.publicKey });
      const broadcast = broadcastThreatIndicator(envelope, node.peers);
      return {
        content: [{ type: 'text', text: JSON.stringify({ envelope, broadcast }, null, 2) }]
      };
    }

    // Tool: get_mesh_peers_status
    if (name === 'get_mesh_peers_status') {
      const node = await createFederationNode();
      const safeNode = {
        nodeId: node.nodeId,
        clusterName: node.clusterName,
        peers: node.peers,
        status: node.status,
        createdAt: node.createdAt,
        publicKeyPreview: node.publicKey ? node.publicKey.substring(0, 40) + '...' : null
      };
      return {
        content: [{ type: 'text', text: JSON.stringify(safeNode, null, 2) }]
      };
    }

    // Tool: synthesize_bpf_lsm_policy
    if (name === 'synthesize_bpf_lsm_policy') {
      const policy = generateBpfLsmPolicy(args.rules || [], args);
      let output = policy;
      if (args.format === 'c') {
        output = {
          policy,
          cSource: exportLsmCSource(policy)
        };
      }
      return {
        content: [{ type: 'text', text: JSON.stringify(output, null, 2) }]
      };
    }

    // Tool: evaluate_bpf_lsm_event
    if (name === 'evaluate_bpf_lsm_event') {
      const policy = args.policy || generateBpfLsmPolicy([], {});
      const evaluation = simulateLsmPolicyEvaluation(policy, args.event || {});
      return {
        content: [{ type: 'text', text: JSON.stringify(evaluation, null, 2) }]
      };
    }

    // Tool: detect_c2_beaconing
    if (name === 'detect_c2_beaconing') {
      const result = detectBeaconingPeriodicity(args.intervals || [], args);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    }

    // Tool: detect_dns_tunneling
    if (name === 'detect_dns_tunneling') {
      const result = detectDnsTunneling(args.queries || [], args);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    }

    // Tool: scan_file_entropy
    if (name === 'scan_file_entropy') {
      const entropyResult = calculateFileEntropy(args.content || args.filePath);
      return {
        content: [{ type: 'text', text: JSON.stringify(entropyResult, null, 2) }]
      };
    }

    // Tool: deploy_ransomware_canaries
    if (name === 'deploy_ransomware_canaries') {
      const canaries = await generateRansomwareCanaryFiles(args.targetDirectory, args);
      return {
        content: [{ type: 'text', text: JSON.stringify(canaries, null, 2) }]
      };
    }

    // Tool: convene_agent_warroom
    if (name === 'convene_agent_warroom') {
      const session = await conveneIncidentWarRoom(
        { incidentId: args.incidentId, evidence: args.evidence },
        args
      );
      const transcript = generateWarRoomTranscript(session);
      return {
        content: [{ type: 'text', text: JSON.stringify({ session, transcript }, null, 2) }]
      };
    }

    // Tool: search_semantic_cti
    if (name === 'search_semantic_cti') {
      const matches = semanticThreatSearch(args.query, args);
      return {
        content: [{ type: 'text', text: JSON.stringify(matches, null, 2) }]
      };
    }

    // Tool: append_audit_ledger
    if (name === 'append_audit_ledger') {
      const entry = await appendLedgerEntry(
        args.entryType,
        args.payload,
        { role: args.signerRole || 'IncidentCommander' },
        args
      );
      return {
        content: [{ type: 'text', text: JSON.stringify(entry, null, 2) }]
      };
    }

    // Tool: verify_ledger_integrity
    if (name === 'verify_ledger_integrity') {
      const verification = await verifyLedgerIntegrity(args.ledgerDir);
      return {
        content: [{ type: 'text', text: JSON.stringify(verification, null, 2) }]
      };
    }

    // Tool: calculate_attack_blast_radius
    if (name === 'calculate_attack_blast_radius') {
      const graph = buildCompositeAttackGraph();
      const blast = calculateBlastRadius(args.nodeId, graph);
      return {
        content: [{ type: 'text', text: JSON.stringify(blast, null, 2) }]
      };
    }

    // Tool: render_terminal_attack_graph
    if (name === 'render_terminal_attack_graph') {
      const graph = buildCompositeAttackGraph();
      let highlightPath = [];
      if (args.highlightFrom && args.highlightTo) {
        const pathRes = findShortestAttackPath(args.highlightFrom, args.highlightTo, graph);
        highlightPath = pathRes.nodePath;
      }
      const rendered = renderAsciiAttackGraph(graph, { highlightPath });
      return {
        content: [{ type: 'text', text: rendered }]
      };
    }

    // Tool: scan_kernel_rootkits
    if (name === 'scan_kernel_rootkits') {
      const kallsyms = args.kallsymsContent ? parseKallsyms(args.kallsymsContent) : [];
      const syscalls = detectSyscallHooking(kallsyms);
      const hidden = detectHiddenModules(args.procModulesContent || '', args.sysModuleList || []);
      const taint = analyzeKernelTaint(args.taintValue != null ? args.taintValue : 0);
      const artifacts = scanRootkitArtifacts();
      const report = generateRootkitReport({
        syscallAnomalies: syscalls,
        hiddenModules: hidden.hiddenModules,
        taintAssessment: taint,
        artifacts
      });
      return {
        content: [{ type: 'text', text: JSON.stringify(report, null, 2) }]
      };
    }

    // Tool: scan_process_yara
    if (name === 'scan_process_yara') {
      const rule = compileYaraRule(args.rule);
      const buf = args.bufferBase64 ? Buffer.from(args.bufferBase64, 'base64') : null;
      const scanRes = await scanProcessMemory(args.pid || 0, [rule], { memoryBuffer: buf });
      const report = generateYaraMemoryReport(scanRes);
      return {
        content: [{ type: 'text', text: JSON.stringify(report, null, 2) }]
      };
    }

    // Tool: extract_cobaltstrike_config
    if (name === 'extract_cobaltstrike_config') {
      const buf = Buffer.from(args.bufferBase64 || '', 'base64');
      const cs = extractCobaltStrikeConfig(buf);
      return {
        content: [{ type: 'text', text: JSON.stringify(cs, null, 2) }]
      };
    }

    // Tool: synthesize_attack_dag
    if (name === 'synthesize_attack_dag') {
      const dag = buildCausalTimeline(args.events || []);
      const rootCause = identifyRootCause(dag);
      const dwell = calculateDwellTime(dag);
      const ascii = renderAsciiTimeline(dag);
      return {
        content: [{ type: 'text', text: JSON.stringify({ rootCause, dwell, ascii, dagStats: dag.stats }, null, 2) }]
      };
    }

    // Tool: run_swarm_duel
    if (name === 'run_swarm_duel') {
      const sim = runFullDuelSimulation(args);
      return {
        content: [{ type: 'text', text: JSON.stringify({ metrics: sim.metrics, transcript: sim.transcript }, null, 2) }]
      };
    }

    // Tool: import_stix_bundle
    if (name === 'import_stix_bundle') {
      const parsed = parseStixBundle(args.bundleJson);
      return {
        content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }]
      };
    }

    // Tool: convert_misp_event
    if (name === 'convert_misp_event') {
      const result = args.direction === 'stix_to_misp' 
        ? convertStixToMisp(args.data) 
        : convertMispToStix(args.data);
      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    }

    // Tool: deploy_honeynet_mesh
    if (name === 'deploy_honeynet_mesh') {
      const mesh = await createHoneynetMesh({ services: args.services });
      return {
        content: [{ type: 'text', text: JSON.stringify({ meshId: mesh.meshId, status: mesh.status, decoys: mesh.decoys.map(d => ({ type: d.type, port: d.port })) }, null, 2) }]
      };
    }

    // Tool: plant_deception_breadcrumbs
    if (name === 'plant_deception_breadcrumbs') {
      const planted = await plantBreadcrumbs(args.targetDir, args.types);
      return {
        content: [{ type: 'text', text: JSON.stringify(planted, null, 2) }]
      };
    }

    // Tool: capture_container_snapshot
    if (name === 'capture_container_snapshot') {
      const snap = await createForensicsSnapshot(args);
      return {
        content: [{ type: 'text', text: JSON.stringify(snap, null, 2) }]
      };
    }

    // Tool: export_rfc3161_evidence_pack
    if (name === 'export_rfc3161_evidence_pack') {
      const pack = await createEvidenceBundle(
        { caseNumber: args.caseNumber, title: args.title },
        args.evidenceItems || []
      );
      return {
        content: [{ type: 'text', text: JSON.stringify(pack, null, 2) }]
      };
    }

    // Tool: dissect_network_packet
    if (name === 'dissect_network_packet') {
      const buf = Buffer.from(args.packetHex || '', 'hex');
      const pkt = dissectFullPacket(buf);
      const hexDump = formatHexDump(buf);
      return {
        content: [{ type: 'text', text: JSON.stringify({ packet: pkt, hexDump }, null, 2) }]
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
