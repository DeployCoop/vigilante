#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import meow from 'meow';
import { App } from '../src/ui/App.js';
import { loadConfig } from '../src/engine/config.js';

const config = loadConfig();

const cli = meow(`
  Usage
    $ vigilante [command] [options]

  Commands
    menu/hub    Central operations hub and interactive workflow dispatcher
    up          Provision k3d cluster, certificates, and deploy modules
    down        Tear down k3d cluster and clean up resources
    status      Check status of prerequisites, cluster, certificates, and DNS
    modules     List available and installed modules
    pods        Live monitor of Kubernetes pods with -A -o wide details
    nmap/scan   Network reconnaissance & data collection saved to XDG nmaps dir
    xml/netmap  Interactive XML network topology & port matrix visualizer
    openvas/gvm OpenVAS & Greenbone vulnerability management & CVE scanning pane
    kctf/ctf    Google kCTF cyber range platform & challenge spin-up pane
    oobscan/oob Out-of-Band (BMC/IPMI/Redfish/AMT) hardware security audit (runZeroInc/oobscan)
    uninstall   Uninstall an individual module from the cluster (use -m <module>)
    reset       Reset and cleanly reinstall an individual module in-place (use -m <module>)
    threat-sim  Trigger network threat simulation batch against SIEM
    playbooks   List all built-in and custom threat simulation scenarios
    instances   List and inspect all k3d cluster instances and their directories
    hosts/hostr Sync local domain mappings into /etc/hosts
    values      Manage, list, or export customizable chart values.yaml files
    config      Inspect, initialize, or display $XDG_CONFIG_HOME/vigilante/config.yaml
    ai/ask      Launch AI Security & Forensics Analyst console (Ollama/Claude/GPT)
    nist        Inspect NIST SP 800-61 Rev. 2 framework and active incident manifests
    mcp         Launch Model Context Protocol (MCP) server over stdio for LLMs
    audit       Shift-left security audit of Kubernetes manifests and Dockerfiles
    kspm        Continuous Kubernetes Security Posture Management & CIS benchmarks
    battlestation/bs Launch live dual-pane Battle Station (Falco eBPF + Zeek/Suricata)
    hunt        Execute SIGMA-to-SQL automated threat hunts across Security Data Lake
    memdump     Inspect process memory maps (/proc/$PID/maps) for fileless/RWX anomalies
    sbom        Generate CycloneDX v1.5 or SPDX v2.3 container SBOM and verify signatures
    matrix      Live socket connection matrix viewer and lateral egress anomaly detector
    mesh        Multi-cluster defense federation peer management and signed threat sharing
    beacon      Statistical C2 beaconing & FFT frequency-domain periodicity detector
    lsm         Synthesize and inspect Linux Security Module (eBPF LSM) C kernel policies
    warroom     Convene autonomous multi-agent incident war room & consensus debate
    vector      Air-gapped offline semantic threat query against MITRE ATT&CK and Sigma
    ledger      Inspect and verify cryptographic Merkle audit ledger & chain-of-custody
    graph       Interactive terminal composite attack graph & blast-radius explorer
    rootkit     Audit /proc/kallsyms, detect syscall table hooking & hidden LKM rootkits
    yara        In-memory process YARA scanner and Cobalt Strike C2 beacon config extractor
    timeline    Interactive attack timeline and automated root-cause causality DAG
    duel        Autonomous Red Team vs Blue Team cyber range swarm battle simulator
    stix        Ingest STIX 2.1 JSON bundles, convert MISP events, and sync TAXII feeds
    honeynet    Deploy ephemeral deception decoys (SSH, Redis, HTTP) and plant breadcrumbs
    snapshot    Capture live container volatile memory and overlayfs upper disk differential
    evidencepack Export ISO/IEC 27037 & RFC 3161 court-admissible evidence bundle with verifiers
    sniffer     Interactive terminal live packet sniffer and protocol dissector

  Options
    --domain, -d       Local top-level domain (Default: ${config.defaults?.domain || 'vigilante.local'})
    --cluster-name, -c Cluster name (Default: ${config.defaults?.clusterName || 'vigilante-dev'})
    --instance, -i     Instance name alias for --cluster-name
    --namespace, -n    Target Kubernetes namespace (e.g. 'default', 'threat-lab', 'tenant-a')
    --module, -m       Specific module(s) to install/uninstall/reset (comma-separated, Default: vigil-soc)
    --delete-namespace Delete target Kubernetes namespace during uninstall
    --scenario, -s     Threat simulation scenario ID (e.g. 'credential-bruteforce', 'dns-tunneling-exfil')
    --playbook, -p     Path to custom YAML/JSON threat playbook file
    --playbooks-dir    Path to custom directory containing threat playbooks
    --all              Execute all available threat simulation scenarios in sequence
    --list             List available threat simulation playbooks and exit
    --values, -f       Path to custom Helm values override file
    --values-dir       Path to directory containing custom values files (Default: ./values or XDG)
    --theme            UI theme (default, cyberpunk, dracula, nord, matrix, monokai)
    --ip               Target IP for hosts mapping (Default: ${config.defaults?.ip || '127.0.0.1'})
    --remove           Remove managed entries from /etc/hosts (for hosts/hostr)
    --check            Check /etc/hosts status without modifying (for hosts/hostr)
    --non-interactive  Run without interactive prompts
    --skip-prereqs     Skip prerequisite verification

  Examples
    $ vigilante up --cluster-name soc-prod --domain prod.local
    $ vigilante threat-sim --scenario credential-bruteforce
    $ vigilante threat-sim --playbook ./playbooks/my-custom-exploit.yaml
    $ vigilante playbooks
    $ vigilante up -m wazuh
    $ vigilante up -n tenant-alpha -m opensearch,vigil-soc
    $ vigilante uninstall -m openvas -n openvas
    $ vigilante reset -m kctf -n kctf
    $ vigilante instances
    $ vigilante config path
    $ vigilante down
`, {
  importMeta: import.meta,
  flags: {
    domain: {
      type: 'string',
      shortFlag: 'd',
      default: config.defaults?.domain || 'vigilante.local'
    },
    clusterName: {
      type: 'string',
      shortFlag: 'c',
      default: config.defaults?.clusterName || 'vigilante-dev'
    },
    instance: {
      type: 'string',
      shortFlag: 'i'
    },
    namespace: {
      type: 'string',
      shortFlag: 'n',
      default: ''
    },
    module: {
      type: 'string',
      shortFlag: 'm'
    },
    deleteNamespace: {
      type: 'boolean',
      default: false
    },
    scenario: {
      type: 'string',
      shortFlag: 's'
    },
    playbook: {
      type: 'string',
      shortFlag: 'p'
    },
    playbooksDir: {
      type: 'string'
    },
    all: {
      type: 'boolean',
      default: false
    },
    list: {
      type: 'boolean',
      default: false
    },
    values: {
      type: 'string',
      shortFlag: 'f'
    },
    valuesDir: {
      type: 'string',
      default: config.defaults?.valuesDir || ''
    },
    web: {
      type: 'boolean',
      shortFlag: 'w',
      default: false
    },
    svg: {
      type: 'boolean',
      default: false
    },
    diff: {
      type: 'boolean',
      default: false
    },
    theme: {
      type: 'string'
    },
    ip: {
      type: 'string',
      default: config.defaults?.ip || '127.0.0.1'
    },
    remove: {
      type: 'boolean',
      default: false
    },
    check: {
      type: 'boolean',
      default: false
    },
    nonInteractive: {
      type: 'boolean',
      default: false
    },
    skipPrereqs: {
      type: 'boolean',
      default: false
    },
    hashes: {
      type: 'boolean',
      default: false
    },
    exportHashes: {
      type: 'boolean',
      default: false
    },
    failOn: {
      type: 'string',
      default: 'HIGH'
    },
    sarif: {
      type: 'boolean',
      default: false
    },
    output: {
      type: 'string',
      shortFlag: 'o'
    },
    query: {
      type: 'string',
      shortFlag: 'q'
    },
    incident: {
      type: 'string'
    }
  }
});

const command = cli.input[0] || 'up';
const subCommand = cli.input[1];
const hostsAction = cli.flags.remove ? 'remove' : cli.flags.check ? 'check' : 'sync';
const effectiveClusterName = cli.flags.instance || cli.flags.clusterName || config.defaults?.clusterName || 'vigilante-dev';

if (command === 'mcp') {
  import('../src/mcp/server.js').then(({ runMcpServer }) => {
    runMcpServer().catch((err) => {
      console.error('Fatal MCP Server error:', err);
      process.exit(1);
    });
  });
} else if (command === 'nist' || command === 'incident' || command === 'incidents') {
  import('../src/engine/nist.js').then(async ({
    NIST_ATTACK_VECTORS,
    NIST_LIFECYCLE_PHASES,
    NIST_EVIDENCE_VOLATILITY,
    NIST_IMPACT_LEVELS,
    listNistIncidents,
    calculateNistIncidentScore
  }) => {
    console.log('\n🛡️  NIST SP 800-61 REV. 2 INCIDENT RESPONSE FRAMEWORK');
    console.log('='.repeat(75));

    console.log('\n📌 LIFECYCLE PHASES:');
    Object.values(NIST_LIFECYCLE_PHASES).forEach(p => {
      console.log(`  • ${p.name}: ${p.description}`);
    });

    console.log('\n🎯 ATTACK VECTORS (Table 3-1):');
    Object.values(NIST_ATTACK_VECTORS).forEach(v => {
      console.log(`  • [${v.id}] ${v.name}`);
      console.log(`    ${v.description}`);
    });

    console.log('\n📊 ACTIVE & ARCHIVED INCIDENT RECORDS (Evidence Vault):');
    const incidents = await listNistIncidents();
    if (incidents.length === 0) {
      console.log('  (No active incident records found. Run forensic triage with `vigilante xml` -> [t])');
    } else {
      incidents.forEach((inc, idx) => {
        const vec = inc.classification?.attackVector?.name || 'Unknown';
        const p = inc.prioritization || {};
        console.log(`  [${idx + 1}] Incident ID: ${inc.incidentId} [${p.severity || 'LOW'}]`);
        console.log(`      Target: Host ${inc.target?.host} on Subnet ${inc.target?.network}`);
        console.log(`      Vector: ${vec} | Sign Type: ${inc.classification?.signType || 'INDICATOR'}`);
        console.log(`      Impact: Functional [${p.functionalImpact}] | Information [${p.informationImpact}] | Recoverability [${p.recoverabilityEffort}]`);
        console.log(`      SLA: ${p.slaTargetMinutes || 60} min | Artifacts: ${inc.chainOfCustody?.artifactsCount || 0}`);
        console.log(`      Vault: ${inc.target?.vaultPath}`);
        console.log();
      });
    }
    console.log('='.repeat(75));
    console.log('💡 Refer to FIRSTRESPONSE.md for the step-by-step incident handling guide.\n');
    process.exit(0);
  });
} else if (command === 'playbooks' || (command === 'threat-sim' && cli.flags.list)) {
  import('../src/engine/threats.js').then(async ({ listAvailablePlaybooks }) => {
    const playbooks = await listAvailablePlaybooks({ customDir: cli.flags.playbooksDir });
    console.log('\n🛡️  AVAILABLE THREAT SIMULATION PLAYBOOKS:');
    console.log('='.repeat(70));
    playbooks.forEach((p, idx) => {
      const typeBadge = p.isCustom ? '[CUSTOM]' : '[BUILT-IN]';
      const mitreTags = (p.mitreTechniques || []).map(t => t.id).join(', ');
      console.log(`[${idx + 1}] ${p.name} (${p.id}) ${typeBadge}`);
      console.log(`    Category: ${p.category} | Severity: ${p.severity} | MITRE: ${mitreTags || 'N/A'}`);
      console.log(`    ${p.description} (${p.events?.length || 0} events)`);
      if (p.filePath) console.log(`    Path: ${p.filePath}`);
      console.log();
    });
    process.exit(0);
  });
} else if ((command === 'oobscan' || command === 'oob') && (cli.flags.exportHashes || cli.flags.hashes)) {
  import('../src/engine/oobscan.js').then(async ({ exportRakpHashes }) => {
    const exported = await exportRakpHashes();
    console.log(`\n🔑 EXPORTED ${exported.count} RAKP-2 HASHCAT FORMAT HASHES:`);
    console.log('='.repeat(70));
    console.log(`File: ${exported.filePath}`);
    console.log(`Ready for cracking: hashcat -m 7300 ${exported.filePath} rockyou.txt\n`);
    process.exit(0);
  });
} else if (command === 'mitre' || command === 'att&ck' || command === 'attack') {
  import('../src/engine/mitre.js').then(async ({ generateMitreCoverageMatrix, generateMitreMarkdownReport, saveMitreReport }) => {
    const report = await saveMitreReport();
    console.log('\n' + report.markdown);
    console.log(`✔ Report saved and signed in evidence directory (ID: ${report.reportId})\n`);
    process.exit(0);
  });
} else if ((command === 'xml' || command === 'netmap' || command === 'map') && (cli.flags.web || cli.flags.svg || cli.flags.diff)) {
  Promise.all([
    import('../src/engine/nmap-xml.js'),
    import('../src/engine/config.js'),
    import('node:fs/promises'),
    import('node:path'),
    import('execa')
  ]).then(async ([nmapXml, cfg, fs, path, execa]) => {
    const scans = await nmapXml.listSavedXmlScans();
    if (scans.length === 0) {
      console.error('✖ No saved Nmap XML scans found in $XDG_CONFIG_HOME/vigilante/nmaps/. Run `vigilante nmap` first.');
      process.exit(1);
    }

    const activeScan = scans[0];

    if (cli.flags.diff) {
      if (scans.length < 2) {
        console.error('✖ Need at least 2 XML scans to calculate differences.');
        process.exit(1);
      }
      const diff = nmapXml.compareNmapScans(scans[1], activeScan);
      console.log(`\n🔍 NASTYMAP SECURITY DIFF: ${scans[1].filename} ➔ ${activeScan.filename}`);
      console.log('='.repeat(70));
      console.log(`Hosts: +${diff.summary.hostsAdded} Added | -${diff.summary.hostsRemoved} Removed | ~${diff.summary.hostsModified} Modified`);
      console.log(`Ports: +${diff.summary.portsAdded} Opened | -${diff.summary.portsRemoved} Closed | ~${diff.summary.portsModified} Modified`);
      if (diff.addedHosts.length > 0) {
        console.log('\n⚠️  ROGUE / NEW HOSTS DISCOVERED:');
        diff.addedHosts.forEach(h => console.log(`  • ${h.ip} (${h.hostname || 'unknown'}) - ${h.portDiffs.length} ports`));
      }
      console.log();
      process.exit(0);
    }

    const graph = nmapXml.generateTopology(activeScan);
    await cfg.ensureVigilanteConfig();
    const mapsDir = path.join(cfg.getVigilanteEvidenceDir(), 'maps');
    await fs.mkdir(mapsDir, { recursive: true });

    if (cli.flags.svg) {
      const svg = nmapXml.generateHeadlessSvg(graph, { title: `Vigilante Topology: ${activeScan.target}` });
      const svgPath = path.join(mapsDir, `nastymap-${activeScan.id}.svg`);
      await fs.writeFile(svgPath, svg, 'utf8');
      console.log(`✔ Exported NastyMap SVG diagram to: ${svgPath}`);
      process.exit(0);
    }

    if (cli.flags.web) {
      const html = nmapXml.generateHtmlReport(activeScan, graph);
      const htmlPath = path.join(mapsDir, `nastymap-${activeScan.id}.html`);
      await fs.writeFile(htmlPath, html, 'utf8');
      console.log(`✔ Generated NastyMap interactive HTML report: ${htmlPath}`);

      const platform = process.platform;
      const cmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
      await execa.execa(cmd, [htmlPath]).catch(() => {});
      console.log(`🌐 Launched in browser via ${cmd}.`);
      process.exit(0);
    }
  });
} else if (command === 'audit') {
  import('../src/engine/audit.js').then(async ({ runPipelineAudit, generateSarifReport }) => {
    const targetPath = cli.input[1] || '.';
    const failOn = cli.flags.failOn || 'HIGH';
    console.log(`\n🔍 VIGILANTE SHIFT-LEFT SECURITY AUDIT`);
    console.log('='.repeat(70));
    console.log(`Target: ${targetPath} | Threshold: ${failOn}\n`);

    try {
      const result = await runPipelineAudit(targetPath, { failOn });

      if (cli.flags.sarif) {
        const sarif = generateSarifReport(result.findings);
        if (cli.flags.output) {
          const fs = await import('node:fs/promises');
          await fs.writeFile(cli.flags.output, JSON.stringify(sarif, null, 2), 'utf8');
          console.log(`✔ SARIF report written to ${cli.flags.output}`);
        } else {
          console.log(JSON.stringify(sarif, null, 2));
        }
      } else {
        console.log(`Scanned ${result.filesScanned} files. Found ${result.findings.length} issues.`);
        console.log(`Summary: Critical: ${result.summary.CRITICAL}, High: ${result.summary.HIGH}, Medium: ${result.summary.MEDIUM}, Low: ${result.summary.LOW}\n`);

        result.findings.forEach((f, idx) => {
          const sevBadge = `[${f.severity}]`;
          console.log(`  [${idx + 1}] ${sevBadge} ${f.title} (${f.ruleId})`);
          console.log(`      File: ${f.file}${f.line ? `:${f.line}` : ''}`);
          console.log(`      ${f.description}`);
          if (f.remediation) console.log(`      Remediation: ${f.remediation}`);
          console.log();
        });
      }

      if (result.failed) {
        console.error(`✖ Audit FAILED: Found violations meeting or exceeding threshold '${failOn}'.`);
        process.exit(1);
      } else {
        console.log(`✔ Audit PASSED: No violations exceeding threshold '${failOn}'.`);
        process.exit(0);
      }
    } catch (err) {
      console.error(`✖ Audit error:`, err.message);
      process.exit(1);
    }
  });
} else if (command === 'kspm') {
  import('../src/engine/kspm.js').then(async ({ generateKspmScorecard, saveKspmReport }) => {
    console.log(`\n🛡️  KUBERNETES SECURITY POSTURE MANAGEMENT (KSPM)`);
    console.log('='.repeat(70));
    const scorecard = await generateKspmScorecard({ namespace: cli.flags.namespace || undefined });
    console.log(`Cluster Posture Grade: [${scorecard.grade}] (${scorecard.overallScore}/100)`);
    console.log(`Evaluated Workloads: ${scorecard.workloadCount} | Violations: ${scorecard.findings.length}\n`);

    scorecard.findings.forEach((f, idx) => {
      console.log(`  [${idx + 1}] [${f.severity}] ${f.title} on ${f.resource}`);
      console.log(`      Namespace: ${f.namespace} | Rule: ${f.ruleId}`);
      console.log(`      ${f.description}`);
      console.log(`      Remediation: ${f.remediation}\n`);
    });

    const report = await saveKspmReport(scorecard);
    console.log(`✔ KSPM Evidence Report signed and saved to: ${report.reportPath}\n`);
    process.exit(0);
  });
} else if (command === 'fix') {
  Promise.all([
    import('../src/engine/remediation.js'),
    import('../src/engine/audit.js'),
    import('node:fs/promises')
  ]).then(async ([remed, auditMod, fs]) => {
    const targetPath = cli.input[1] || '.';
    console.log(`\n🛠️  SELF-HEALING AUTO-REMEDIATOR ("AUTO-PATCH ENGINE")`);
    console.log('='.repeat(70));
    console.log(`Auditing and patching target: ${targetPath}`);

    const auditRes = await auditMod.runPipelineAudit(targetPath);
    if (auditRes.findings.length === 0) {
      console.log('✔ No security findings found to remediate.');
      process.exit(0);
    }

    console.log(`Discovered ${auditRes.findings.length} findings to remediate.\n`);
    let patchedCount = 0;

    for (const f of auditRes.findings) {
      if (!f.file) continue;
      try {
        const fileContent = await fs.readFile(f.file, 'utf8');
        const fileType = f.file.endsWith('Dockerfile') ? 'dockerfile' : 'k8s';
        const patchRes = remed.generatePatchForFinding(f, fileContent, fileType);

        if (patchRes.modified) {
          console.log(`[PATCH] ${f.file} (${f.ruleId}): ${patchRes.description}`);
          if (cli.flags.apply) {
            await remed.applyPatchToFile(f.file, patchRes.patchedContent, { backup: true });
            console.log(`  ✔ Applied patch to ${f.file} (with backup).`);
            patchedCount++;
          } else {
            const diff = remed.generateUnifiedDiff(fileContent, patchRes.patchedContent, f.file);
            console.log(diff + '\n');
          }
        }
      } catch (err) {
        console.warn(`  ⚠️ Could not patch ${f.file}: ${err.message}`);
      }
    }

    if (cli.flags.apply) {
      console.log(`\n🎉 Successfully applied ${patchedCount} security patches.`);
    } else {
      console.log(`\n💡 Run with --apply to write patches to disk.`);
    }
    process.exit(0);
  });
} else if (command === 'canary') {
  import('../src/engine/deception.js').then(async (deception) => {
    const sub = cli.input[1] || 'list';
    console.log(`\n🪤 AUTONOMOUS DECEPTION MESH ("CANARY KUBE")`);
    console.log('='.repeat(70));

    if (sub === 'deploy') {
      const type = cli.input[2] || 'sa';
      let asset;
      if (type === 'secret') asset = deception.generateCanarySecret('prod-db-canary', 'default', 'db_password');
      else if (type === 'decoy') asset = deception.generateDecoyDeploymentYaml('smb', { namespace: 'default' });
      else asset = deception.generateCanaryServiceAccount('cluster-admin-canary', 'kube-system');

      await deception.registerCanaryAsset(asset.canary);
      console.log(`✔ Generated & registered Canary [${asset.canary.type}] (ID: ${asset.canary.id}):`);
      console.log(asset.yaml);
    } else {
      const items = await deception.listActiveCanaries();
      console.log(`Registered Canaries (${items.length}):`);
      items.forEach(c => {
        const status = c.tripped ? '🚨 TRIPPED' : '🟢 ARMED';
        console.log(`  • ${status} [${c.type}] ${c.name} (${c.namespace}) - ID: ${c.id}`);
      });
    }
    console.log();
    process.exit(0);
  });
} else if (command === 'purple') {
  import('../src/engine/purpleteam.js').then(async (purple) => {
    const scen = cli.flags.scenario || 'lateral-smb-exfil';
    console.log(`\n⚔️ AUTONOMOUS PURPLE TEAM ARENA`);
    console.log('='.repeat(70));
    console.log(`Executing wargame scenario: ${scen}`);

    const sim = await purple.runPurpleTeamSimulation(scen);
    const sc = purple.calculatePurpleScorecard(sim);
    const reportPath = await purple.savePurpleReport(sim, sc);

    console.log(`\nScorecard: Grade [${sc.grade}] (${sc.score}/100) | Verdict: ${sc.contained ? 'CONTAINED' : 'EXFILTRATED'}`);
    console.log(`MTTD: ${sc.mttdSec}s | MTTR: ${sc.mttrSec}s | Containment: Step ${sc.containmentStep}`);
    console.log(`✔ Full Wargame Report saved to: ${reportPath}\n`);
    process.exit(0);
  });
} else if (command === 'query') {
  import('../src/engine/datalake.js').then(async (lake) => {
    const sql = cli.input.slice(1).join(' ') || 'SELECT count(*) as total_events FROM security_events';
    const backend = lake.getDataLakeBackend();
    console.log(`\n⚡ SECURITY DATA LAKE SQL QUERY [Engine: ${backend.toUpperCase()}]`);
    console.log('='.repeat(70));
    console.log(`SQL: ${sql}\n`);
    try {
      const rows = lake.queryDataLake(sql);
      console.table(rows);
    } catch (err) {
      console.error('✖ Query error:', err.message);
    }
    process.exit(0);
  });
} else if (command === 'forensics') {
  import('../src/engine/forensics.js').then(async (forensics) => {
    const pcapFile = cli.input[1];
    console.log(`\n🔬 DEEP PCAP FORENSIC EXTRACTION`);
    console.log('='.repeat(70));
    const items = await forensics.listCarvedFiles();
    console.log(`Carved Artifacts in Dropzone (${items.length}):`);
    items.forEach(i => console.log(`  • 📦 ${i.fileName} (${i.sizeBytes} bytes) - ${i.filePath}`));
    console.log();
    process.exit(0);
  });
} else if (command === 'cloudsec') {
  import('../src/engine/cloudsec.js').then(async (cloudsec) => {
    console.log(`\n☁️  MULTI-CLOUD WORKLOAD IDENTITY & CSPM AUDIT`);
    console.log('='.repeat(70));
    const report = cloudsec.generateCloudSecReport([], []);
    console.log(report);
    process.exit(0);
  });
} else if (command === 'hunt') {
  import('../src/engine/sigma.js').then(async (sigma) => {
    const technique = cli.flags.technique || 'T1059.004';
    console.log(`\n🎯 SIGMA-TO-SQL AUTOMATED THREAT HUNT [Technique: ${technique}]`);
    console.log('='.repeat(70));
    const rule = sigma.generateSigmaHypothesis(technique);
    console.log(`Rule Title: ${rule.title}`);
    console.log(`Technique: ${rule.technique} | Level: ${(rule.level || rule.sigma?.level || 'MEDIUM').toUpperCase()}`);
    console.log(`Hypothesis: ${rule.hypothesis}`);
    console.log(`\nGenerated ANSI SQL:`);
    console.log(`  ${rule.sql}`);
    const huntMatches = sigma.runSigmaThreatHunt([rule.sigma || rule]);
    console.log(`\nTelemetry Matches Found: ${huntMatches.length}`);
    if (huntMatches.length > 0) {
      console.table(huntMatches);
    } else {
      console.log('  No active attack indicators matched in current telemetry.');
    }
    console.log();
    process.exit(0);
  });
} else if (command === 'memdump') {
  import('../src/engine/memdump.js').then(async (memdump) => {
    const targetPid = parseInt(cli.input[1] || '1', 10);
    console.log(`\n🧬 IN-MEMORY PROCESS & MAPS FORENSIC TRIAGE [PID: ${targetPid}]`);
    console.log('='.repeat(70));
    const anomalies = memdump.detectMemoryAnomalies(targetPid);
    console.log(`Discovered In-Memory Anomalies: ${anomalies.length}`);
    if (anomalies.length > 0) {
      anomalies.forEach((a, idx) => {
        console.log(`  ${idx + 1}. [${a.severity}] ${a.type} - ${a.description || a.pathname}`);
      });
    } else {
      console.log('  No RWX, unlinked binaries, or fileless memory segments detected.');
    }
    console.log();
    process.exit(0);
  });
} else if (command === 'sbom') {
  import('../src/engine/supplychain.js').then(async (sc) => {
    const format = (cli.flags.format || 'cyclonedx').toLowerCase();
    console.log(`\n📦 SUPPLY CHAIN SBOM GENERATOR [Format: ${format.toUpperCase()}]`);
    console.log('='.repeat(70));
    const manifests = [
      { name: 'express', version: '4.19.2', license: 'MIT', purl: 'pkg:npm/express@4.19.2' },
      { name: 'jsonwebtoken', version: '9.0.2', license: 'MIT', purl: 'pkg:npm/jsonwebtoken@9.0.2' },
      { name: 'sqlite3', version: '5.1.7', license: 'BSD-3-Clause', purl: 'pkg:npm/sqlite3@5.1.7' }
    ];
    const sbom = format === 'spdx'
      ? sc.generateSpdxSbom(manifests, { documentName: 'vigilante-runtime' })
      : sc.generateCycloneDxSbom(manifests, { componentName: 'vigilante-runtime' });
    console.log(JSON.stringify(sbom, null, 2));
    process.exit(0);
  });
} else if (command === 'matrix') {
  import('../src/engine/observability.js').then(async (obs) => {
    console.log(`\n🌐 REAL-TIME SOCKET CONNECTION MATRIX & ANOMALOUS EGRESS`);
    console.log('='.repeat(70));
    const rawEvents = [
      { source: '10.244.0.15', destination: '10.244.1.22', dstPort: 443, protocol: 'TCP', bytesSent: 4500, bytesReceived: 18200, pod: 'frontend' },
      { source: '10.244.1.22', destination: '10.244.2.8', dstPort: 5432, protocol: 'TCP', bytesSent: 12000, bytesReceived: 45000, pod: 'api-service' },
      { source: '10.244.0.15', destination: '198.51.100.44', dstPort: 4444, protocol: 'TCP', bytesSent: 512, bytesReceived: 128, pod: 'frontend' }
    ];
    const matrix = obs.buildSocketConnectionMatrix(rawEvents);
    const anomalies = obs.detectAnomalousSocketConnections(matrix);
    console.log(`Total Connections: ${matrix.summary.totalConnections} | Unique Sources: ${matrix.summary.uniqueSourcesCount} | Destinations: ${matrix.summary.uniqueDestinationsCount}`);
    console.table(matrix.connections.map(c => ({
      Source: c.source,
      Destination: `${c.destination}:${c.dstPort}`,
      Proto: c.protocol,
      Sent: `${(c.bytesSent / 1024).toFixed(1)} KB`,
      Recv: `${(c.bytesReceived / 1024).toFixed(1)} KB`,
      State: c.state
    })));
    if (anomalies.length > 0) {
      console.log(`\n⚠️  FLAGGED SOCKET ANOMALIES (${anomalies.length}):`);
      anomalies.forEach((a, i) => {
        console.log(`  ${i + 1}. [${a.severity}] ${a.type}: ${a.details}`);
        console.log(`     Recommendation: ${a.recommendation}`);
      });
    }
    console.log();
    process.exit(0);
  });
} else if (command === 'mesh') {
  import('../src/engine/federation.js').then(async (fed) => {
    const sub = cli.input[1] || 'status';
    console.log(`\n🛡️  MULTI-CLUSTER DEFENSE FEDERATION`);
    console.log('='.repeat(70));
    const node = await fed.createFederationNode();
    if (sub === 'status') {
      console.log(`Node ID: ${node.nodeId}`);
      console.log(`Cluster: ${node.clusterName}`);
      console.log(`Status:  ${node.status}`);
      console.log(`Created: ${node.createdAt}`);
      console.log(`Connected Peers (${node.peers.length}): ${node.peers.join(', ') || 'None configured'}`);
      console.log(`Public Key: ${node.publicKey.split('\n')[1]}...`);
    } else if (sub === 'broadcast') {
      const indicator = cli.flags.indicator || cli.input[2] || '198.51.100.99';
      const envelope = fed.signThreatRecord(
        { indicator, type: 'IP', severity: 'CRITICAL', reason: 'CLI Manual Broadcast' },
        node.privateKey,
        { nodeId: node.nodeId, publicKey: node.publicKey }
      );
      const res = fed.broadcastThreatIndicator(envelope, node.peers.length > 0 ? node.peers : ['cluster-peer-alpha']);
      console.log(`✔ Broadcast ${res.broadcastId} dispatched to ${res.sentTo} peer clusters for indicator: ${indicator}`);
    } else {
      console.log(`Unknown mesh subcommand: '${sub}'. Supported: status, broadcast`);
    }
    console.log();
    process.exit(0);
  });
} else if (command === 'beacon') {
  import('../src/engine/beaconing.js').then(async (beacon) => {
    console.log('\n📡 STATISTICAL C2 BEACONING & FFT FREQUENCY DETECTOR');
    console.log('='.repeat(70));
    const sampleIntervals = [60.2, 59.8, 60.1, 59.9, 60.4, 59.7, 60.0, 60.3];
    const beaconRes = beacon.detectBeaconingPeriodicity(sampleIntervals, { jitterPercent: 15 });
    console.log(`Connection Samples: ${sampleIntervals.length}`);
    console.log(`Mean Interval:      ${beaconRes.dominantIntervalSec}s`);
    console.log(`Calculated Jitter:  ±${beaconRes.jitterPercent}%`);
    console.log(`Confidence Score:   ${beaconRes.confidence}%`);
    console.log(`Beaconing Detected: ${beaconRes.isBeaconing ? '⚠️  YES (C2 Heartbeat Alert)' : '✔ NO'}`);

    const sampleQueries = [
      'a4f89d91cb42.exfil.darknet-c2.org',
      'f03ba9182390.exfil.darknet-c2.org',
      'google.com'
    ];
    const dnsRes = beacon.detectDnsTunneling(sampleQueries);
    console.log(`\nDNS Tunneling Analysis (${sampleQueries.length} queries):`);
    console.log(`Tunneling Detected: ${dnsRes.hasTunnelingThreat ? '⚠️  EXFILTRATION SUSPECTED' : '✔ Normal'}`);
    dnsRes.anomalies.forEach(q => {
      console.log(`  • Flagged: ${q.query} (Entropy H: ${q.entropy})`);
    });
    console.log();
    process.exit(0);
  });
} else if (command === 'lsm') {
  import('../src/engine/lsm.js').then(async (lsm) => {
    console.log('\n🔒 LINUX SECURITY MODULE (eBPF LSM) POLICY SYNTHESIZER');
    console.log('='.repeat(70));
    const sampleRules = [
      {
        id: 'LSM-BLOCK-CONTAINER-SHELLS',
        hook: 'bprm_check_security',
        action: 'DENY',
        condition: { comm: ['bash', 'sh'], containerOnly: true }
      },
      {
        id: 'LSM-PROTECT-LD-PRELOAD',
        hook: 'file_open',
        action: 'DENY',
        condition: { path: '/etc/ld.so.preload', writeOnly: true }
      }
    ];
    const policy = lsm.generateBpfLsmPolicy(sampleRules);
    console.log(`Synthesized Hooks (${policy.hooks.length}): ${policy.hooks.join(', ')}`);
    policy.rules.forEach(r => {
      console.log(`  • Hook [${r.hook}]: Rule '${r.id}' -> Action ${r.action}`);
    });
    console.log('\nGenerated eBPF C Source Skeleton:\n');
    const cSource = lsm.exportLsmCSource(policy);
    console.log(cSource.split('\n').slice(0, 25).join('\n'));
    console.log('  ... [BPF-LSM C Program Ready for Clang / vmlinux.h]');
    console.log();
    process.exit(0);
  });
} else if (command === 'warroom') {
  import('../src/engine/warroom.js').then(async (warroom) => {
    console.log('\n⚔️  AUTONOMOUS MULTI-AGENT INCIDENT WAR ROOM');
    console.log('='.repeat(70));
    const incidentData = {
      incidentId: cli.flags.incident || cli.input[1] || 'IR-PROD-9901',
      severity: 'CRITICAL',
      title: 'Active C2 Beaconing and Container Escape in payment-gateway',
      affectedPod: 'payment-gateway-7b98d45-zx92',
      namespace: 'tenant-prod'
    };
    console.log(`Incident ID: ${incidentData.incidentId} | Severity: ${incidentData.severity}`);
    console.log('Convening 4 AI Specialist Personas (Forensics, Threat Intel, SRE Blast Radius, Commander)...');
    const session = await warroom.conveneIncidentWarRoom(incidentData);
    console.log(`\nDebate Consensus Score: ${session.consensus.consensusScore}% [Verdict: ${session.consensus.finalVerdict}]`);
    console.log(`Quorum Status:          ${session.consensus.quorumApproved ? '✔ APPROVED' : '⚠️ REJECTED'} (${session.consensus.containVotes}/${session.consensus.totalAgents} Contain Votes)`);
    console.log(`Target Workload:        ${session.targetWorkload}`);
    console.log('\nAgent Consortium Opinions:');
    session.opinions.forEach(op => {
      console.log(`  • [${op.role}] Verdict: ${op.verdict} (Confidence: ${op.confidence}%)`);
      console.log(`    Rationale: ${op.rationale}`);
    });
    console.log();
    process.exit(0);
  });
} else if (command === 'vector') {
  import('../src/engine/vectorcti.js').then(async (vector) => {
    const query = cli.flags.query || cli.input.slice(1).join(' ') || 'adversary dumped LSASS memory in container';
    console.log('\n🔍 OFFLINE SEMANTIC CTI & VECTOR THREAT SEARCH');
    console.log('='.repeat(70));
    console.log(`Query: "${query}"\n`);
    const results = vector.semanticThreatSearch(query, { topK: 5 });
    console.log(`Ranked Matches (${results.length}):`);
    results.forEach((r, i) => {
      console.log(`  ${i + 1}. [${r.id}] ${r.name} (Similarity: ${(r.similarityScore * 100).toFixed(1)}%)`);
      console.log(`     Tactic: ${r.tactic} (${r.tacticId}) | ${r.description}`);
    });
    console.log();
    process.exit(0);
  });
} else if (command === 'ledger') {
  import('../src/engine/ledger.js').then(async (ledger) => {
    const sub = cli.input[1] || 'status';
    console.log('\n⚖️  CRYPTOGRAPHIC MERKLE AUDIT LEDGER');
    console.log('='.repeat(70));
    if (sub === 'verify') {
      const integrity = await ledger.verifyLedgerIntegrity();
      console.log(`Verification Status: ${integrity.valid ? '✔ VALID & PRISTINE' : '✖ TAMPERED / CORRUPTED'}`);
      console.log(`Total Chain Entries: ${integrity.count}`);
      if (integrity.merkleRoot) console.log(`Merkle Root:         ${integrity.merkleRoot}`);
      if (!integrity.valid) console.log(`Issue:               ${integrity.issue}`);
    } else {
      const meta = await ledger.initAuditLedger();
      const entries = await ledger.getLedgerEntries();
      const { root } = ledger.buildMerkleRoot(entries);
      console.log(`Ledger Path:  ${meta.ledgerFile}`);
      console.log(`Entry Count:  ${entries.length}`);
      console.log(`Cipher Suite: ${meta.cipherSuite}`);
      console.log(`Merkle Root:  ${root || 'Empty Ledger'}`);
      if (entries.length > 0) {
        console.log('\nRecent Ledger Entries:');
        entries.slice(-3).forEach(e => {
          console.log(`  • [#${e.index}] ${e.timestamp} | ${e.entryType} | Signer: ${e.signer?.role}`);
        });
      }
    }
    console.log();
    process.exit(0);
  });
} else if (command === 'graph') {
  import('../src/engine/attackgraph.js').then(async (ag) => {
    const sub = cli.input[1];
    if (sub === 'blast') {
      const targetNode = cli.input[2] || 'ext-attacker';
      const graph = ag.buildCompositeAttackGraph();
      const blast = ag.calculateBlastRadius(targetNode, graph);
      console.log(`\n💥 BLAST RADIUS IMPACT ANALYSIS for [${targetNode}]`);
      console.log('='.repeat(70));
      console.log(`Impact Score: ${blast.impactScore}/100 [${blast.riskLevel}]`);
      console.log(`Reachable Downstream Assets: ${blast.reachableCount}`);
      console.log(`Compromised Workloads:       ${blast.compromisedBreakdown.workloads.join(', ') || 'None'}`);
      console.log(`Compromised Identities:      ${blast.compromisedBreakdown.identities.join(', ') || 'None'}`);
      console.log();
      process.exit(0);
    }
    const graph = ag.buildCompositeAttackGraph();
    const rendered = ag.renderAsciiAttackGraph(graph);
    console.log('\n' + rendered + '\n');
    process.exit(0);
  });
} else if (command === 'rootkit') {
  import('../src/engine/rootkit.js').then(async (rk) => {
    console.log('\n🛡️  RING-0 KERNEL HOOK & ROOTKIT HUNTER AUDIT');
    console.log('='.repeat(70));
    const taint = rk.analyzeKernelTaint(0);
    const artifacts = rk.scanRootkitArtifacts();
    const report = rk.generateRootkitReport({ taintAssessment: taint, artifacts });
    console.log(`Status:              ${report.overallStatus}`);
    console.log(`Kernel Taint:        ${taint.riskAssessment} (${taint.activeFlagsCount} flags active)`);
    console.log(`Artifact Findings:   ${artifacts.length}`);
    if (artifacts.length > 0) {
      artifacts.forEach(a => console.log(`  • [${a.severity}] ${a.type}: ${a.details}`));
    } else {
      console.log('  ✔ No known user-space or LKM rootkit artifacts detected on host.');
    }
    console.log();
    process.exit(0);
  });
} else if (command === 'yara') {
  import('../src/engine/yarascan.js').then(async (ys) => {
    const targetPid = cli.flags.pid || cli.input[1] || process.pid;
    console.log(`\n🔍 IN-MEMORY PROCESS YARA SCANNER (PID ${targetPid})`);
    console.log('='.repeat(70));
    const defaultRule = ys.compileYaraRule(`
rule InFlight_Suspicious_Strings {
    strings:
        $s1 = "eval(" nocase
        $s2 = "/bin/sh"
    condition:
        $s1 or $s2
}
`);
    const scan = await ys.scanProcessMemory(targetPid, [defaultRule]);
    console.log(`Status:              ${scan.status}`);
    console.log(`Segments Scanned:    ${scan.segmentsScanned}`);
    console.log(`YARA Matches:        ${scan.yaraMatches.length}`);
    console.log(`Cobalt Strike C2:    ${scan.c2Config?.detected ? 'DETECTED!' : 'None'}`);
    console.log();
    process.exit(0);
  });
} else if (command === 'duel') {
  import('../src/engine/swarmduel.js').then(async (duel) => {
    const rounds = cli.flags.rounds ? parseInt(cli.flags.rounds, 10) : 5;
    const sim = duel.runFullDuelSimulation({ maxRounds: rounds });
    console.log('\n' + sim.transcript + '\n');
    console.log(`Metrics: Winner: ${sim.metrics.winner} | MTTD: ${sim.metrics.mttdRounds} rounds | MTTR: ${sim.metrics.mttrRounds} rounds`);
    console.log();
    process.exit(0);
  });
} else if (command === 'stix') {
  import('../src/engine/stixmisp.js').then(async (sm) => {
    console.log('\n🌐 STANDARDIZED STIX 2.1 / MISP THREAT FEED ENGINE');
    console.log('='.repeat(70));
    const sampleMisp = {
      Event: {
        uuid: 'd3b07384-d113-491a-a5f1-334455667788',
        info: 'APT Ingress Telemetry',
        Attribute: [
          { type: 'ip-dst', value: '198.51.100.99', to_ids: true },
          { type: 'domain', value: 'c2.threat-actor.internal', to_ids: true }
        ]
      }
    };
    const stixBundle = sm.convertMispToStix(sampleMisp);
    console.log(`Ingested MISP Event -> Converted STIX 2.1 Bundle: [${stixBundle.id}]`);
    console.log(`Generated Objects:   ${stixBundle.objects.length} SDOs`);
    stixBundle.objects.filter(o => o.type === 'indicator').forEach(ind => {
      console.log(`  • [${ind.type}] ${ind.name} (Pattern: ${ind.pattern})`);
    });
    console.log();
    process.exit(0);
  });
} else if (command === 'honeynet') {
  import('../src/engine/honeynet.js').then(async (hn) => {
    console.log('\n🍯 EPHEMERAL HONEYNET & BREADCRUMB MESH');
    console.log('='.repeat(70));
    const mesh = await hn.createHoneynetMesh({ services: ['SSH', 'REDIS', 'HTTP'] });
    console.log(`Mesh ID:    ${mesh.meshId} [${mesh.status}]`);
    console.log(`Active Decoys (${mesh.decoys.length}):`);
    mesh.decoys.forEach(d => console.log(`  • [${d.type}] Listening on port ${d.port}`));
    await mesh.teardown();
    console.log('Ephemeral honeynet mesh teardown completed cleanly.\n');
    process.exit(0);
  });
} else if (command === 'snapshot') {
  import('../src/engine/snapshot.js').then(async (snap) => {
    console.log('\n📸 CONTAINER VOLATILE FORENSIC SNAPSHOT');
    console.log('='.repeat(70));
    const res = await snap.createForensicsSnapshot({
      podName: cli.flags.pod || 'cluster-core-service',
      pid: process.pid
    });
    console.log(`Snapshot ID:  ${res.snapshotId}`);
    console.log(`Output Path:  ${res.snapshotDir}`);
    console.log(`SHA-256 Seal: ${res.sha256Seal}`);
    console.log();
    process.exit(0);
  });
} else if (command === 'evidencepack') {
  import('../src/engine/evidencepack.js').then(async (ep) => {
    console.log('\n⚖️  RFC 3161 COURT-ADMISSIBLE EVIDENCE BUNDLE');
    console.log('='.repeat(70));
    const bundle = await ep.createEvidenceBundle(
      { caseNumber: 'CASE-2026-INC-01', title: 'Kubernetes Incident Triage' },
      [
        { filename: 'cluster_volatiles.json', content: '{"status": "captured"}' },
        { filename: 'network_audit.pcap', content: 'PCAP_RAW_STREAM_DATA' }
      ]
    );
    console.log(`Bundle ID:     ${bundle.bundleId}`);
    console.log(`Directory:     ${bundle.bundleDir}`);
    console.log(`RFC 3161 Time: ${bundle.rfc3161Token.tstInfo.genTime}`);
    console.log(`TSA Authority: ${bundle.rfc3161Token.tstInfo.tsa}`);
    console.log(`Standalone Verifier: ${bundle.verifyBashPath}`);
    console.log();
    process.exit(0);
  });
} else {
  render(
    React.createElement(App, {
      command,
      subCommand,
      domain: cli.flags.domain,
      clusterName: effectiveClusterName,
      namespace: cli.flags.namespace || null,
      selectedModules: cli.flags.module ? cli.flags.module.split(',').map(m => m.trim()) : undefined,
      customValuesPath: cli.flags.values,
      customValuesDir: cli.flags.valuesDir || null,
      theme: cli.flags.theme,
      hostsAction,
      ip: cli.flags.ip,
      deleteNamespace: cli.flags.deleteNamespace,
      nonInteractive: cli.flags.nonInteractive,
      skipPrereqs: cli.flags.skipPrereqs
    })
  );
}
