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
    threat-sim  Trigger network threat simulation batch against SIEM
    playbooks   List all built-in and custom threat simulation scenarios
    instances   List and inspect all k3d cluster instances and their directories
    hosts/hostr Sync local domain mappings into /etc/hosts
    values      Manage, list, or export customizable chart values.yaml files
    config      Inspect, initialize, or display $XDG_CONFIG_HOME/vigilante/config.yaml
    ai/ask      Launch AI Security & Forensics Analyst console (Ollama/Claude/GPT)
    nist        Inspect NIST SP 800-61 Rev. 2 framework and active incident manifests
    mcp         Launch Model Context Protocol (MCP) server over stdio for LLMs

  Options
    --domain, -d       Local top-level domain (Default: ${config.defaults?.domain || 'vigilante.local'})
    --cluster-name, -c Cluster name (Default: ${config.defaults?.clusterName || 'vigilante-dev'})
    --instance, -i     Instance name alias for --cluster-name
    --namespace, -n    Target Kubernetes namespace (e.g. 'default', 'threat-lab', 'tenant-a')
    --module, -m       Specific module(s) to install (comma-separated, Default: vigil-soc)
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
    $ vigilante up -n tenant-alpha -m opensearch,vigil-soc
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
      nonInteractive: cli.flags.nonInteractive,
      skipPrereqs: cli.flags.skipPrereqs
    })
  );
}
