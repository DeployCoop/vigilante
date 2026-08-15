Here is an architectural blueprint and starter code for vigilante, an Ink-based React CLI designed to provision local k3d Kubernetes clusters, issue local TLS certificates via mkcert, and dynamically load modular SOC packages like OpenSearch SIEM.
1. Project Architecture
To support a modular plugin ecosystem (where vigil-SOC is the initial package), divide the codebase into core CLI infrastructure, environment provisioners, and package plugins.
vigilante/
├── bin/
│   └── vigilante.js          # CLI entry point (Meow/Commander)
├── src/
│   ├── ui/                   # Ink React Components
│   │   ├── App.jsx           # Main Ink Dashboard / Orchestrator
│   │   ├── TaskRunner.jsx    # Step execution & spinners
│   │   └── SelectModules.jsx # Package selector UI
│   ├── engine/               # Infrastructure controllers
│   │   ├── prerereqs.js      # Checks docker, k3d, mkcert, helm
│   │   ├── certs.js          # Mkcert CA & TLS generator
│   │   └── cluster.js        # K3d lifecycle runner
│   ├── modules/              # Package Architecture
│   │   ├── base.js           # Abstract Module class
│   │   └── vigil-soc/        # Package 1: OpenSearch SIEM
│   │       ├── index.js
│   │       ├── values.yaml
│   │       └── manifests/
│   └── utils/
│       └── exec.js           # Child process execution wrapper
└── package.json


2. Dependencies (package.json)
{
  "name": "vigilante",
  "version": "0.1.0",
  "type": "module",
  "bin": {
    "vigilante": "./bin/vigilante.js"
  },
  "dependencies": {
    "execa": "^8.0.1",
    "ink": "^4.4.1",
    "ink-select-input": "^5.0.0",
    "ink-spinner": "^5.0.0",
    "meow": "^12.1.1",
    "react": "^18.2.0"
  }
}


3. Core Engine: Certs & K3d Provisioner
vigilante needs to check local prerequisites, generate certificates via mkcert, and inject those secrets into the k3d cluster creation phase.
Local Certs & K3d Handler (src/engine/cluster.js)
import { execa } from 'execa';
import fs from 'node:fs/promises';
import path from 'node:path';

export async function setupCertificates(domain = 'vigilante.local') {
  const certDir = path.resolve(process.cwd(), '.certs');
  await fs.mkdir(certDir, { recursive: true });

  const certPath = path.join(certDir, `${domain}.pem`);
  const keyPath = path.join(certDir, `${domain}-key.pem`);

  // Ensure CA is installed locally
  await execa('mkcert', ['-install']);
  
  // Generate wildcard certs for local subdomains
  await execa('mkcert', [
    '-cert-file', certPath,
    '-key-file', keyPath,
    domain,
    `*.${domain}`
  ]);

  return { certPath, keyPath };
}

export async function createK3dCluster(clusterName = 'vigilante-dev') {
  // Check if cluster exists
  const { stdout } = await execa('k3d', ['cluster', 'list', '-o', 'json']);
  const clusters = JSON.parse(stdout || '[]');
  
  if (clusters.some(c => c.name === clusterName)) {
    return { status: 'exists' };
  }

  // Spin up k3d cluster with Traefik ingress enabled and HTTP/HTTPS port mappings
  await execa('k3d', [
    'cluster', 'create', clusterName,
    '--agents', '1',
    '-p', '80:80@loadbalancer',
    '-p', '443:443@loadbalancer',
    '--k3s-arg', '--disable=traefik@server:0' // Optional: Disable default if supplying custom NGINX/Traefik
  ]);

  return { status: 'created' };
}


4. Package Contract & Module: vigil-SOC
Every package implements a standard interface extending a BaseModule.
Base Module (src/modules/base.js)
export class BaseModule {
  constructor(name, description) {
    this.name = name;
    this.description = description;
  }

  async install(options) {
    throw new Error('Install method must be implemented');
  }

  async uninstall(options) {
    throw new Error('Uninstall method must be implemented');
  }
}


Module Implementation (src/modules/vigil-soc/index.js)
This provisions OpenSearch & OpenSearch Dashboards via Helm configured for SIEM and network threat analysis ingestion.
import { execa } from 'execa';
import { BaseModule } from '../base.js';

export class VigilSOCModule extends BaseModule {
  constructor() {
    super('vigil-SOC', 'OpenSearch SIEM & Network Threat Ingestion Pipeline');
  }

  async install({ domain, certPath, keyPath }) {
    // 1. Create namespace
    await execa('kubectl', ['create', 'namespace', 'vigil-soc', '--dry-run=client', '-o', 'yaml', '|', 'kubectl', 'apply', '-f', '-'], { shell: true });

    // 2. Inject Mkcert Secrets for Ingress TLS
    await execa('kubectl', [
      'create', 'secret', 'tls', 'vigil-soc-tls',
      `--cert=${certPath}`,
      `--key=${keyPath}`,
      '-n', 'vigil-soc',
      '--dry-run=client', '-o', 'yaml', '|', 'kubectl', 'apply', '-f', '-'
    ], { shell: true });

    // 3. Add Helm Repositories
    await execa('helm', ['repo', 'add', 'opensearch', 'https://opensearch-project.github.io/helm-charts/']);
    await execa('helm', ['repo', 'update']);

    // 4. Install OpenSearch SIEM Single-Node Dev Cluster
    await execa('helm', [
      'upgrade', '--install', 'opensearch', 'opensearch/opensearch',
      '--namespace', 'vigil-soc',
      '--set', 'singleNode=true',
      '--set', 'persistence.enabled=false', // Dev configuration
      '--set', 'resources.requests.memory=2Gi'
    ]);

    // 5. Install Dashboards
    await execa('helm', [
      'upgrade', '--install', 'opensearch-dashboards', 'opensearch/opensearch-dashboards',
      '--namespace', 'vigil-soc',
      '--set', 'opensearchHosts=http://opensearch-cluster-master:9200',
      '--set', `ingress.enabled=true`,
      '--set', `ingress.hosts[0].host=siem.${domain}`,
      '--set', `ingress.hosts[0].paths[0].path=/`,
      '--set', `ingress.hosts[0].paths[0].pathType=Prefix`,
      '--set', `ingress.hosts[0].paths[0].backend.serviceName=`,
      '--set', `ingress.tls[0].hosts[0]=siem.${domain}`,
      '--set', `ingress.tls[0].secretName=vigil-soc-tls`
    ]);
  }
}


5. Ink Terminal Interface (src/ui/App.jsx)
An interactive React CLI using Ink to display spinners and step outputs.
import React, { useState, useEffect } from 'react';
import { Text, Box, render } from 'ink';
import Spinner from 'ink-spinner';
import { setupCertificates, createK3dCluster } from '../engine/cluster.js';
import { VigilSOCModule } from '../modules/vigil-soc/index.js';

const STEPS = {
  CERTS: 'Generating local TLS certificates via mkcert...',
  K3D: 'Spinning up k3d Kubernetes cluster...',
  VIGIL_SOC: 'Deploying vigil-SOC (OpenSearch SIEM)...',
  DONE: 'Vigilante environment ready!'
};

export const App = ({ domain = 'vigilante.local' }) => {
  const [currentStep, setCurrentStep] = useState(STEPS.CERTS);
  const [logs, setLogs] = useState([]);
  const [isCompleted, setIsCompleted] = useState(false);

  useEffect(() => {
    async function bootstrap() {
      try {
        // Step 1: Generate Certs
        setLogs(l => [...l, '🔑 Initializing mkcert CA and issuing TLS keys...']);
        const certs = await setupCertificates(domain);

        // Step 2: Provision K3d
        setCurrentStep(STEPS.K3D);
        setLogs(l => [...l, '🐳 Orchestrating k3d cluster with HTTP/443 ingress bindings...']);
        await createK3dCluster();

        // Step 3: Install vigil-SOC Module
        setCurrentStep(STEPS.VIGIL_SOC);
        setLogs(l => [...l, '🛡️  Installing OpenSearch SIEM & Security Dashboards...']);
        const soc = new VigilSOCModule();
        await soc.install({ domain, ...certs });

        // Step 4: Done
        setCurrentStep(STEPS.DONE);
        setIsCompleted(true);
      } catch (err) {
        setLogs(l => [...l, `❌ Error: ${err.message}`]);
      }
    }

    bootstrap();
  }, []);

  return (
    <Box flexDirection="column" padding={1} borderStyle="round" borderColor="cyan">
      <Text bold color="red">
        🦇 VIGILANTE CLI — Local Threat Analysis Sandbox
      </Text>
      <Box marginTop={1} flexDirection="column">
        {logs.map((log, index) => (
          <Text key={index} color="gray">{log}</Text>
        ))}
      </Box>

      <Box marginTop={1}>
        {!isCompleted ? (
          <Text color="yellow">
            <Spinner type="dots" /> {currentStep}
          </Text>
        ) : (
          <Box flexDirection="column" marginTop={1}>
            <Text color="green" bold>✔ All modules deployed successfully!</Text>
            <Text>
              Access SIEM Dashboard: <Text color="cyan" underline>https://siem.{domain}</Text>
            </Text>
          </Box>
        )}
      </Box>
    </Box>
  );
};


Entry CLI Executable (bin/vigilante.js)
#!/usr/bin/env node
import React from 'react';
import { render } from 'ink';
import meow from 'meow';
import { App } from '../src/ui/App.jsx';

const cli = meow(`
  Usage
    $ vigilante [command] [options]

  Options
    --domain, -d  Local top-level domain (Default: vigilante.local)

  Examples
    $ vigilante init --domain dev.local
`, {
  importMeta: import.meta,
  flags: {
    domain: {
      type: 'string',
      shortFlag: 'd',
      default: 'vigilante.local'
    }
  }
});

render(<App domain={cli.flags.domain} />);


6. Recommended Network Threat Pipeline Extensions for vigil-SOC
To complete network threat analysis capabilities inside OpenSearch SIEM:
Ingestion Layer (Zeek / Suricata): Add a Helm sub-chart or DaemonSet to vigil-SOC running Suricata (for IDS/IPS rule matching) or Zeek (for structured network event log extraction).
Log Collector (Logstash / FluentBit): Route raw PCAP/Interface logs from nodes into OpenSearch standard indices using ECS (Elastic Common Schema) mapping.
Pre-configured Detection Rules: Package a Kubernetes Job inside vigil-SOC that auto-imports pre-built OpenSearch Security Analytics detection rules (SIGMA rules) for automated network anomaly alerts.

