# 🦇 Vigilante

**Vigilante** is a modern, modular terminal CLI application built with **React** and **Ink** designed to orchestrate local Kubernetes environments using **k3d**, automatically issue and trust local TLS certificates via **mkcert**, and dynamically deploy modular security and SOC packages like **OpenSearch SIEM** for network threat analysis.

---

## 🌟 Features

- **Ink Terminal UI**: Interactive dashboards, step spinners, dynamic logs, and keyboard-driven module selectors.
- **Automated k3d Orchestration**: Spin up lightweight K3s clusters in Docker with Ingress port bindings (`80` / `443`).
- **Zero-Config Local TLS (`mkcert`)**: Generate wildcard certificates (`*.vigilante.local`) trusted by your operating system keychain and automatically inject them as Kubernetes Ingress secrets.
- **Modular Package Ecosystem**: Clean `BaseModule` architecture allowing security tools (SIEM, IDS/IPS, telemetry, analyzers) to be plugged in dynamically.
- **vigil-SOC (OpenSearch SIEM)**: Out-of-the-box OpenSearch and OpenSearch Dashboards configured for SIEM and network threat analysis at `https://siem.vigilante.local`.
- **Network Threat Pipeline & Simulator**: Pre-packaged SIGMA threat detection rules and an automated threat injection simulator (Port Scanning, SSH Brute Force, DNS Tunneling) to validate SIEM alerts.

---

## 📋 Prerequisites

Vigilante automatically verifies your local environment before spinning up resources. Ensure the following tools are installed:

| Tool | Purpose | Install Command |
| :--- | :--- | :--- |
| **Docker** | Container Engine | [Docker Desktop / Engine](https://docs.docker.com/get-docker/) |
| **k3d** | Lightweight K3s in Docker | `curl -s https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh \| bash` |
| **mkcert** | Local Trusted CA & TLS | `brew install mkcert` or `apt install libnss3-tools && brew/apt install mkcert` |
| **kubectl** | Kubernetes CLI | `brew install kubectl` or [Kubernetes Docs](https://kubernetes.io/docs/tasks/tools/) |
| **Helm** | Kubernetes Package Manager | `curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 \| bash` |

---

## 🚀 Quick Start

### 1. Install & Link CLI
```bash
npm install
npm link
```

### 2. Provision Local Environment
```bash
# Interactive mode with package selector
vigilante up

# Or with custom domain
vigilante up --domain dev.local
```

### 3. Configure Local DNS
Add the following line to `/etc/hosts`:
```text
127.0.0.1 siem.vigilante.local
```

### 4. Access OpenSearch SIEM
Open your browser and navigate to:
```
https://siem.vigilante.local
```
*(TLS certificate is automatically trusted via mkcert root CA)*

---

## 🛠️ CLI Commands & Usage

```bash
$ vigilante [command] [options]

Commands:
  up          Provision k3d cluster, certificates, and deploy security modules
  down        Tear down k3d cluster and clean up resources
  status      Check status of prerequisites, cluster, certificates, and modules
  modules     List available and installed security modules
  threat-sim  Trigger network threat simulation batch against SIEM

Options:
  --domain, -d       Local top-level domain (Default: vigilante.local)
  --cluster-name, -c Cluster name (Default: vigilante-dev)
  --module, -m       Specific module(s) to install (comma-separated, Default: vigil-soc)
  --non-interactive  Run without interactive prompts
  --skip-prereqs     Skip prerequisite verification
```

### Examples
```bash
# Check system and cluster health
vigilante status

# Trigger sample network threat injection to test SIEM detection rules
vigilante threat-sim

# Destroy the cluster and clean up
vigilante down
```

---

## 🧩 Modular Package Architecture

Every package extends `BaseModule` from `src/modules/base.js`:

```javascript
import { BaseModule } from './base.js';

export class MyCustomSecurityModule extends BaseModule {
  constructor() {
    super({
      id: 'custom-ids',
      name: 'Custom IDS',
      description: 'Network IDS sensor and packet analyzer',
      category: 'ids',
      version: '1.0.0',
      dependencies: ['vigil-soc']
    });
  }

  async install({ domain, certPath, keyPath, clusterName, onLog }) {
    // 1. Deploy manifests or Helm chart
    // 2. Configure Ingress with domain and certs
  }

  async uninstall({ clusterName, onLog }) {
    // Cleanup resources
  }

  async status({ domain, clusterName }) {
    // Return health and pod status
  }

  async getEndpoints({ domain }) {
    return [{ name: 'IDS Web UI', url: `https://ids.${domain}`, description: 'IDS Sensor UI' }];
  }
}
```

Register new modules in `src/modules/registry.js` to expose them across the CLI and interactive installer.

---

## 📂 Project Structure

```
vigilante/
├── bin/
│   └── vigilante.js              # Executable entry point (Meow CLI)
├── src/
│   ├── index.js                  # Programmatic library exports
│   ├── engine/
│   │   ├── prereqs.js            # Tooling verification (docker, k3d, mkcert, kubectl, helm)
│   │   ├── certs.js              # mkcert CA & TLS certificates manager
│   │   └── cluster.js            # k3d cluster lifecycle provisioner
│   ├── modules/
│   │   ├── base.js               # Abstract BaseModule contract
│   │   ├── registry.js           # Module registry & dependency resolver
│   │   └── vigil-soc/            # Package 1: OpenSearch SIEM & Threat Ingestion Pipeline
│   │       ├── index.js          # VigilSOCModule lifecycle implementation
│   │       ├── values.yaml       # OpenSearch & Dashboards Helm values
│   │       └── manifests/
│   │           ├── network-threat-pipeline.yaml  # SIGMA threat detection rules
│   │           └── threat-simulator.yaml        # Network threat event generator Job
│   ├── ui/                       # React & Ink UI Components
│   │   ├── App.js                # Master terminal view controller
│   │   ├── Header.js             # Terminal banner & ASCII styling
│   │   ├── TaskRunner.js         # Animated task spinner & log viewer
│   │   ├── SelectModules.js      # Interactive keyboard package selector
│   │   ├── StatusDashboard.js    # Comprehensive diagnostics dashboard
│   │   └── ThreatSimView.js      # Network threat simulation runner
│   └── utils/
│       ├── exec.js               # Subprocess execution & streaming
│       └── logger.js             # Event-based log streaming
├── design.md                     # Architectural planning document
├── package.json
└── README.md
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
