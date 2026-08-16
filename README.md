# 🦇 Vigilante

**Vigilante** is a modern, modular terminal CLI application built with **React** and **Ink** designed to orchestrate local Kubernetes environments using **k3d**, automatically issue and trust local TLS certificates via **mkcert**, and dynamically deploy modular security and SOC packages like **OpenSearch SIEM** for network threat analysis.

---

## Asciinema demo

[![asciicast](https://asciinema.org/a/vG4odD90z9xHqw3a.svg)](https://asciinema.org/a/vG4odD90z9xHqw3a)

---

## 🌟 Features

- **Ink Terminal UI**: Interactive dashboards, step spinners, dynamic logs, and keyboard-driven module selectors.
- **Interactive Click-to-Copy & Quick Shortcuts**: Click on any pane in interactive mode (or press `[1-6]`) to copy text/URLs to your system clipboard, and press `[t]` anytime from the status dashboard to trigger threat simulations.
- **Automated k3d Orchestration**: Spin up lightweight K3s clusters in Docker with Ingress port bindings (`80` / `443`), defaulting straight to the live status dashboard on completion.
- **Zero-Config Local TLS (`mkcert`)**: Generate wildcard certificates (`*.vigilante.local`) trusted by your operating system keychain and automatically inject them as Kubernetes Ingress secrets.
- **Automated Local DNS (`hostr`)**: Automatically synchronizes `/etc/hosts` with managed domain mappings (`127.0.0.1 vigilante.local`, `127.0.0.1 siem.vigilante.local`) in an idempotent, safe block with sudo elevation when required.
- **Modular Package Ecosystem & Custom Values**: Declarative `BaseModule` system with easy `values.yaml` customization (`vigilante values export`) to tweak chart configurations without modifying code.
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
pnpm install
pnpm link --global
```

### 2. Provision Local Environment
```bash
# Interactive mode with package selector (auto-configures TLS, DNS, & k3d)
vigilante up

# Or with custom domain
vigilante up --domain dev.local
```

### 3. Local DNS & Host Resolution (`hostr`)
`/etc/hosts` is automatically updated during `vigilante up`. You can also manage it directly at any time:
```bash
# Sync domain mappings to /etc/hosts
vigilante hostr

# Check current resolution status
vigilante hostr --check

# Remove managed entries from /etc/hosts
vigilante hostr --remove
```

### 4. Access OpenSearch SIEM
Open your browser and navigate to:
```text
https://siem.vigilante.local
```
- **Username**: `admin`
- **Password**: `Admin123456!` *(or `admin`)*
- *(Local TLS certificate is automatically trusted via mkcert root CA; dev mode allows direct access without auth friction)*

---

## 🛠️ CLI Commands & Usage

```bash
$ vigilante [command] [options]

Commands:
  up          Provision k3d cluster, certificates, and deploy security modules
  down        Tear down k3d cluster and clean up resources
  status      Check status of prerequisites, cluster, certificates, and DNS
  modules     List available and installed security modules
  threat-sim  Trigger network threat simulation batch against SIEM
  hosts/hostr Sync or manage local domain mappings in /etc/hosts
  values      Inspect or export customizable Helm chart values.yaml files

Options:
  --domain, -d       Local top-level domain (Default: vigilante.local)
  --cluster-name, -c Cluster name (Default: vigilante-dev)
  --module, -m       Specific module(s) to install (comma-separated, Default: vigil-soc)
  --values, -f       Path to custom Helm values override file
  --values-dir       Path to directory with custom values files (Default: ./values)
  --ip               Target IP for hosts mapping (Default: 127.0.0.1)
  --remove           Remove managed entries from /etc/hosts (for hosts/hostr)
  --check            Check /etc/hosts status without modifying (for hosts/hostr)
  --non-interactive  Run without interactive prompts
  --skip-prereqs     Skip prerequisite verification
```

### Examples
```bash
# Check system and cluster health (including /etc/hosts status)
vigilante status

# Export editable starter values.yaml files to ./values/
vigilante values export

# Inspect active default and override values files
vigilante values

# Deploy using custom values overrides
vigilante up --values ./values/vigil-soc/opensearch.yaml

# Sync local DNS mappings for custom domain
vigilante hostr --domain custom.local

# Trigger sample network threat injection to test SIEM detection rules
vigilante threat-sim

# Destroy the cluster and clean up hosts
vigilante down
```

---

## 🎮 Interactive Keyboard Action Menu

In interactive mode, Vigilante provides a persistent action menu allowing you to navigate between operations instantly at any time:

| Key | Action | Description |
|---|---|---|
| `[u]` / `[U]` | **Up (Deploy)** | Provision k3d cluster, certificates, and security modules |
| `[d]` / `[D]` | **Down (Teardown)** | Tear down k3d cluster and clean up `/etc/hosts` |
| `[s]` / `[S]` | **Status** | View live environment health, prerequisites, and endpoints |
| `[t]` / `[T]` | **Threat-Sim** | Trigger network threat simulations against SIEM |
| `[h]` / `[H]` | **Hostr** | Synchronize domain mappings in `/etc/hosts` |
| `[v]` / `[V]` | **Values** | Inspect and manage Helm chart configurations |
| `[m]` / `[M]` | **Modules** | View available security packages |
| `[1-6]` / 🖱️ | **Copy Pane** | Copy individual pane text / URL to system clipboard |
| `[q]` / `[Esc]` | **Quit** | Exit the CLI application |

---

## ⚙️ Customizing Helm Chart Values (`values.yaml`)

Vigilante allows you to customize the underlying Helm charts for each security module without modifying source code.

### 1. Interactive Values Manager & `$EDITOR` Integration
Open the interactive values screen anytime by running `vigilante values` or pressing `[v]` from the main menu:
```bash
vigilante values
```
- **Chart Selector**: Navigate configurable charts using `[↑/↓]` or `[j/k]`.
- **Open in `$EDITOR`**: Hit `[e]` or `[Enter]` on any chart to immediately launch your environment's `$EDITOR` (or `$VISUAL`, defaulting to `nano`). If the override file does not exist yet, Vigilante automatically initializes it with clean starter defaults for you!
- **Quick Export**: Press `[x]` to export all starter templates at once.

### 2. Export Starter Values via CLI
Generate editable starter values files for all installed modules directly:
```bash
vigilante values export
```
This generates:
- `./values/opensearch/opensearch.yaml` (OpenSearch SIEM core cluster memory, CPU, replica settings)
- `./values/opensearch/opensearch-dashboards.yaml` (OpenSearch Dashboards UI, ingress, resources)
- `./values/vigil-soc/vigil.yaml` (Vigil AI SOC: backend API, daemon orchestrator, LLM/agent workers, postgres, redis, ingress)

### 3. Edit & Apply Custom Overrides
Modify the YAML files in `./values/` as needed (e.g. increase memory limits or enable persistence). When you run:
```bash
vigilante up
```
Vigilante automatically detects `./values/<module>/<chart>.yaml` and layers your overrides on top of the module defaults!

You can also pass explicit files or directories via the CLI:
```bash
vigilante up -f ./my-custom-opensearch.yaml
vigilante up --values-dir ./custom-values
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
      dependencies: ['opensearch']
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

## 📋 Debug Logging (`/tmp/.vigilante.log`)

Vigilante includes a persistent, low-overhead debug file logger that records real-time lifecycle events to `/tmp/.vigilante.log`:

- **Recorded Information**:
  - Application startup arguments, active flags, and runtime mode.
  - Interactive keyboard inputs and workflow navigation triggers.
  - Subprocess shell execution (`exec` / `execStream`), commands executed, and output streams.
  - Kubernetes / Helm / k3d task state transitions.
  - Detailed error messages and full stack traces.

### Live Log Streaming
To monitor or debug operations in real-time, open a secondary terminal and run:
```bash
tail -f /tmp/.vigilante.log
```

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
│   │   ├── cluster.js            # k3d cluster lifecycle provisioner
│   │   ├── hosts.js              # /etc/hosts domain resolution sync & cleanup (hostr)
│   │   ├── pods.js               # Live Kubernetes pods querying & watch poller (-A -o wide)
│   │   └── helm.js               # Dynamic Helm values resolver, renderer & exporter
│   ├── modules/
│   │   ├── base.js               # Abstract BaseModule contract
│   │   ├── registry.js           # Module registry & dependency resolver
│   │   ├── opensearch/           # Package 1: OpenSearch SIEM Analytics & Dashboards
│   │   │   ├── index.js          # OpenSearchModule lifecycle implementation
│   │   │   ├── values/           # Default Helm values templates (opensearch, opensearch-dashboards)
│   │   │   └── manifests/        # SIGMA threat rules & threat simulation Job
│   │   └── vigil-soc/            # Package 2: Vigil AI-Native SOC Investigation Platform
│   │       ├── index.js          # VigilSOCModule lifecycle implementation
│   │       ├── charts/           # Vendored Helm charts (charts/vigil)
│   │       └── values/           # Default Helm values templates (vigil.yaml)
│   ├── ui/                       # React & Ink UI Components
│   │   ├── App.js                # Master terminal view controller & router
│   │   ├── Header.js             # Terminal banner & ASCII styling
│   │   ├── MenuBar.js            # Persistent interactive keyboard action menu
│   │   ├── TaskRunner.js         # Animated task spinner & log viewer
│   │   ├── SelectModules.js      # Interactive keyboard package selector
│   │   ├── StatusDashboard.js    # Comprehensive diagnostics dashboard
│   │   ├── ThreatSimView.js      # Network threat simulation runner
│   │   ├── ValuesView.js         # Interactive Values & $EDITOR manager
│   │   ├── ModulesView.js        # Interactive Security Modules & Package Manager
│   │   ├── PodsView.js           # Live Kubernetes Pods Monitor (-A -o wide table)
│   │   └── ClipboardManager.js   # Click-to-copy provider & SGR mouse tracker
│   └── utils/
│       ├── exec.js               # Subprocess execution & streaming with debug logging
│       ├── editor.js             # Terminal TTY suspension & $EDITOR launcher
│       ├── clipboard.js          # Multi-platform clipboard copy utility (OSC 52, Wayland, X11, macOS)
│       └── logger.js             # Centralized debug file logger (/tmp/.vigilante.log)
├── tests/
│   ├── test-values.js            # Unit test suite for Helm values engine & template rendering
│   ├── test-editor.js            # Unit test suite for editor & starter file initialization
│   ├── test-modules.js           # Unit test suite for module registry & dependency resolver
│   ├── test-pods.js              # Unit test suite for pod status formatting & live watcher
│   └── test-clipboard.js         # Unit test suite for clipboard & ANSI stripping
├── values/                       # Exported starter & custom user Helm values overrides
├── package.json
└── README.md
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
