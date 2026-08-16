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
| `[p]` / `[P]` | **Pods (Live)** | Live Kubernetes Pods monitor (`-A -o wide`) with logs, describe, shell |
| `[n]` / `[N]` | **Nmap (Scan)** | Data collection & network reconnaissance scanner |
| `[x]` / `[X]` | **XML Map** | Interactive XML network topology & port matrix visualizer |
| `[t]` / `[T]` | **Threat-Sim** | Trigger network threat simulations against SIEM |
| `[h]` / `[H]` | **Hostr** | Synchronize domain mappings in `/etc/hosts` |
| `[v]` / `[V]` | **Values** | Inspect and manage Helm chart configurations |
| `[m]` / `[M]` | **Modules** | View and toggle security packages |
| `[1-6]` / 🖱️ | **Copy Pane** | Copy individual pane text / URL to system clipboard |
| `[q]` / `[Esc]` | **Quit** | Exit the CLI application |

---

## 🎨 XDG Configuration & Theming (`config.yaml`)

Vigilante supports standard **XDG Base Directory** configurations at `$XDG_CONFIG_HOME/vigilante/` (defaulting to `~/.config/vigilante/`).

```
$XDG_CONFIG_HOME/vigilante/
├── config.yaml          # Global configuration, themes, custom colors, and CLI defaults
├── nmaps/               # Historical Nmap scan reports (.nmap, .xml)
└── values/              # Global Helm values overrides for all security packages
    ├── opensearch/
    │   ├── opensearch.yaml
    │   └── opensearch-dashboards.yaml
    └── vigil-soc/
        └── vigil.yaml
```

### 1. Theming & Color Customization
Vigilante comes with built-in color themes and supports fine-grained color customization in `config.yaml`:

- **Predefined Themes**: `default`, `cyberpunk`, `dracula`, `nord`, `matrix`, `monokai`.
- **Switch Theme on the Fly**:
  ```bash
  vigilante up --theme dracula
  vigilante pods --theme cyberpunk
  ```
- **Edit `$XDG_CONFIG_HOME/vigilante/config.yaml`**:
  ```yaml
  theme:
    name: "dracula" # default, cyberpunk, dracula, nord, matrix, monokai
    colors:
      primary: "magenta"
      secondary: "cyan"
      accent: "green"
      border: "magenta"
      header: "magenta"
      success: "green"
      warning: "yellow"
      error: "red"
      muted: "gray"

  defaults:
    domain: "vigilante.local"
    clusterName: "vigilante-dev"
    ip: "127.0.0.1"

  # Host Resolution (hostr) Settings
  # Controls automatic /etc/hosts management during cluster up/down.
  # Note: Even when disabled, manual 'vigilante hostr' or pressing [h] remains available.
  hostr:
    enabled: true         # Set to false to disable automatic /etc/hosts modifications
    autoSyncOnUp: true    # Automatically sync local domain mappings on 'vigilante up'
    autoCleanOnDown: true # Automatically clean up domain mappings on 'vigilante down'

  behavior:
    autoWatchPods: true
    podsPollIntervalMs: 2000
  ```

### 2. Inspect & Manage Config via CLI
```bash
# Print config path
vigilante config path

# View config summary and active theme
vigilante config

# Initialize default config and values directory
vigilante config init
```

---

## ⚙️ Customizing Helm Chart Values (`values.yaml`)

Vigilante allows you to customize the underlying Helm charts for each security module without modifying source code.

### 1. Values Override Hierarchy
When deploying charts, Vigilante checks for custom `values.yaml` files in the following priority order:
1. **Explicit CLI Flag**: `--values / -f <path>` or `--values-dir <dir>`
2. **Local Workspace**: `./values/<module>/<chart>.yaml` or `./config/values/...`
3. **Global XDG Directory**: `$XDG_CONFIG_HOME/vigilante/values/<module>/<chart>.yaml`
4. **Built-in Module Defaults**: `src/modules/<module>/values/<chart>.yaml`

### 2. Interactive Values Manager & `$EDITOR` Integration
Open the interactive values screen anytime by running `vigilante values` or pressing `[v]` from the main menu:
```bash
vigilante values
```
- **Chart Selector**: Navigate configurable charts using `[↑/↓]` or `[j/k]`.
- **Open in `$EDITOR`**: Hit `[e]` or `[Enter]` on any chart to immediately launch your environment's `$EDITOR` (or `$VISUAL`, defaulting to `nano`). If the override file does not exist yet, Vigilante automatically initializes it with clean starter defaults for you!
- **Edit `config.yaml`**: Press `[c]` to quickly edit `$XDG_CONFIG_HOME/vigilante/config.yaml` to change themes or defaults.
- **Export Local**: Press `[x]` to export starter templates into local `./values/`.
- **Export Global (XDG)**: Press `[g]` to export starter templates into `$XDG_CONFIG_HOME/vigilante/values/`.

### 3. Export Starter Values via CLI
Generate editable starter values files for all installed modules directly:
```bash
# Export to local workspace (./values/)
vigilante values export

# Export to global XDG directory (~/.config/vigilante/values/)
vigilante values export --values-dir ~/.config/vigilante/values
```
This generates:
- `opensearch/opensearch.yaml` (OpenSearch SIEM core cluster memory, CPU, replica settings)
- `opensearch/opensearch-dashboards.yaml` (OpenSearch Dashboards UI, ingress, resources)
- `vigil-soc/vigil.yaml` (Vigil AI SOC: backend API, daemon orchestrator, LLM/agent workers, postgres, redis, ingress)

---

## 📡 Data Collection & Network Reconnaissance (Nmap)

Vigilante features a dedicated **Data Collection & Reconnaissance Pane** powered by **Nmap**. Scan individual host targets or map entire network subnets via CIDR notation (e.g. `10.0.1.0/24`, `192.168.1.0/24`, `10.42.0.0/16`), automatically archiving structured reports into `$XDG_CONFIG_HOME/vigilante/nmaps/`.

### 1. Interactive Nmap Console & Network Mapper
Launch the scanner anytime via `vigilante scan` / `vigilante nmap` or by pressing **`[n]`** from the main menu:

- **Scan Profiles**:
  - `🗺️  Network Ping Sweep / Host Discovery`: Discover all live hosts across a CIDR network block (`-sn -T4`)
  - `⚡ Network Sweep & Top Ports`: Sweep CIDR for live hosts and scan top 100 ports (`-T4 -F`)
  - `🔍 Network Service & Version Mapping`: Scan CIDR hosts for service versions on top 20 ports (`-sV -T4 --top-ports 20`)
  - `⚡ Quick Scan (Single Host)`: Fast audit of top 100 ports (`-T4 -F`)
  - `🔍 Service & Version Detection`: Banner grabbing and version fingerprinting (`-sV -T4`)
  - `🛡️  Vulnerability & Threat Audit`: Run CVE and security audit scripts (`-sV --script=vuln`)
  - `🌐 Full Port Scan`: Comprehensive 65,535 TCP port audit (`-p- -T4`)
- **Custom CIDR / Target Input (`[i]`)**: Type any custom CIDR (e.g. `10.0.1.0/24`, `192.168.1.0/24`) or IP address directly into the terminal with live interactive entry.
- **Smart Target & Subnet Cycling (`[t]`)**: Auto-detects local LAN interfaces, cluster pod CIDR (`10.42.0.0/16`), cluster service CIDR (`10.43.0.0/16`), Docker bridges, and deployed endpoints (`siem.vigilante.local`, `vigil.vigilante.local`).
- **Discovered Network Hosts Map**: Selecting any historical CIDR scan displays an active host breakdown with IP addresses, hostnames, and open ports.
- **System Pager Integration (`[v]` / `[Enter]`)**: Open any saved scan directly in `$PAGER` (`less -R`) with full search and scroll navigation.
- **Actions**:
  - `[n]`: Run new scan against selected target
  - `[i]`: Input custom CIDR or IP
  - `[t]`: Cycle detected targets and subnets
  - `[p]`: Cycle scan profiles
  - `[e]`: Open raw scan file in `$EDITOR`
  - `[c]`: Copy full scan output to system clipboard
  - `[d]`: Delete saved scan report

### 2. Output Storage
Every scan automatically saves both human-readable text and XML reports in your XDG directory:
```
$XDG_CONFIG_HOME/vigilante/nmaps/
├── nmap-10.0.1.0_24-1786886669150.nmap
├── nmap-10.0.1.0_24-1786886669150.xml
├── nmap-127.0.0.1-1786886384289.nmap
├── nmap-127.0.0.1-1786886384289.xml
├── nmap-siem.vigilante.local-1786886400000.nmap
└── nmap-siem.vigilante.local-1786886400000.xml
```

---

## 📊 Nmap XML Network Topology & Port Matrix Visualizer

Vigilante includes an interactive **XML Network Visualizer** that parses `.xml` scan reports from `$XDG_CONFIG_HOME/vigilante/nmaps/` into structured network topology cards and port matrices.

### 1. Launching the XML Visualizer
- From the main menu: Press **`[x]`** anytime.
- From the Data Collection pane: Highlight any scan and press **`[x]`**.
- From the CLI: `vigilante xml` or `vigilante visualizer`.

### 2. Features & Navigation
- **Network Overview**: Target network, scanner version, command line arguments, execution time, and live host counts (`🟢 Up / 🔴 Down`).
- **Interactive Host Tree (`[↑/↓]` or `[j/k]`)**:
  - Live vs. down host indicator.
  - Resolved IP addresses, PTR/user hostnames, MAC address, and hardware vendor.
  - OS detection accuracy and fingerprint matches (`Linux 5.15 - 6.5 (98% match)`).
- **Port & Service Matrix**:
  - Structured table with Port ID, Protocol (`tcp`/`udp`), State (`OPEN`/`CLOSED`), Service Name (`http`, `https`, `ipp`), Product & Software Version (`nginx 1.24.0`, `OpenSearch 2.11`), and CPEs.
- **Security & NSE Script Findings**:
  - Automatically highlights CVE vulnerability reports, SSL certificate details, and HTTP banners from `--script=vuln` or custom NSE scripts.
- **Scan Cycling & Filtering**:
  - Press **`[s]`** or **`[Tab]`** to cycle through saved XML scans in `$XDG_CONFIG_HOME/vigilante/nmaps/`.
  - Press **`[f]`** to cycle filters: `All Hosts` | `🟢 Live Hosts` | `🔓 Open Ports` | `🛡️ Script / CVEs`.
  - Press **`[x]`** / **`[v]`** / **`[Enter]`** to view the raw XML in the system pager (`$PAGER`).
  - Press **`[e]`** to open the raw XML in `$EDITOR`.
  - Press **`[c]`** to export a clean JSON summary of the XML scan to your clipboard.

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
