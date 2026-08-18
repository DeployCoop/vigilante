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
- **Model Context Protocol (MCP) Server for LLMs**: Expose discovered host profiles, network topology maps, Incident Response Evidence Vaults, Kubernetes cluster telemetry, and live forensic diagnostic tools (`ping`, `mtr`, `curl`, `dns`, `tls`, `ab`, `arp`) directly to AI assistants (Claude, Antigravity, Cursor) via `@modelcontextprotocol/sdk`.

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
  menu/hub    Central operations hub and interactive workflow dispatcher
  up          Provision k3d cluster, certificates, and deploy security modules
  down        Tear down k3d cluster and clean up resources
  status      Check status of prerequisites, cluster, certificates, and DNS
  modules     List available and installed security modules
  pods        Live monitor of Kubernetes pods with -A -o wide details
  nmap/scan   Network reconnaissance & data collection saved to XDG nmaps dir
  xml/netmap  Interactive XML network topology & port matrix visualizer
  threat-sim  Trigger network threat simulation batch against SIEM
  instances   List and inspect all k3d cluster instances and their directories
  hosts/hostr Sync or manage local domain mappings in /etc/hosts
  values      Inspect or export customizable Helm chart values.yaml files
  config      Inspect, initialize, or display $XDG_CONFIG_HOME/vigilante/config.yaml
  mcp         Launch Model Context Protocol (MCP) server over stdio for LLMs

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

## 🎮 Globally Context-Sensitive Action Menu & Workflow

Vigilante features an adaptive, **context-sensitive bottom action bar** that updates dynamically depending on which pane and state you are actively in, preventing keyboard shortcut collisions (for instance, `[p]` triggers Ping when inspecting a host in the Visualizer, while taking you to the Live Pods monitor when in the Status Dashboard).

### 1. Canonical Operational Workflow
```
[1. UP] ➔ [2. Modules] ➔ [3. Status] ➔ [4. Pods] ➔ [5. Nmap] ➔ [6. Visualizer]
```
The menu automatically highlights your active stage (e.g. `[● 4. Pods]`) and indicates the next recommended step (e.g. `Next ➔ [n] Nmap (Scan)`).

### 2. Contextual Shortcuts per Screen

| Screen / Context | Keybindings | Description |
|---|---|---|
| **6. XML Visualizer** | `[p]` Ping, `[b]` Bench (`ab`), `[m]` MTR, `[h]` HTTP, `[d]` DNS, `[s]` Switch Scan, `[f]` Filter, `[x/v]` Raw XML, `[e]` Editor, `[c]` Copy, `[n]` Nmap, `[q]` Return | Host network diagnostics & XML topology exploration |
| **5. Nmap Scanner** | `[n]` Run Scan, `[i]` Custom CIDR/IP, `[t]` Target, `[p]` Profile, `[x]` ➔ XML Visualizer, `[v]` Pager, `[e]` Editor, `[c]` Copy, `[d]` Delete, `[q]` Dashboard | Network sweeps & target profiling |
| **4. Live Pods** | `[↑/↓]` Select Pod, `[d]` Describe, `[l]` Logs, `[s]` Shell, `[f]` Filter NS, `[r]` Refresh, `[n]` ➔ Nmap, `[x]` Visualizer, `[c]` Copy, `[q]` Dashboard | Kubernetes pod operations (`-A -o wide`) |
| **3. Status Dashboard** | `[p]` ➔ Pods (Live), `[n]` Nmap, `[x]` Visualizer, `[t]` Threat-Sim, `[m]` Modules, `[v]` Values, `[h]` Hostr, `[u]` Up, `[d]` Down, `[1-6]` Copy, `[q]` Quit | Global health, ingress endpoints & quick navigation |
| **2. Modules** | `[↑/↓]` Navigate, `[Space]` Toggle, `[Enter]` Apply, `[u]` ➔ Deploy (Up), `[s]` Status, `[v]` Values, `[q]` Back | Security package enablement & dependencies |
| **1. Up (Running)** | `[Esc/Ctrl+C]` Abort Task, `[Enter]` ➔ Next: Status Dashboard | Cluster creation, TLS provisioning & chart deployments |
| **Values** | `[↑/↓]` Select Chart, `[e/Enter]` Edit in `$EDITOR`, `[v]` View Pager, `[x]` Export Starters, `[u]` ➔ Deploy (Up), `[q]` Back | Helm value customization & overrides |
| **Threat-Sim** | `[↑/↓]` Select Scenario, `[Enter]` Run Scenario, `[a]` Run All, `[s]` Open SIEM UI, `[q]` Back | Adversary simulation & detection verification |

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
- **Individual Host Forensic Probes & Incident Response (IR)**:
  - **`[t]` Full IR Triage Bundle**: Executes parallel multi-vector forensic triage probes (`ping`, `mtr`, `dns`, `tls_certs`, `http_headers`, `arp_neighbors`, `benchmark`) and archives the complete evidence bundle into the evidence vault.
  - **`[p]` Ping (ICMP)**: Measure RTT latency, packet loss, and jitter (`ping -c 4`).
  - **`[b]` Bench (ab / ApacheBench)**: Benchmark HTTP response throughput and concurrency against discovered web ports.
  - **`[m]` MTR / Network Route Trace**: Trace latency and packet loss per hop across the network route.
  - **`[h]` HTTP Headers & TLS (curl -I)**: Inspect server headers, cookies, TLS versions, and redirect chains.
  - **`[c]` TLS Certificate Chain (OpenSSL)**: Extract full public certificates, issuer CAs, validity dates, SANs, and cipher suites with `openssl s_client -showcerts`.
  - **`[d]` DNS Lookup (dig)**: Perform forward (A/AAAA/CNAME/MX) and reverse PTR lookups.
  - **`[a]` Kernel ARP & Neighbor Cache**: Inspect kernel ARP cache (`ip neigh show`) to identify MAC addresses and detect potential ARP spoofing / MITM gateways.
- **Scan Cycling & Filtering**:
  - Press **`[s]`** or **`[Tab]`** to cycle through saved XML scans in `$XDG_CONFIG_HOME/vigilante/nmaps/`.
  - Press **`[f]`** to cycle filters: `All Hosts` | `🟢 Live Hosts` | `🔓 Open Ports` | `🛡️ Script / CVEs`.
  - Press **`[x]`** / **`[v]`** / **`[Enter]`** to view the raw XML in the system pager (`$PAGER`).
  - Press **`[e]`** to open the raw XML in `$EDITOR`.
  - Press **`[y]`** to export a clean JSON summary of the XML scan to your clipboard.

---

## 📁 Incident Response Evidence Vault (`net/host/data.ext`)

Vigilante automatically archives all forensic evidence, telemetry, and live triage data in a hierarchical network/host directory structure under `$XDG_CONFIG_HOME/vigilante/evidence/`:

```
$XDG_CONFIG_HOME/vigilante/evidence/
├── 10.0.1.0_24/                          # Network CIDR Block
│   ├── 10.0.1.1/                         # Gateway / Router
│   │   ├── ping.json
│   │   ├── mtr.txt
│   │   ├── http_headers.txt
│   │   └── arp_neighbors.json
│   └── 10.0.1.5/                         # Target / SIEM Host
│       ├── triage_summary.json           # Triage index with timestamps & artifact hashes
│       ├── ping.json                     # ICMP RTT statistics
│       ├── mtr.txt                       # MTR route hop latency & packet loss
│       ├── dns_records.json              # Forward DNS & reverse PTR records
│       ├── tls_certificates.pem         # Full X.509 certificate chain
│       ├── http_headers.txt              # Security headers & server tokens
│       ├── arp_neighbors.json            # Kernel ARP neighbor entries & MACs
│       └── benchmark.txt                 # HTTP latency & concurrency metrics
└── 127.0.0.0_8/
    └── 127.0.0.1/
        ├── triage_summary.json
        ├── ping.json
        └── tls_certificates.pem
```

---

## 🔏 GPG Cryptographic Signatures & Non-Repudiation

When responding to an active incident or preparing chain-of-custody forensic reports, Vigilante can automatically sign every file, diagnostic output, and scan with a designated GPG identity upon creation.

### Enabling GPG in `$XDG_CONFIG_HOME/vigilante/config.yaml`
```yaml
# GPG Digital Signature & Evidence Integrity
gpg:
  enabled: true                                      # Enable cryptographic signing
  keyId: "security-lead@vigilante.local"             # Key identity, email, or fingerprint
  autoSign: true                                     # Automatically sign files as they are written
  detached: true                                     # Create detached ASCII-armored signatures (.asc)
  gnupgHome: ""                                      # Optional custom GNUPGHOME directory
```

When enabled, every evidence file (`.json`, `.txt`, `.pem`, `.xml`, `.nmap`) automatically receives a cryptographic detached signature (`.asc`) created at the exact moment of acquisition:
- `evidence/10.0.1.0_24/10.0.1.5/mtr.txt` + `mtr.txt.asc`
- `evidence/10.0.1.0_24/10.0.1.5/ping.json` + `ping.json.asc`
- `evidence/10.0.1.0_24/10.0.1.5/tls_certificates.pem` + `tls_certificates.pem.asc`
- `evidence/10.0.1.0_24/10.0.1.5/triage_summary.json` + `triage_summary.json.asc`

The Visualizer automatically inspects and displays signature badges (`[🔏 GPG Signed]`) for verified artifacts.

---

## 📦 Multi-Instance k3d Orchestration & Instance Isolation

All files associated with a Vigilante k3d cluster instance live in an isolated directory structure inside `$XDG_CONFIG_HOME/.vigilante/instances/<instance_name>/`:

```
$XDG_CONFIG_HOME/.vigilante/instances/
├── vigilante-dev/                        # Default dev instance
│   ├── certs/                            # Local TLS wildcard certs (*.vigilante.local)
│   │   ├── vigilante.local.pem
│   │   └── vigilante.local-key.pem
│   ├── values/                           # Instance-specific Helm chart overrides
│   ├── logs/                             # Instance deployment & lifecycle logs
│   └── instance.json                     # Cluster metadata & deployed module state
└── soc-prod/                             # Custom named cluster instance
    ├── certs/                            # Isolated certs for *.soc-prod.local
    │   ├── soc-prod.local.pem
    │   └── soc-prod.local-key.pem
    ├── values/
    ├── logs/
    └── instance.json
```

### Running and Managing Multiple Instances

```bash
# Launch a named instance
$ vigilante up --cluster-name soc-prod --domain prod.local

# Launch an instance using the -i alias
$ vigilante up -i test-soc -d test.local

# List all known instances, directories, and live k3d cluster states
$ vigilante instances

# Inspect status of a specific instance
$ vigilante status -c soc-prod

# Live pod monitor for a specific instance
$ vigilante pods -c soc-prod

# Tear down a specific instance and clean up its resources
$ vigilante down -c soc-prod
```

---

## 🏢 Namespaced Module Deployments & Multi-Tenant Replication

Vigilante supports deploying sets of security packages into specific Kubernetes namespaces, and repeating deployments for multiple distinct namespaces on the same or different k3d cluster instances:

```bash
# Deploy OpenSearch & Vigil SOC into namespace 'tenant-alpha'
$ vigilante up -n tenant-alpha -m opensearch,vigil-soc

# Deploy another independent Vigil SOC stack into namespace 'tenant-beta'
$ vigilante up -n tenant-beta -m vigil-soc

# Deploy a threat simulation environment into namespace 'threat-lab'
$ vigilante up -n threat-lab -m opensearch

# Inspect status of packages in a specific namespace
$ vigilante status -n tenant-alpha

# Live pod monitor filtered to a specific namespace
$ vigilante pods -n tenant-alpha
```

### Namespace-Aware Values Overrides

When customizing Helm values, Vigilante prioritizes namespace-specific override files:
- `$XDG_CONFIG_HOME/.vigilante/instances/<cluster>/values/<namespace>/<module>/<chart>.yaml`
- `./values/<namespace>/<module>/<chart>.yaml`
- `$XDG_CONFIG_HOME/vigilante/values/<namespace>/<module>/<chart>.yaml`
- Defaulting smoothly to standard module values if no namespace override exists.

---

## 🤖 Model Context Protocol (MCP) Server for LLMs

Vigilante includes a built-in **Model Context Protocol (MCP)** server built on `@modelcontextprotocol/sdk` (2024-11-05 standard specification) running over standard `stdio` transport. It enables AI assistants (such as **Claude Desktop**, **Antigravity**, **Cursor**, **Gemini**, and **ChatGPT**) to discover, query, and perform live incident response diagnostics across your local network and Kubernetes infrastructure.

```
┌─────────────────────────┐          JSON-RPC (stdio)          ┌────────────────────────────────────────┐
│  AI Assistant / LLM     │ ◄────────────────────────────────► │  🛡️  Vigilante MCP Server               │
│  (Claude, Cursor, AGY)  │                                    │  (src/mcp/server.js)                   │
└─────────────────────────┘                                    └───────────────────┬────────────────────┘
                                                                                   │
                 ┌─────────────────────────────────┬───────────────────────────────┴───────────────────────────────┐
                 ▼                                 ▼                                                               ▼
       🌐 Network & Topology             📁 Evidence Vault & GPG                                         ☸️ Kubernetes & Modules
  • vigilante://hosts               • vigilante://evidence                                          • vigilante://pods
  • vigilante://topology            • vigilante://evidence/{net}/{host}                             • vigilante://clusters
  • list_hosts / get_host_details   • list_evidence / verify_evidence_signature                     • vigilante://modules
  • run_nmap_scan                   • run_diagnostic / run_triage_capture                          • get_pods / get_pod_logs
```

### 1. Launching the MCP Server
```bash
# Via CLI command
vigilante mcp

# Or via pnpm script
pnpm mcp
```

### 2. LLM Client Configuration Examples

#### A. Claude Desktop (`claude_desktop_config.json`)
- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "vigilante": {
      "command": "node",
      "args": ["/home/djehauti/git/DeployCoop/vigilante/bin/vigilante.js", "mcp"]
    }
  }
}
```

#### B. Antigravity / Cursor / VS Code (`settings.json`)
```json
{
  "mcpServers": {
    "vigilante": {
      "command": "vigilante",
      "args": ["mcp"]
    }
  }
}
```

---

### 3. Exposed MCP Resources

AI models can directly inspect real-time state and historical scan reports using standardized `vigilante://` resource URIs:

| Resource URI | Description | MIME Type |
| :--- | :--- | :--- |
| `vigilante://hosts` | Aggregated list of all discovered hosts with IP addresses, hostnames, open ports, OS fingerprint guesses, and MAC hardware vendors. | `application/json` |
| `vigilante://topology` | Hierarchical network topology map grouped by CIDR subnets with live host counts and service matrices. | `application/json` |
| `vigilante://evidence` | Incident Response Evidence Vault hierarchy (`net/host/data.ext`) with triage artifacts, sizes, timestamps, and signature status. | `application/json` |
| `vigilante://pods` | Real-time list of all Kubernetes pods across all namespaces matching `kubectl get pods -A -o wide`. | `application/json` |
| `vigilante://clusters` | All configured k3d cluster instances, directory paths, and deployed namespaces. | `application/json` |
| `vigilante://modules` | Security packages (OpenSearch SIEM, Vigil AI SOC) with their live ingress URLs and cluster DNS endpoints. | `application/json` |
| `vigilante://scans` | List of all saved raw XML and text Nmap scan reports in `$XDG_CONFIG_HOME/vigilante/nmaps/`. | `application/json` |
| `vigilante://config` | Active configuration settings, default domain, cluster name, hostr sync, and GPG signing identity. | `application/json` |

#### Parameterized Resource Templates

| Template URI | Description |
| :--- | :--- |
| `vigilante://hosts/{hostIp}` | Deep-dive profile for a specific host, including all open ports, version banners, OS matches, and NSE script outputs. |
| `vigilante://evidence/{network}/{hostIp}` | All forensic evidence artifacts captured for a specific host within a subnet. |
| `vigilante://evidence/{network}/{hostIp}/{filename}` | Raw text/PEM/JSON content of a specific forensic artifact file in the evidence vault. |
| `vigilante://scans/{filename}` | Raw text or XML content of a saved Nmap scan report. |

---

### 4. 12 Interactive Tools for LLMs

The MCP server provides 12 callable tools that allow LLMs to actively query infrastructure, trigger reconnaissance scans, and run non-destructive forensic diagnostics:

| Tool Name | Parameters | Purpose |
| :--- | :--- | :--- |
| `list_hosts` | `subnet`, `port`, `service`, `state` (`up`/`down`/`all`) | Query discovered network hosts across Nmap XML scans with flexible attribute filtering. |
| `get_host_details` | `host` *(required)* | Retrieve complete in-depth profile for a target host IP, including open ports, banners, OS match guesses, NSE vulnerability script outputs, and existing evidence artifacts. |
| `query_topology` | *(none)* | Get structured network topology tree grouped by subnet CIDRs, live host IP addresses, and open service ports. |
| `list_evidence` | `network`, `host` | Browse the Incident Response Evidence Vault (`net/host/data.ext`), listing all forensic artifacts, triage bundles, and cryptographic GPG signatures. |
| `run_diagnostic` | `tool` (`ping`/`mtr`/`curl`/`dns`/`tls`/`ab`/`arp`), `host`, `port`, `path`, `count`, `network` | Execute live forensic network diagnostic probes against a target host, with optional automatic archiving into the Evidence Vault. |
| `run_triage_capture` | `network`, `host`, `ports` | Execute a full parallel incident response forensic triage bundle against a host (`ping`, `mtr`, `dns`, `tls`, `http`, `arp`), save all structured artifacts in `net/host/data.ext`, and sign with GPG if configured. |
| `run_nmap_scan` | `target`, `profile` (`sweep`/`quick`/`service`/`vuln`/`full`/`custom`), `customArgs` | Launch an Nmap reconnaissance scan against a target IP or CIDR range, save results as XML and Nmap text, and return parsed host data. |
| `verify_evidence_signature` | `filePath`, `signaturePath` | Verify the cryptographic GPG detached signature (`.asc`) for an artifact in the Evidence Vault to confirm evidence authenticity and non-repudiation. |
| `get_pods` | `namespace`, `clusterName` | Query live Kubernetes pods across all namespaces (`-A -o wide`) with pod IP, node, status, restart count, and age. |
| `get_pod_logs` | `podName`, `namespace`, `container`, `tailLines`, `clusterName` | Retrieve live log tails from a specific Kubernetes pod container. |
| `describe_pod` | `podName`, `namespace`, `clusterName` | Fetch detailed Kubernetes pod description, containers, volumes, conditions, and lifecycle events. |
| `get_cluster_status` | `clusterName`, `domain`, `namespace` | Check health and status of prerequisites, k3d clusters, TLS certificates, local DNS host mappings, and deployed security modules. |

---

### 5. Example LLM Prompt Scenarios

Once connected, your AI assistant can execute multi-step analysis and incident response workflows autonomously:

- *"What hosts are currently running HTTP services on subnet 10.0.1.0/24?"* ➔ The LLM invokes `list_hosts({ subnet: "10.0.1.0/24", service: "http" })`.
- *"Perform a forensic triage on rogue host 10.0.1.15 and verify the cryptographic signature of the evidence."* ➔ The LLM calls `run_triage_capture({ network: "10.0.1.0/24", host: "10.0.1.15" })` followed by `verify_evidence_signature({ filePath: "..." })`.
- *"Why is the OpenSearch pod crashing in namespace tenant-alpha?"* ➔ The LLM calls `get_pods({ namespace: "tenant-alpha" })` followed by `get_pod_logs({ podName: "opensearch-0", namespace: "tenant-alpha", tailLines: 50 })`.

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
│   └── vigilante.js              # Executable entry point (Meow CLI & MCP dispatcher)
├── src/
│   ├── index.js                  # Programmatic library exports
│   ├── mcp/
│   │   └── server.js             # Model Context Protocol (MCP) Server for LLMs
│   ├── engine/
│   │   ├── prereqs.js            # Tooling verification (docker, k3d, mkcert, kubectl, helm)
│   │   ├── certs.js              # mkcert CA & TLS certificates manager
│   │   ├── cluster.js            # k3d cluster lifecycle provisioner
│   │   ├── k8s.js                # Kubernetes safety apply & API readiness engine
│   │   ├── hosts.js              # /etc/hosts domain resolution sync & cleanup (hostr)
│   │   ├── pods.js               # Live Kubernetes pods querying & watch poller (-A -o wide)
│   │   ├── helm.js               # Dynamic Helm values resolver, renderer & exporter
│   │   ├── config.js             # XDG Base Directory configuration & theme resolver
│   │   ├── instances.js          # Multi-instance k3d orchestration & metadata isolation
│   │   ├── nmap.js               # Network reconnaissance & subnet scanner
│   │   ├── nmap-xml.js           # Nmap XML parser & topology graph builder
│   │   ├── evidence.js           # Incident Response Evidence Vault (net/host/data.ext)
│   │   ├── gpg.js                # GPG cryptographic non-repudiation signing & verification
│   │   └── diagnostics.js        # Host diagnostic probes (ping, ab, mtr, curl, dig, tls, arp)
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
│   │   ├── MenuBar.js            # Globally context-sensitive keyboard action menu
│   │   ├── NavHub.js             # Central operations hub & workflow dispatcher ([Tab])
│   │   ├── TaskRunner.js         # Animated task spinner & log viewer
│   │   ├── SelectModules.js      # Interactive package selector & namespace switcher ([n])
│   │   ├── StatusDashboard.js    # Comprehensive diagnostics dashboard
│   │   ├── ThreatSimView.js      # Network threat simulation runner
│   │   ├── ValuesView.js         # Interactive Values & $EDITOR manager
│   │   ├── ModulesView.js        # Interactive Security Modules & Package Manager
│   │   ├── PodsView.js           # Live Kubernetes Pods Monitor (-A -o wide table)
│   │   ├── DataCollectionView.js # Interactive Nmap reconnaissance & subnet sweeper
│   │   ├── NmapVisualizerView.js # Interactive XML network topology & port matrix visualizer
│   │   ├── InstancesView.js      # Multi-instance k3d manager
│   │   ├── ClipboardManager.js   # Click-to-copy provider & SGR mouse tracker
│   │   └── theme.js              # Theme context & color palette definitions
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
│   ├── test-clipboard.js         # Unit test suite for clipboard & ANSI stripping
│   ├── test-config.js            # Unit test suite for XDG config & themes
│   ├── test-nmap.js              # Unit test suite for Nmap scanner & subnet calculation
│   ├── test-nmap-xml.js          # Unit test suite for XML parser & topology graph
│   ├── test-diagnostics.js       # Unit test suite for host diagnostic probes
│   ├── test-menubar.js           # Unit test suite for context-sensitive menu bar
│   ├── test-evidence.js          # Unit test suite for Evidence Vault hierarchy
│   ├── test-gpg.js               # Unit test suite for GPG digital signing & verification
│   ├── test-instances.js         # Unit test suite for multi-instance k3d isolation
│   ├── test-namespaces.js        # Unit test suite for namespaced module deployments
│   ├── test-k8s.js               # Unit test suite for safe kubectl apply pipeline
│   ├── test-hub.js               # Unit test suite for operations hub & dispatcher
│   └── test-mcp.js               # Unit test suite for Model Context Protocol (MCP) server
├── values/                       # Exported starter & custom user Helm values overrides
├── package.json
└── README.md
```

---

## 📄 License

MIT License. See [LICENSE](LICENSE) for details.
