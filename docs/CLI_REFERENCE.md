# 💻 Vigilante CLI Reference Manual

This manual provides an exhaustive reference for the `vigilante` command-line interface, including all 26 subcommands, global flags, exit codes, and automation examples.

---

## 1. Global Syntax & Options

```bash
vigilante [command] [subcommand/target] [options]
```

### Global Options

| Flag | Short | Type | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `--domain` | `-d` | string | `vigilante.local` | Base local domain for TLS certificates and `/etc/hosts` mappings. |
| `--cluster-name` | `-c` | string | `vigilante-dev` | Target k3d cluster instance name. |
| `--module` | `-m` | string | `vigil-soc` | Comma-separated list of modules to install (e.g. `wazuh,falco,zeek`). |
| `--values` | `-f` | string | `""` | Path to custom Helm values YAML override file. |
| `--values-dir` | | string | `./values` | Directory containing custom module values overrides. |
| `--ip` | | string | `127.0.0.1` | Target IP address for `/etc/hosts` domain mappings. |
| `--non-interactive` | | boolean | `false` | Run in non-interactive batch mode without prompting for input. |
| `--skip-prereqs` | | boolean | `false` | Bypass prerequisite validation checks (Docker, k3d, mkcert, kubectl, helm). |
| `--help` | `-h` | boolean | `false` | Display command help and usage instructions. |
| `--version` | `-v` | boolean | `false` | Display installed Vigilante version. |

---

## 2. Command Index

### Infrastructure & Cluster Operations

#### `vigilante up`
Provisions the local environment: checks prerequisites, issues local CA and TLS certificates via `mkcert`, spins up the k3d cluster with Ingress port bindings (`80:80`, `443:443`), synchronizes `/etc/hosts`, and deploys chosen security modules.
```bash
# Interactive mode (select modules with spacebar)
vigilante up

# Deploy specific modules with custom domain
vigilante up -m wazuh,falco -d lab.local

# Non-interactive CI execution with values override
vigilante up -m vigil-soc -f ./custom-vigil.yaml --non-interactive
```

#### `vigilante down`
Tears down the k3d cluster and releases allocated Docker resources.
```bash
# Delete default cluster (vigilante-dev)
vigilante down

# Delete specific named cluster
vigilante down -c staging-cluster
```

#### `vigilante status`
Runs diagnostic checks across prerequisites, Docker daemon, k3d cluster nodes, active TLS certificates, and `/etc/hosts` domain synchronization.
```bash
vigilante status
```

#### `vigilante instances`
Enumerates all active and stopped k3d cluster instances, their resource allocations, port mappings, and associated directory paths.
```bash
vigilante instances
```

#### `vigilante hosts` / `vigilante hostr`
Inspects, tests, or updates local domain mappings in `/etc/hosts`.
```bash
# Verify current DNS resolution
vigilante hostr --check

# Synchronize mappings (prompts for sudo if changes needed)
vigilante hostr

# Clean up all Vigilante managed entries
vigilante hostr --remove
```

#### `vigilante pods`
Launches the full-screen live Kubernetes pods monitor (`kubectl get pods -A -o wide`), with pod health status, restart tracking, IP addresses, node assignments, and real-time streaming logs.
```bash
vigilante pods
```

---

### Configuration & Package Management

#### `vigilante modules`
Interactive terminal package manager listing all 12 supported security modules, their installation status, ingress endpoints, and dependencies.
```bash
vigilante modules
```

#### `vigilante values`
Inspects, renders, and manages Helm values overrides.
```bash
# Export editable default values.yaml files for all modules into ./values/
vigilante values export

# Export values to a custom directory
vigilante values export --values-dir ./my-configs/
```

#### `vigilante config`
Displays, initializes, or validates the Vigilante global configuration file at `$XDG_CONFIG_HOME/vigilante/config.yaml`.
```bash
vigilante config
```

---

### Reconnaissance, Scanners & Offensive Operations

#### `vigilante nmap` / `vigilante scan`
Performs network discovery and vulnerability scanning across target IP ranges or domains, automatically cataloging raw XML and text reports in `$XDG_CONFIG_HOME/vigilante/nmaps/`.
```bash
# Scan default local cluster subnet
vigilante scan

# Target specific subnet with aggressive scan profile
vigilante scan 192.168.1.0/24
```

#### `vigilante xml` / `vigilante netmap`
Interactive network topology visualizer. Parses Nmap XML scans into node-edge network graphs, port matrices, and host fingerprint tables.
```bash
vigilante xml
```

#### `vigilante nasty`
Launches **NastyMap 2.0**: maps lateral attack paths across Kubernetes pods and network endpoints, calculates risk scores, and generates headless SVG or interactive HTML reports.
```bash
# Interactive TUI Attack Graph
vigilante nasty

# Generate standalone SVG report
vigilante nasty --export svg

# Generate standalone HTML report
vigilante nasty --export html
```

#### `vigilante oob`
Out-of-band hardware management scanner. Probes for BMC, IPMI 1.5/2.0, and Redfish management controllers, tests for default credentials, and dumps RAKP-2 authentication hashes for offline cracking.
```bash
vigilante oob 10.0.0.0/24
```

#### `vigilante threat-sim`
Executes automated adversarial simulation playbooks against the active SIEM/SOC stack to test alert pipelines (Port Scanning, SSH Brute Force, DNS Tunneling, Web Shells).
```bash
vigilante threat-sim
```

#### `vigilante kctf`
Google kCTF cyber range manager. Deploys sandboxed CTF challenge archetypes (Web, Pwn/nsjail, Crypto, Rev, Forensics) for red/blue training.
```bash
vigilante kctf
```

#### `vigilante openvas`
Controls Greenbone Vulnerability Management (OpenVAS) scanning workflows, profile selection, and report downloads.
```bash
vigilante openvas
```

---

### Cyber Defense, Posture & Incident Response

#### `vigilante battle`
Launches the **Cyber Defense Operations BattleStation** (`src/ui/BattleStationView.js`), aggregating real-time alerts from Falco, Suricata, and Zeek alongside SOAR quick-containment controls.
```bash
vigilante battle
```

#### `vigilante audit`
Shift-Left CI/CD pipeline auditor. Scans Kubernetes manifests and Dockerfiles against Pod Security Standards (PSS) and CIS benchmarks, outputs SARIF v2.1.0 reports, and gates pull requests.
```bash
# Audit a manifest file
vigilante audit deployment.yaml

# Audit entire repository and emit SARIF
vigilante audit ./deploy/ --sarif report.sarif
```

#### `vigilante fix`
Self-Healing Auto-Remediator. Evaluates security audit findings and automatically patches Kubernetes YAMLs or Dockerfiles to resolve vulnerabilities, creating timestamped backups and Git PR scripts.
```bash
# Preview auto-remediation unified diff
vigilante fix deployment.yaml

# Apply patches directly to disk
vigilante fix deployment.yaml --apply
```

#### `vigilante canary`
Autonomous Deception Mesh management. Deploys and monitors decoy ServiceAccounts, canary Secrets, and network honeypots.
```bash
# List active canary tokens and tripped status
vigilante canary list

# Deploy a decoy ServiceAccount
vigilante canary deploy sa

# Deploy a decoy database credentials Secret
vigilante canary deploy secret
```

#### `vigilante purple`
Runs autonomous multi-agent adversarial simulations (Red Team adversary vs. Blue Team SOC) across 4 MITRE ATT&CK phases, outputting MTTD/MTTR scorecards.
```bash
vigilante purple
```

#### `vigilante query`
High-Throughput Security Data Lake SQL query runner. Queries normalized security telemetry across Falco, Zeek, Suricata, Audit, and Canary events using embedded SQLite or DuckDB.
```bash
# Query aggregate event count
vigilante query "SELECT event_type, count(*) as count FROM security_events GROUP BY event_type"

# Find critical anomalies in the last 24 hours
vigilante query "SELECT timestamp, source_pod, severity, mitre_technique FROM security_events WHERE severity = 'CRITICAL'"
```

#### `vigilante forensics`
Deep PCAP forensic analysis tool. Scans the evidence dropzone, carves files from HTTP/SMB streams, computes SHA256 hashes, and reconstructs TCP conversations.
```bash
# List carved forensic artifacts
vigilante forensics

# Carve artifacts from a specific PCAP dump
vigilante forensics /path/to/capture.pcap
```

#### `vigilante cloudsec`
Multi-Cloud Workload Identity and CSPM auditor. Audits AWS IRSA, GCP Workload Identity, and Azure Client ID annotations on cluster workloads, flagging over-privileged permissions and exposed storage buckets.
```bash
vigilante cloudsec
```

#### `vigilante hunt`
Automated SIGMA-to-SQL threat hunting engine. Transpiles SIGMA rules or MITRE hypotheses into ANSI SQL queries against historical telemetry in the Security Data Lake.
```bash
# Hunt for suspicious shell executions in containers (T1059.004)
vigilante hunt --technique T1059.004

# Hunt for lateral SMB connections (T1021.002)
vigilante hunt --technique T1021.002
```

#### `vigilante memdump`
In-memory process triage and `/proc/$PID/maps` inspection. Scans for RWX shellcode buffers, unlinked deleted binaries, fileless `memfd_create` executions, and `/tmp` shared library injections.
```bash
# Triage PID 1 (init / container entrypoint)
vigilante memdump 1

# Triage target workload process
vigilante memdump 1042
```

#### `vigilante sbom`
Supply chain security and container Software Bill of Materials (SBOM) generator. Generates CycloneDX v1.5 or SPDX v2.3 SBOM documents and audits dependencies against vulnerability rules.
```bash
# Generate CycloneDX v1.5 JSON SBOM
vigilante sbom --format cyclonedx

# Generate SPDX v2.3 JSON SBOM
vigilante sbom --format spdx
```

#### `vigilante matrix`
Real-time network socket connection matrix and lateral movement detector. Aggregates pod-to-pod and pod-to-external socket connections and flags unauthorized egress or reverse shell ports.
```bash
vigilante matrix
```

#### `vigilante mesh`
Multi-cluster defense federation peer management and signed threat sharing. Generates Ed25519 node identities, cryptographically signs threat indicators, and broadcasts IoCs across peer clusters for automated SOAR containment.
```bash
# View local node status and connected peer clusters
vigilante mesh status

# Broadcast malicious IP to all peer clusters
vigilante mesh broadcast --indicator 198.51.100.99
```

#### `vigilante beacon`
Statistical C2 beaconing and Discrete Fourier Transform (DFT) frequency detector. Analyzes socket connection intervals for periodic command-and-control heartbeats and detects DNS tunneling data exfiltration via Shannon entropy.
```bash
vigilante beacon
```

#### `vigilante lsm`
Synthesizes Linux Security Module (BPF-LSM) in-kernel security policies from declarative YAML rules, generating compile-ready eBPF C source code hooks (`bprm_check_security`, `file_open`, `socket_connect`).
```bash
vigilante lsm
```

#### `vigilante warroom`
Convenes an autonomous multi-agent incident war room. Orchestrates Forensics, Threat Intel, SRE Blast Radius, and Incident Commander AI specialist personas to debate consensus on active containment actions.
```bash
vigilante warroom
vigilante warroom --incident IR-PROD-9901
```

#### `vigilante vector`
Air-gapped offline semantic threat query using zero-dependency 128-dimensional dense float vector embeddings against MITRE ATT&CK techniques and Sigma rules.
```bash
vigilante vector --query "reverse shell in container"
```

#### `vigilante ledger`
Inspects and cryptographically verifies the immutable, append-only Merkle audit ledger and legal chain-of-custody affidavit.
```bash
# View ledger status and Merkle root
vigilante ledger

# Cryptographically verify ledger integrity and detect tampering
vigilante ledger verify
```

#### `vigilante graph`
Interactive terminal composite attack graph and blast-radius explorer. Federates network topology, Kubernetes workloads, and Identity access paths to discover privilege escalation vectors.
```bash
# Render ASCII composite attack graph
vigilante graph

# Calculate blast radius impact from an origin asset
vigilante graph blast ext-attacker
```

---

### AI Assistance & Protocol Integration

#### `vigilante ai`
Launches the interactive AI Security Analyst powered by local Ollama (`llama3.2`, `mistral`, `deepseek-r1`) or cloud models (Claude, ChatGPT, Gemini). Includes quick forensic prompts for triage, CVE research, and post-mortems.
```bash
vigilante ai
```

#### `vigilante mcp`
Launches the **Model Context Protocol (MCP)** server over `stdio`, exposing 78 callable tools and 16 resources to LLM agents (Claude, Antigravity, Cursor).
```bash
vigilante mcp
```

---

## 3. Environment Variables

| Variable | Description |
| :--- | :--- |
| `XDG_CONFIG_HOME` | Base path for configuration, evidence, and data lake (Default: `~/.config`). |
| `VIGILANTE_DATALAKE_BACKEND` | Preferred Data Lake SQL backend (`sqlite` or `duckdb`, Default: `auto`). |
| `SSLKEYLOGFILE` | Path to TLS session secret keys for PCAP stream decryption. |
| `OLLAMA_HOST` | Custom Ollama API server address (Default: `http://localhost:11434`). |
| `DEBUG` | Enables verbose debug logging to `/tmp/.vigilante.log`. |
