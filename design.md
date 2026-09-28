# 🏗️ Vigilante: System Design & Architectural Blueprint

This document details the production design, subsystem boundaries, data models, and architectural patterns of **Vigilante**, a modular, terminal-native Cyber Defense, Incident Response, and Modular SOC Operations Platform built with React, Ink, and Node.js.

---

## 1. Design Principles & Goals

1. **Terminal-Native Ergonomics**: Complete cyber defense, triage, threat hunting, and incident remediation accessible entirely within a high-performance terminal UI without requiring a web browser.
2. **Modular Micro-Package Architecture**: Every security service is an isolated module extending `BaseModule`, with decoupled Helm charts and custom values overrides.
3. **Sub-Second Active Containment (SOAR)**: When a critical threat or honeypot trip is detected, programmatic zero-trust isolation policies are enforced within milliseconds.
4. **Legal Chain-of-Custody**: All forensic captures, triage dumps, and post-mortems are persisted in an immutable evidence vault backed by GPG detached digital signatures.
5. **Zero-Friction Zero-Dependency Baseline**: High-throughput embedded SQL data lakes and Wasm detectors run out-of-the-box using the Node.js standard library, while gracefully scaling to official enterprise tooling (such as DuckDB) when available.
6. **AI & LLM Interoperability**: Every asset, scan, topology map, and containment action is exposed to AI agents via the Model Context Protocol (MCP).

---

## 2. Global System Architecture

```mermaid
graph TB
    subgraph UI["Presentation Layer (React 18 + Ink 4)"]
        CLI["CLI Command Router (bin/vigilante.js)"]
        APP["Terminal Controller (App.js)"]
        HUB["NavHub ([Tab])"]
        VIEWS["19 Terminal Subviews (BattleStation, Pods, Forensics, Lineage, etc.)"]
        PALETTE["Command Palette ([:] Hotkey)"]
    end

    subgraph MCP_SERVER["Model Context Protocol (MCP) Server"]
        MCP_CORE["MCP Server Core (stdio)"]
        TOOLS["66 Callable Tools"]
        RESOURCES["16 Static Resources & 5 Templates"]
    end

    subgraph ENGINE["Security & Orchestration Engines (32 Engines)"]
        direction TB
        SOAR_ENG["SOAR Containment (soar.js)"]
        AGENT_SOC["Autonomous Agentic SOC (agent-soc.js)"]
        DECEPTION["Deception Mesh & Honeytokens (deception.js)"]
        SIGMA["SIGMA-to-SQL Transpiler (sigma.js)"]
        ADVERSARY["Dynamic Red Team Agent (adversary.js)"]
        MEMDUMP["In-Memory Forensics (memdump.js)"]
        SUPPLYCHAIN["Supply Chain & SBOM (supplychain.js)"]
        OBSERVABILITY["eBPF Ring Buffer & Matrix (observability.js)"]
        FEDERATION["Defense Federation Mesh (federation.js)"]
        CANVAS["Braille Canvas & Heatmaps (canvas.js)"]
        PURPLE["Purple Team Arena (purpleteam.js)"]
        REMEDIATION["Auto-Remediator (remediation.js)"]
        FORENSICS["PCAP Forensics (forensics.js)"]
        LINEAGE["Process Lineage Tree (lineage.js)"]
        CLOUDSEC["Multi-Cloud CSPM (cloudsec.js)"]
        DATALAKE["Security Data Lake (datalake.js)"]
        WASM_ENG["WebAssembly Engine (wasm.js)"]
        SCANNERS["Scanners (recon, nuclei, trivy, zap, netexec, oobscan)"]
        GPG_VAULT["Evidence Vault & GPG (evidence.js, gpg.js)"]
    end

    subgraph MODULES["Modular Security Stack (12 Packages)"]
        VIGIL_SOC["Vigil AI-Native SOC"]
        OPEN_SEARCH["OpenSearch SIEM & Flamingo"]
        WAZUH["Wazuh XDR/SIEM"]
        FALCO["Falco eBPF"]
        SURICATA["Suricata IDS/IPS"]
        ZEEK["Zeek Network Metadata"]
        BLOODHOUND["BloodHound CE + Neo4j"]
        KCTF["Google kCTF"]
        OPENVAS["Greenbone OpenVAS"]
    end

    subgraph INFRA["Host & Cluster Runtime"]
        K3D["k3d Lightweight Kubernetes"]
        DOCKER["Docker Engine"]
        ETC_HOSTS["/etc/hosts (hostr)"]
        STORAGE["$XDG_CONFIG_HOME/vigilante/"]
    end

    CLI --> APP
    CLI --> MCP_CORE
    APP --> HUB
    HUB --> VIEWS
    VIEWS --> PALETTE
    APP --> ENGINE
    MCP_CORE --> TOOLS
    MCP_CORE --> RESOURCES
    TOOLS --> ENGINE
    RESOURCES --> ENGINE
    ENGINE --> MODULES
    MODULES --> K3D
    ENGINE --> INFRA
```

---

## 3. Data Flow & Execution Pipelines

### A. Autonomous Incident Response & Active Containment

```mermaid
sequenceDiagram
    autonumber
    participant Sensor as Detection Sensor (Falco/Suricata/Canary)
    participant SOC as Autonomous ReAct SOC (agent-soc.js)
    participant SOAR as SOAR Engine (soar.js)
    participant K8s as Kubernetes API
    participant Vault as Evidence Vault (evidence.js)
    participant GPG as GPG Non-Repudiation (gpg.js)

    Sensor->>SOC: Security Anomaly / Trip Alert Dispatched
    Note over SOC: Analyze pod telemetry, open ports, process tree
    SOC->>SOC: Classify Verdict: [CRITICAL] (CAT-3 Malicious Code)
    SOC->>SOAR: Trigger Emergency Containment (isolatePod)
    SOAR->>K8s: Apply Zero-Trust Deny-All NetworkPolicy
    SOAR->>SOAR: Freeze Pod Processes (SIGSTOP / cgroup)
    SOAR-->>SOC: Containment Active (cont-179049-rak16)
    SOC->>Vault: Save NIST SP 800-61 Incident Manifest
    Vault->>GPG: Compute Detached Cryptographic Signature (.asc)
    GPG-->>Vault: Signed Incident Record Sealed
    SOC-->>Sensor: Incident Fully Contained & Documented
```

---

### B. High-Throughput Security Data Lake Pipeline

```mermaid
flowchart LR
    subgraph Sources["Telemetry Ingestion"]
        FALCO["Falco Alerts"]
        ZEEK["Zeek Logs"]
        SURICATA["Suricata EVE"]
        AUDIT["K8s Audit"]
        CANARY["Canary Trips"]
    end

    subgraph LakeEngine["Security Data Lake Engine (datalake.js)"]
        NORMALIZER["Event Normalizer & ID Generator"]
        ADAPTER{"Backend Adapter"}
        SQLITE["node:sqlite (DatabaseSync)<br/>[Default / Free First]"]
        DUCKDB["DuckDB Driver<br/>[Official Supported]"]
        TABLE["Table: security_events<br/>(id, event_type, src_ip, dst_ip, severity, mitre, ts)"]
    end

    subgraph Consumers["Analytics & Threat Hunting"]
        CLI_Q["CLI Query (vigilante query)"]
        MCP_Q["MCP query_security_datalake"]
        HUNT["Retrospective Threat Hunter (CTI Sync)"]
    end

    Sources --> NORMALIZER
    NORMALIZER --> ADAPTER
    ADAPTER -->|Default| SQLITE
    ADAPTER -->|If Installed/Configured| DUCKDB
    SQLITE --> TABLE
    DUCKDB --> TABLE
    TABLE --> CLI_Q
    TABLE --> MCP_Q
    TABLE --> HUNT
```

---

### C. Autonomous Purple Team Simulation Pipeline

```mermaid
sequenceDiagram
    autonumber
    participant Arena as Purple Team Arena (purpleteam.js)
    participant Red as Red Adversary Agent
    participant Blue as Blue ReAct SOC Agent
    participant Scorecard as Scorecard Evaluator

    Arena->>Red: Launch Scenario (e.g. Lateral SMB & Privilege Escalation)
    Red->>Red: Step 1: Reconnaissance (T1046)
    Arena->>Blue: Ingest Telemetry
    Blue-->>Arena: Step 1 Detection Logged (Time: +4s)
    Red->>Red: Step 2: Credential Access (T1552)
    Arena->>Blue: Ingest Telemetry
    Blue-->>Arena: Step 2 Detection Logged
    Red->>Red: Step 3: Lateral Movement Attempt (T1021.002)
    Blue->>Blue: Detect Anomalous Lateral Link
    Blue->>Arena: Trigger SOAR Active Isolation
    Arena->>Red: Adversary Execution Blocked at Step 3
    Arena->>Scorecard: Calculate MTTD (4s) & MTTR (24s)
    Scorecard-->>Arena: Final Score: 98/100 (Grade: A+)
    Arena->>Arena: Render Signed Post-Mortem Report
```

---

## 4. Key Subsystem Specifications

### 1. Storage & State Architecture
Vigilante adopts the standard XDG Base Directory specification:
- **`$XDG_CONFIG_HOME/vigilante/config.yaml`**: Configuration preferences, default domain, theme.
- **`$XDG_CONFIG_HOME/vigilante/evidence/`**: Multi-tenant evidence tree partitioned by network CIDR and host IP.
- **`$XDG_CONFIG_HOME/vigilante/datalake/`**: Persistent embedded database (`events.db` or `events.duckdb`).
- **`$XDG_CONFIG_HOME/vigilante/canary/`**: Catalog of active canary honeytokens and decoy pods.
- **`$XDG_CONFIG_HOME/vigilante/carved/`**: Extracted files and reconstructed stream payloads.

### 2. Multi-Cluster Isolation & Instance Tracking
Multiple k3d cluster instances can coexist without port or state collisions:
- Every instance records its metadata in [`src/engine/instances.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/instances.js).
- Cluster state, certificates, and DNS entries are tagged with the specific cluster name (default: `vigilante-dev`).

### 3. Model Context Protocol Specification
The MCP server in `src/mcp/server.js` exposes:
- **54 Tools**: Spanning cluster management, vulnerability scanning, active containment, data lake querying, and posture auditing.
- **16 Static Resources**: Directly addressing cluster configurations, pod tables, evidence vaults, and NastyMap graphs via `vigilante://` URIs.
- **5 Parameterized Resource Templates**: For on-demand host profiles and evidence file inspection.
