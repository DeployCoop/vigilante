# 📦 Vigilante Security Modules Catalog

This document details all 12 modular security packages supported by **Vigilante**, including their architectural roles, default ports, ingress hostnames, default credentials, and customization options.

---

## 1. Module Overview Matrix

| Module Name | Category | Primary Function | Default Ingress URL | Default Credentials |
| :--- | :--- | :--- | :--- | :--- |
| **`vigil-soc`** | AI SOC | AI-Native SOC Investigation & Multi-Agent Triage | `https://vigil.vigilante.local` | `admin` / `admin` |
| **`vigil-local`** | Local SOC | Lightweight Local Agent Sandbox for Developers | `https://local.vigilante.local` | None |
| **`opensearch`** | SIEM / Log | OpenSearch SIEM Analytics & Dashboards | `https://siem.vigilante.local` | `admin` / `Admin123456!` |
| **`wazuh`** | XDR / SIEM | Wazuh Endpoint Security, Indexer & Manager | `https://wazuh.vigilante.local` | `admin` / `SecretPassword` |
| **`bloodhound`**| Attack Graph| BloodHound CE + Neo4j Active Directory/K8s Paths| `https://bloodhound.vigilante.local` | `admin` / `BloodHound123!` |
| **`falco`** | Runtime | eBPF Kernel Threat Detection & Container Escapes | In-Cluster DaemonSet | N/A |
| **`suricata`** | Network IDS | High-Speed Deep Packet Inspection & Threat Rules| In-Cluster DaemonSet / Ingress | N/A |
| **`zeek`** | Network Meta| Deep Network Protocol Parsing & Forensic Logging | In-Cluster DaemonSet | N/A |
| **`zap`** | DAST | OWASP ZAP Automated Web Vulnerability Scanner | `https://zap.vigilante.local` | API Key Managed |
| **`flamingo`** | SIEM UI | Modern OpenSearch Web Interface | `https://flamingo.vigilante.local` | Inherits OpenSearch |
| **`kctf`** | Cyber Range | Google kCTF Sandboxed Security Challenges | `https://ctf.vigilante.local` | CTF Admin Managed |
| **`openvas`** | Vulnerability| Greenbone Vulnerability Management (GVM) | `https://openvas.vigilante.local` | `admin` / `OpenVAS123!` |

---

## 2. Detailed Module Profiles

### 1. Vigil AI-Native SOC (`vigil-soc`)
- **Directory**: [`src/modules/vigil-soc/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/vigil-soc/)
- **Architecture**:
  - `agent-worker`: Background worker running multi-agent security triage pipelines.
  - `agent-serve`: REST and gRPC API serving agent decisions and case status.
  - `backend`: Core business logic service managing alerts, incidents, and episodic memory.
  - `daemon`: Stateful daemon aggregating alerts and telemetry streams.
  - `db-init-job`: PostgreSQL database migration pipeline managing 35 schema migrations (audit logs, episodic memory, verdict techniques, agent hash chains).
- **Ingress**: `https://vigil.vigilante.local`
- **Values Override**: `src/modules/vigil-soc/values/vigil.yaml`

---

### 2. OpenSearch SIEM (`opensearch`)
- **Directory**: [`src/modules/opensearch/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/opensearch/)
- **Architecture**:
  - OpenSearch cluster single-node deployment tuned for local development with JVM heap limits.
  - OpenSearch Dashboards pre-configured with security analytics indices and SIGMA detection rule collections.
  - Automated threat ingestion pipeline mapped to SIEM indices.
- **Ingress**: `https://siem.vigilante.local`
- **Default Credentials**: `admin` / `Admin123456!`

---

### 3. Wazuh XDR / SIEM (`wazuh`)
- **Directory**: [`src/modules/wazuh/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/wazuh/)
- **Architecture**:
  - **Wazuh Indexer**: Elasticsearch-compatible document datastore for security events.
  - **Wazuh Manager**: Core server processing agent telemetry, rule evaluations, and compliance checks.
  - **Wazuh Dashboard**: Kibana-based web console for threat exploration.
  - Agent event port `1514/TCP`, enrollment port `1515/TCP`, and Manager API port `55000/TCP`.
- **Ingress**: `https://wazuh.vigilante.local`
- **Default Credentials**:
  - Dashboard: `admin` / `SecretPassword`
  - Internal Service Account: `kibanaserver` / `kibanaserver`
  - Manager API: `wazuh-wui` / `MyS3cr37P450r.*-`

---

### 4. BloodHound Community Edition (`bloodhound`)
- **Directory**: [`src/modules/bloodhound/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/bloodhound/)
- **Architecture**:
  - BloodHound CE application server and Web UI.
  - Embedded Neo4j graph database instance storing Active Directory and Kubernetes RBAC attack paths.
  - Pre-wired collector endpoints for SharpHound and AzureHound ingest.
- **Ingress**: `https://bloodhound.vigilante.local`
- **Default Credentials**: `admin` / `BloodHound123!`

---

### 5. Falco eBPF Runtime Security (`falco`)
- **Directory**: [`src/modules/falco/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/falco/)
- **Architecture**:
  - Deployed as a Kubernetes DaemonSet with host PID and kernel tracing access.
  - Modern eBPF probe driver capturing system call activity across all containers.
  - Pre-packaged with standard Kubernetes threat rules (detecting shell spawns in containers, unauthorized binary execution, privilege escalation, and container escape breakouts).
  - Emits normalized JSON events directly into the Vigilante Evidence Vault and Data Lake.

---

### 6. Suricata Network Threat Engine (`suricata`)
- **Directory**: [`src/modules/suricata/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/suricata/)
- **Architecture**:
  - Multi-threaded network Intrusion Detection and Prevention System (IDS/IPS).
  - Synchronizes daily Emerging Threats (ET Open) threat signatures (>50,000 rules) via `vigilante` CTI engine.
  - Emits unified `eve.json` event logs recording DNS lookups, TLS handshakes, HTTP transactions, and signature alerts.

---

### 7. Zeek Deep Network Metadata Engine (`zeek`)
- **Directory**: [`src/modules/zeek/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/zeek/)
- **Architecture**:
  - High-fidelity behavioral network analysis platform (formerly Bro).
  - Passively reconstructs network protocol conversations without relying on rigid signatures.
  - Produces structured TSV and JSON metadata streams (`conn.log`, `dns.log`, `http.log`, `ssl.log`, `x509.log`).

---

### 8. OWASP ZAP Security Scanner (`zap`)
- **Directory**: [`src/modules/zap/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/zap/)
- **Architecture**:
  - Automated Zed Attack Proxy container running in daemon mode.
  - Exposes REST API on port `8080` for automated spidering, active scanning, and vulnerability reporting.
- **Ingress**: `https://zap.vigilante.local`

---

### 9. OpenSearch Flamingo Web UI (`flamingo`)
- **Directory**: [`src/modules/flamingo/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/flamingo/)
- **Architecture**:
  - Lightweight, modern next-gen web interface for querying and visualizing OpenSearch SIEM indices.
  - Connected directly to the OpenSearch cluster backend via internal Kubernetes service networking.
- **Ingress**: `https://flamingo.vigilante.local`

---

### 10. Google kCTF Cyber Range (`kctf`)
- **Directory**: [`src/modules/kctf/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/kctf/)
- **Architecture**:
  - Kubernetes-native CTF infrastructure developed by Google.
  - Provides sandboxed nsjail challenge isolation for binary exploitation (pwn), cryptography, reverse engineering, and web security scenarios.
- **Ingress**: `https://ctf.vigilante.local`

---

### 11. Greenbone OpenVAS (`openvas`)
- **Directory**: [`src/modules/openvas/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/openvas/)
- **Architecture**:
  - Full Greenbone Vulnerability Management (GVM) suite.
  - Includes daily updated Greenbone Community Feed (GCF) Network Vulnerability Tests (NVTs).
- **Ingress**: `https://openvas.vigilante.local`
- **Default Credentials**: `admin` / `OpenVAS123!`

---

### 12. Vigil Local Development Mode (`vigil-local`)
- **Directory**: [`src/modules/vigil-local/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/modules/vigil-local/)
- **Architecture**:
  - Minimalistic, low-footprint mock backend for rapid offline development, UI testing, and CI validation.
  - Avoids starting heavy Java/Elasticsearch containers when testing CLI interactions and reporting tools.

---

## 3. Values Customization Workflow

You can export default Helm values for all modules into an editable directory:
```bash
vigilante values export
```
This generates:
```text
values/
├── opensearch.yaml
├── opensearch-dashboards.yaml
├── wazuh.yaml
├── vigil.yaml
├── bloodhound.yaml
├── falco.yaml
├── suricata.yaml
└── zeek.yaml
```
Modify any values file and apply changes on deployment:
```bash
vigilante up -m wazuh -f ./values/wazuh.yaml
```
Alternatively, press `[v]` in the interactive terminal UI to edit values directly within your `$EDITOR`.
