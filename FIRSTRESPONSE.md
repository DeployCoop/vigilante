# 🚨 Vigilante Emergency Incident First Response Playbook

> **CRITICAL FIRST DIRECTIVE: DO NOT REBOOT OR POWER OFF COMPROMISED SYSTEMS.**
> Rebooting destroys volatile RAM artifacts, active network socket states, inject malware memory modules, and kernel ARP tables. Follow this playbook to contain the breach, preserve forensic evidence with cryptographic chain-of-custody, and determine root-cause initial access.

---

## 🧭 Executive Overview

This playbook provides a battle-tested, structured workflow for security professionals, incident responders, and SOC leads who suspect or have confirmed an active network breach.

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                B R E A C H   D E T E C T E D                                      │
└────────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ PHASE 1: IMMEDIATE TRIAGE & ISOLATION (0 - 15 MIN)                                             │
 │ • Establish Out-of-Band (OOB) Comms  • Network Isolation & Egress Block  • Boot IR Station     │
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ PHASE 2: DISCOVER SHADOW & LATERAL ASSETS (15 - 30 MIN)                                        │
 │ • Subnet Discovery Sweeps (`vigilante scan`) • Topology & Open Port Matrix (`vigilante xml`)  │
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ PHASE 3: VOLATILE EVIDENCE ACQUISITION & GPG SIGNING (30 - 60 MIN)                             │
 │ • Capture Triage Bundle (`[t]`) • Net/Host/Data Vault Hierarchy • Detached GPG Signatures (.asc)│
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ PHASE 4: ROOT-CAUSE INVESTIGATION ("HOW THE ADVERSARY GOT IN")                                 │
 │ • Initial Access Vectors • Persistence Checks • Ingress Banners • ARP Spoofing / MITM Checks   │
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ PHASE 5: AI-AUGMENTED THREAT CORRELATION (LOCAL OLLAMA / MCP)                                  │
 │ • Private Offline Ollama Reasoning (`vigilante ai`) • CVE Auditing • MCP Tool Grounding        │
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ PHASE 6: CONTAINMENT, ERADICATION & GPG-SIGNED INCIDENT REPORT                                 │
 │ • Revoke Credentials & TLS CAs • NetworkPolicy Lockdown • Export Signed Post-Mortem Report     │
 └────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## ⏱️ Phase 1: Immediate Triage & Isolation (Minutes 0 – 15)

### 1.1 Out-of-Band (OOB) Communications
- **Never discuss incident response over internal email, Slack, or Teams** if the corporate network is potentially compromised.
- Switch the incident response team immediately to dedicated external Signal groups, hardware tokens, or air-gapped devices.

### 1.2 Network-Level Containment (Do NOT Power Off)
1. **Sever External Ingress / Egress**:
   - Apply boundary firewall drop rules for non-essential outbound traffic to prevent active data exfiltration or Command & Control (C2) beaconing.
2. **Segment the Affected VLAN / Subnet**:
   - Isolate compromised subnets (e.g., `10.0.1.0/24`) using VLAN tagging or switch port isolation.
3. **Preserve Volatile Host State**:
   - If taking a machine off the network, disconnect the physical Ethernet cable or disable virtual NICs; do **not** restart the operating system.

### 1.3 Launch Vigilante Forensic Operations Hub
From your designated secure analyst workstation:
```bash
# 1. Verify environment prerequisites
vigilante status

# 2. Open the Central Operations Hub
vigilante menu
# or press [Tab] anytime inside Vigilante
```

---

## 📡 Phase 2: Live Network Reconnaissance & Shadow Infrastructure Discovery (Minutes 15 – 30)

Adversaries often deploy shadow infrastructure, secondary backdoors, or lateral scanning tools within minutes of gaining initial footholds.

### 2.1 Discover All Live Hosts Across Breach Subnets
Launch network reconnaissance against the suspected subnet:
```bash
# Open the Nmap Reconnaissance console
vigilante scan
```
- Press **`[i]`** and enter the target subnet (e.g., `10.0.1.0/24`, `192.168.1.0/24`, or Kubernetes Pod CIDR `10.42.0.0/16`).
- Select profile: `🗺️ Network Ping Sweep / Host Discovery` or `⚡ Network Sweep & Top Ports`.
- Press **`[n]`** to execute the scan.

### 2.2 Inspect Topology and Open Ports in the Visualizer
```bash
# Launch the interactive XML Visualizer
vigilante xml
```
1. Press **`[s]`** to select the latest XML scan report.
2. Press **`[f]`** to filter by `🔓 Open Ports` or `🛡️ Script / CVEs`.
3. Identify:
   - **Rogue IP Addresses**: Unregistered or uninventoried MAC addresses.
   - **Unexpected Listening Ports**: E.g., `4444`, `1337`, `8080`, `9001`, `31337`, or SSH running on non-standard ports (`2222`).
   - **Exposed Database & Storage Ports**: Unauthenticated Redis (`6379`), Elasticsearch/OpenSearch (`9200`), MongoDB (`27017`).

---

## 📁 Phase 3: Volatile Evidence Acquisition with GPG Non-Repudiation (Minutes 30 – 60)

For forensic evidence to be legally admissible and tamper-evident during post-incident audits or law enforcement handoffs, every artifact must be cryptographically signed at the exact moment of acquisition.

### 3.1 Enable GPG Signing in `config.yaml`
Ensure your responder GPG identity is configured in `$XDG_CONFIG_HOME/vigilante/config.yaml`:
```yaml
gpg:
  enabled: true
  keyId: "ir-lead@yourcompany.com" # GPG email, Key ID, or fingerprint
  autoSign: true
  detached: true
```

### 3.2 Execute Automated Parallel Forensic Triage
Inside `vigilante xml`, highlight the suspected host (e.g. `10.0.1.15`) and press **`[t]`** (Full IR Triage Bundle).

Vigilante automatically executes parallel probes and archives structured artifacts into the hierarchical **Evidence Vault** (`$XDG_CONFIG_HOME/vigilante/evidence/<network>/<host>/`):

| Artifact File | Evidence Collected | Adversary Investigation Value |
| :--- | :--- | :--- |
| `ping.json` | ICMP RTT latency, packet loss, jitter | Detects network throttling, local proxy delays, or dropped hops. |
| `mtr.txt` | Per-hop route traceroute and packet loss | Identifies unauthorized inline gateways, BGP/route poisoning, and upstream MITM taps. |
| `dns_records.json` | Forward A/AAAA/CNAME & Reverse PTR lookups | Detects DNS hijacking, internal spoofing, and C2 domain name resolution. |
| `tls_certificates.pem` | Full X.509 certificate chain & SAN entries | Uncovers rogue self-signed certificates, compromised internal CAs, or TLS inspection proxies. |
| `http_headers.txt` | Raw HTTP response headers & server tokens | Identifies attacker webshell headers, altered server versions, or injected reverse proxy banners. |
| `arp_neighbors.json` | Kernel ARP / Neighbor table (`ip neigh`) | **Detects ARP Cache Poisoning**: Identifies duplicate MAC addresses impersonating default gateways. |
| `triage_summary.json` | Master index with timestamps & SHA-256 hashes | Establishes the authoritative chain-of-custody timeline. |

Every artifact automatically receives a cryptographic signature file:
```
$XDG_CONFIG_HOME/vigilante/evidence/10.0.1.0_24/10.0.1.15/
├── triage_summary.json        ├── triage_summary.json.asc  (🔏 Signed)
├── ping.json                  ├── ping.json.asc
├── mtr.txt                    ├── mtr.txt.asc
├── dns_records.json           ├── dns_records.json.asc
├── tls_certificates.pem      ├── tls_certificates.pem.asc
├── http_headers.txt           ├── http_headers.txt.asc
└── arp_neighbors.json         └── arp_neighbors.json.asc
```

---

## 🔍 Phase 4: Determining Root Cause ("How the Criminal Got In")

Use this structured matrix to map discovered telemetry against the primary **MITRE ATT&CK Initial Access Vectors**:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                             INITIAL ACCESS INVESTIGATION MATRIX                                  │
├───────────────────────┬──────────────────────────────────────────┬───────────────────────────────┤
│ Vector                │ Artifacts & Telemetry to Inspect          │ Vigilante Action              │
├───────────────────────┼──────────────────────────────────────────┼───────────────────────────────┤
│ 1. Exploited Public   │ Web server banners (`http_headers.txt`), │ `vigilante xml` -> [2] CVEs   │
│    Application (CVEs) │ NSE vuln scripts, unpatched services     │ `vigilante ai` -> [2] Vulns   │
├───────────────────────┼──────────────────────────────────────────┼───────────────────────────────┤
│ 2. Compromised        │ SSH services on non-standard ports,      │ `vigilante scan` (Service)    │
│    Credentials / RDP  │ RDP (3389), VNC (5900), Telnet (23)      │ `vigilante threat-sim`        │
├───────────────────────┼──────────────────────────────────────────┼───────────────────────────────┤
│ 3. Ingress / TLS /    │ Expired certificates, missing SANs,      │ Probes: [c] TLS Chain         │
│    MITM Interception  │ mismatched issuer CAs in .pem dumps      │ Evidence: tls_certificates.pem│
├───────────────────────┼──────────────────────────────────────────┼───────────────────────────────┤
│ 4. Network Lateral    │ Conflicting MAC addresses in ARP cache,  │ Probes: [a] ARP Neighbors     │
│    Poisoning (ARP/DNS)│ DNS PTR records pointing to rogue C2s    │ Evidence: arp_neighbors.json  │
├───────────────────────┼──────────────────────────────────────────┼───────────────────────────────┤
│ 5. Container & Cloud  │ Pod restart loops, CrashLoopBackOff,     │ `vigilante pods`              │
│    Workload Escape    │ unauthorized privileged containers       │ `describe_pod` / `get_pod_logs`│
└───────────────────────┴──────────────────────────────────────────┴───────────────────────────────┘
```

### 4.1 Step-by-Step Investigation Walkthrough

#### Step A: Verify Ingress Vulnerabilities and Exposed Banners
Run a targeted vulnerability audit:
```bash
vigilante scan
# Select target IP -> Profile: 🛡️ Vulnerability & Threat Audit (-sV --script=vuln)
```
- Review the parsed report in `vigilante xml` to check if known remote code execution (RCE) CVEs (e.g. Log4j, OpenSSL buffer overflows, Spring4Shell) match the host's running services.

#### Step B: Check for ARP Gateway Impersonation (MITM)
Inspect the captured `arp_neighbors.json`:
- If the default gateway's IP address (e.g. `10.0.1.1`) is mapped to a MAC address belonging to another workstation or an unknown vendor, an adversary is actively conducting **ARP Spoofing / Man-In-The-Middle** packet sniffing.

#### Step C: Inspect Kubernetes Infrastructure & Workload Integrity
If running containerized workloads:
```bash
# Launch live pod monitor
vigilante pods
```
- Look for unexpected pods in system namespaces (`kube-system`, `default`).
- Highlight suspicious pods and press **`[d]`** to describe container security contexts (look for `privileged: true`, host path mounts `/`, or root execution).
- Press **`[l]`** to tail container logs for unauthorized process spawns (`/bin/sh`, `curl`, `nc -e`, crypto miners).

---

## 🤖 Phase 5: AI-Augmented Forensic Analysis (Local Ollama / MCP)

Use Vigilante's built-in AI analyst for rapid pattern recognition and anomaly correlation across all gathered telemetry.

### 5.1 Launching the AI Security Analyst
```bash
vigilante ai
```
*(By default, Vigilante connects directly to your local **Ollama** daemon at `http://localhost:11434` for 100% private, offline forensic reasoning without leaking breach data to third-party clouds).*

### 5.2 Execute Forensic Presets
Inside the AI Analyst console:
- Press **`[1]`** (**Recon Summary**): Identifies exposed high-risk ports and anomalous subnets.
- Press **`[2]`** (**Vulnerability & CVE Audit**): Correlates software versions with exploit advisories and generates remediation rules.
- Press **`[3]`** (**Incident Triage Review**): Ingests the entire Evidence Vault hierarchy and detects multi-vector anomalies.
- Press **`[4]`** (**Kubernetes Pod Audit**): Pinpoints crashed containers, restart loops, and misconfigured ingress controllers.
- Press **`[5]`** (**Threat Correlation**): Correlates findings with simulated threat patterns and outputs an executive defense plan.

### 5.3 Custom Natural Language Queries
Press **`[i]`** or **`[Space]`** to ask free-form forensic questions:
- *"Based on the ARP cache and MTR traceroutes for host 10.0.1.15, is there evidence of traffic redirection or MITM?"*
- *"Generate an iptables ruleset and Kubernetes NetworkPolicy to isolate host 10.0.1.15 while allowing forensic telemetry on port 22."*

---

## 🛡️ Phase 6: Containment, Eradication & Hardening Checklist

Execute these containment actions in order:

- [ ] **1. Cryptographic Identity Revocation**:
  - Revoke all compromised SSH keys, API tokens, and IAM service account credentials.
  - Regenerate local trusted TLS wildcard certificates using `vigilante up --domain <domain>`.
- [ ] **2. Network Policy Isolation**:
  - Apply default-deny `NetworkPolicy` objects to restrict pod-to-pod traffic in Kubernetes:
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: default-deny-all
      namespace: <affected-namespace>
    spec:
      podSelector: {}
      policyTypes:
      - Ingress
      - Egress
    ```
- [ ] **3. Ingress Route Lockdown**:
  - Clean up exposed `/etc/hosts` domain mappings if rogue ingress was established:
    ```bash
    vigilante hostr --remove
    ```
- [ ] **4. Patch and Re-deploy Clean Base Images**:
  - Re-deploy security modules into isolated namespaces (`vigilante up -n containment-lab -m opensearch,vigil-soc`).

---

## 📄 Phase 7: Post-Incident Forensic Reporting & Executive Debrief

### 7.1 Export GPG-Signed Analysis Report
Inside `vigilante ai`, press **`[x]`** to export the AI analysis report:
- Saved to `$XDG_CONFIG_HOME/vigilante/evidence/ai_reports/report-<timestamp>-<topic>.md`
- Automatically signed with your GPG detached signature (`.asc`).

### 7.2 Incident Documentation Template

When presenting the breach report to executive leadership, legal counsel, and insurance underwriters, structure the findings using this standard format:

```markdown
# Security Incident Post-Mortem Report

## 1. Incident Metadata
- **Incident ID**: INC-YYYYMMDD-01
- **Severity**: [CRITICAL | HIGH | MEDIUM | LOW]
- **Date / Time of Detection**: [UTC Timestamp]
- **Lead Incident Responder**: [Name / GPG Fingerprint]

## 2. Executive Summary
Brief non-technical summary of what occurred, affected business assets, duration of intrusion, and current containment status.

## 3. Initial Access Vector & Root Cause
- **Entry Point**: [e.g. Unauthenticated Ingress on Port 9200 / Exploited CVE-XXXX-XXXX]
- **Adversary Activity**: [Tools, commands, persistence mechanisms identified]
- **Evidence Reference**: `evidence/10.0.1.0_24/10.0.1.15/triage_summary.json` (🔏 GPG Verified)

## 4. Timeline of Events (UTC)
- `HH:MM`: Initial anomaly detected via network reconnaissance sweep.
- `HH:MM`: Forensic triage bundle acquired and signed with GPG non-repudiation.
- `HH:MM`: Affected subnet isolated via firewall and NetworkPolicy rules.
- `HH:MM`: Root-cause initial access confirmed.

## 5. Containment & Eradication Actions Taken
List all revoked credentials, patched CVEs, updated firewall rules, and re-provisioned clusters.

## 6. Long-Term Hardening Recommendations
Action items to prevent recurrence.
```

---

## 🚀 Quick Reference Commands

| Goal | Command |
| :--- | :--- |
| **Open Operations Hub** | `vigilante menu` *(or press `[Tab]`)* |
| **Run Subnet Reconnaissance** | `vigilante scan` |
| **Inspect Topology & Probes** | `vigilante xml` |
| **Full Host IR Triage Bundle** | Highlight host in `vigilante xml` ➔ Press `[t]` |
| **Launch AI Security Analyst** | `vigilante ai` *(or `vigilante ask`)* |
| **Verify Pod Infrastructure** | `vigilante pods` |
| **Check Environment & TLS** | `vigilante status` |
| **Start MCP Server for LLMs** | `vigilante mcp` |
| **Export GPG Signed Report** | Press `[x]` inside `vigilante ai` |

---

*Stay vigilant. Preserve volatile data, sign every artifact, and contain rapidly.*
