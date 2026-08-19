# 🚨 Vigilante Emergency Incident First Response Playbook
## Authoritative Incident Handling Guide Aligned with NIST SP 800-61 Rev. 2

> **CRITICAL FIRST DIRECTIVE: DO NOT REBOOT OR POWER OFF COMPROMISED SYSTEMS.**
> Rebooting or abruptly powering off machines destroys volatile memory (RAM), active network socket connections, injected malware payloads residing exclusively in memory, temporary staging directories, and kernel ARP routing tables. Follow this playbook to systematically execute the **NIST SP 800-61 Revision 2 Incident Response Lifecycle**, contain the intrusion, preserve forensic evidence with cryptographic chain-of-custody, and document root-cause initial access.

---

## 🧭 NIST SP 800-61 Rev. 2 Incident Response Lifecycle Overview

NIST Special Publication 800-61 Revision 2 (*Computer Security Incident Handling Guide*) defines four core lifecycle phases. Vigilante maps every phase directly to automated forensics, cryptographic evidence vaults, network probes, and AI-augmented telemetry analysis:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                      NIST SP 800-61 REV. 2 INCIDENT RESPONSE LIFECYCLE                           │
└────────────────────────────────────────────────┬─────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ 1. PREPARATION (NIST Sec 2.3 & 3.1)                                                            │
 │ • Out-of-Band (OOB) Secure Communications     • Responder GPG Identity Configuration           │
 │ • Incident Handling Jump Station Preparation  • Baseline Network & Host Topology Profiling    │
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ 2. DETECTION & ANALYSIS (NIST Sec 3.2)                                                         │
 │ • Precursor & Indicator Identification        • Attack Vector Categorization                   │
 │ • Live Reconnaissance & Subnet Sweeps (`scan`) • Order of Volatility Acquisition (RFC 3227)    │
 │ • Automated Parallel Triage Bundle (`[t]`)    • Detached GPG Non-Repudiation Signatures (.asc) │
 │ • Incident Prioritization (Impact Matrix)     • AI-Augmented Forensic Grounding (`vigilante ai`)│
 │ • Root-Cause Initial Access Determination     • Stakeholder & Regulatory Incident Notification │
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ 3. CONTAINMENT, ERADICATION & RECOVERY (NIST Sec 3.3)                                          │
 │ • Containment Strategy Selection              • Network Segmentation & Default-Deny Policies   │
 │ • Lateral Movement Disruption (ARP/DNS/SMB)   • Credential Revocation & TLS CA Invalidation    │
 │ • Adversary Tool & Webshell Eradication       • Phased Recovery with High-Frequency Monitoring │
 └───────────────────────────────────────────────┬────────────────────────────────────────────────┘
                                                 │
 ┌───────────────────────────────────────────────▼────────────────────────────────────────────────┐
 │ 4. POST-INCIDENT ACTIVITY (NIST Sec 3.4)                                                       │
 │ • Lessons Learned Conference & Action Items   • Incident Data & CSIRT Metrics Collection       │
 │ • Multi-Year Evidence Vault Retention         • GPG-Signed Executive Post-Mortem Reporting     │
 └────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Phase 1: Preparation (NIST SP 800-61 § 2.3 & § 3.1)

Preparation ensures responders possess the requisite tooling, communication channels, cryptographic identities, and baseline data *before* an incident occurs or during immediate mobilization.

### 1.1 Establish Out-of-Band (OOB) Secure Communications
- **Zero Trust on Corporate Infrastructure**: Assume internal email, Microsoft Teams, Slack, PBX phones, and internal ticketing systems are actively monitored by the adversary.
- **Dedicated OOB Channel**: Responders must immediately transition to dedicated, out-of-band communication channels:
  - Hardware-token-secured Signal messenger groups.
  - Dedicated cellular devices operating outside corporate Wi-Fi.
  - Air-gapped analyst workstations.

### 1.2 Configure Responder Cryptographic GPG Identity
NIST guidelines require that all acquired evidence maintains strict integrity and legal chain of custody. Ensure your GPG signing identity is configured in `$XDG_CONFIG_HOME/vigilante/config.yaml`:

```yaml
# $XDG_CONFIG_HOME/vigilante/config.yaml
gpg:
  enabled: true
  keyId: "ir-team@vigilante.local"  # GPG email, Key ID, or 40-char fingerprint
  autoSign: true                     # Automatically sign every acquired evidence file
  detached: true                     # Generate verifiable .asc detached signature files
```

### 1.3 Initialize the Vigilante Forensic Incident Jump Station
On your designated secure analyst workstation:
```bash
# 1. Verify environmental dependencies and runtime readiness
vigilante status

# 2. Open the Central Operations Hub
vigilante menu
# or press [Tab] anywhere within Vigilante
```

---

## 🔍 Phase 2: Detection & Analysis (NIST SP 800-61 § 3.2)

The Detection & Analysis phase focuses on identifying precursors and indicators, scoping the breach across the network, acquiring volatile evidence, assessing incident severity, and determining root-cause initial access.

### 2.1 Attack Vector Categorization (NIST Table 3-1)
NIST SP 800-61 categorizes incidents by primary attack vector. Map your telemetry immediately to one or more vectors:

| Attack Vector (NIST) | Vector Definition | Typical Telemetry / Artifacts | Vigilante Action |
| :--- | :--- | :--- | :--- |
| **External / Removable Media** | Attack executed from removable hardware or peripheral media. | Rogue USB autorun, unauthorized mass storage, raw device mount logs. | Audit endpoint kernel logs. |
| **Attrition / Denial of Service** | Attacks employing brute force or flooding to degrade or exhaust resources. | High volume TCP SYN bursts, SSH authentication floods, DNS floods. | `vigilante threat-sim -s credential-bruteforce` |
| **Web Application** | Attacks executed against web applications, REST APIs, or HTTP ingress. | JNDI/Log4j strings, SQL injection, webshells, abnormal HTTP response headers. | `vigilante scan` (Vuln profile) & `http_headers.txt` |
| **Email / Phishing** | Attacks executed via spear phishing, malicious attachments, or social links. | Phishing payloads, credential harvest domains, malicious Office macros. | Audit mail gateway & DNS lookups. |
| **Impersonation / MITM** | Attacks involving spoofing, rogue gateways, or identity theft. | Duplicate MAC addresses in ARP cache, rogue default gateways, hijacked DNS. | `arp_neighbors.json` & `dns_records.json` |
| **Improper Usage / Privilege Escalation** | A user or compromised service violates acceptable use or escapes isolation. | Unauthorized `sudo`, chroot host breakouts, Kubernetes SA token misuse. | `vigilante pods` & `describe_pod` |
| **Loss / Theft of Equipment** | Physical theft or loss of computing equipment containing credentials. | Missing laptops, unencrypted offline storage access. | Immediate identity revocation. |

---

### 2.2 Signs of an Incident: Precursors vs. Indicators (NIST § 3.2.2)

Understanding whether telemetry represents a **Precursor** or an **Indicator** is critical for prioritization:
- **Precursor**: A sign that an attack *may happen in the future* (e.g., port scan activity from an external IP, vulnerability scanner probes against web endpoints, security mailing list zero-day announcements).
- **Indicator**: A sign that an attack *has happened or is actively happening right now* (e.g., unexpected listening ports on high numbers, duplicate MAC address claiming default gateway, multiple SSH authentication failures followed by root login, volume shadow copies deleted via `vssadmin`).

---

### 2.3 Network Profiling & Live Host Discovery (NIST § 3.2.4)
Adversaries frequently spin up temporary backdoors, staging servers, and pivot listeners. Rapidly scan the affected network segments:

```bash
# Launch Nmap Reconnaissance console
vigilante scan
```
1. Press **`[i]`** and specify the suspected subnet (e.g. `10.0.1.0/24`, `192.168.1.0/24`, or Kubernetes Pod CIDR `10.42.0.0/16`).
2. Select scan profile:
   - `🗺️ Network Ping Sweep / Host Discovery`: Rapid ICMP/ARP host discovery.
   - `⚡ Network Sweep & Top Ports`: Sweep with port checks on common service ports.
   - `🛡️ Vulnerability & Threat Audit`: Service version detection (`-sV`) and NSE vulnerability scripts (`--script=vuln`).
3. Press **`[n]`** to execute the scan.

Inspect results in the **Network Topology & XML Visualizer**:
```bash
vigilante xml
```
- Press **`[s]`** to select the newest XML scan report.
- Press **`[f]`** to filter by `🔓 Open Ports` or `🛡️ Script / CVE Findings`.
- Identify uninventoried MAC addresses, unexpected listeners (`4444`, `1337`, `8080`, `9001`), and unauthenticated databases (`9200`, `6379`, `27017`).

---

### 2.4 Order of Volatility Evidence Acquisition (RFC 3227 & NIST SP 800-86)

When collecting digital evidence, responders MUST acquire artifacts strictly in order of volatility from most volatile to least volatile:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                  ORDER OF VOLATILITY (RFC 3227)                                  │
├───────┬──────────────────────────────────┬───────────────────────────────────────────────────────┤
│ Rank  │ Volatility Level                 │ Forensic Artifact & Evidence Collection Method        │
├───────┼──────────────────────────────────┼───────────────────────────────────────────────────────┤
│ **1** │ CPU Registers, Cache, Buffers    │ Hardware registers, CPU state dumps.                   │
│ **2** │ System Memory (RAM)              │ Volatile processes, injected DLLs, unencrypted keys.  │
│ **3** │ Network State & Sockets          │ Active TCP/UDP connections, ARP cache, routing tables.│
│ **4** │ Running Processes & File Handles │ Process tree, open file descriptors, active sockets.  │
│ **5** │ Disk & Persistent Storage        │ Local filesystems, logs, configuration files.         │
│ **6** │ Remote Logs & Network Devices    │ SIEM index logs, firewall logs, NetFlow data.         │
│ **7** │ Archival & Backup Media          │ Tape backups, snapshot archives, cold storage.        │
└───────┴──────────────────────────────────┴───────────────────────────────────────────────────────┘
```

#### Automated Parallel Triage Bundle (`[t]`)
In `vigilante xml`, highlight the target suspect host (e.g. `10.0.1.15`) and press **`[t]`** (Full IR Triage Bundle).

Vigilante executes non-destructive parallel forensic probes and records structured artifacts into the **Incident Response Evidence Vault** (`$XDG_CONFIG_HOME/vigilante/evidence/<network>/<host>/`):

| Artifact File | Collected Forensic Telemetry | NIST Investigation Utility |
| :--- | :--- | :--- |
| `arp_neighbors.json` | Kernel ARP / Neighbor table (`ip neigh`) | **Detects MITM**: Identifies duplicate MAC addresses claiming the Default Gateway. |
| `ping.json` | ICMP RTT latency, packet loss, jitter | Detects network throttling, local proxy delays, or dropped hops. |
| `mtr.txt` | Per-hop route traceroute and loss stats | Identifies unauthorized inline gateways, BGP/route poisoning, and upstream MITM taps. |
| `dns_records.json` | Forward A/AAAA/CNAME & Reverse PTR lookups | Detects DNS hijacking, internal spoofing, and C2 domain name resolution. |
| `tls_certificates.pem` | Full X.509 certificate chain & SAN entries | Uncovers rogue self-signed certificates, compromised internal CAs, or TLS inspection proxies. |
| `http_headers.txt` | Raw HTTP response headers & server tokens | Identifies attacker webshell headers, altered server versions, or injected reverse proxy banners. |
| `triage_summary.json` | Master index with timestamps & SHA-256 hashes | Establishes the authoritative chain-of-custody timeline. |

Every artifact is automatically signed with your responder GPG key:
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

### 2.5 Incident Prioritization & Impact Assessment (NIST § 3.2.6)

NIST SP 800-61 requires prioritizing incidents based on three distinct scoring dimensions:

#### 1. Functional Impact (Impact to Business & Operational Systems)
- **None**: No effect on business operations.
- **Low**: Minimal impact on non-critical systems; core business functions intact.
- **Medium**: Critical system degraded; some services unavailable to users.
- **High**: Critical systems offline; core business operations completely halted.

#### 2. Information Impact (Impact to Organizational Data)
- **None**: No data compromised.
- **Privacy Breach**: PII (Personally Identifiable Information) or sensitive employee/customer data accessed.
- **Proprietary Breach**: Core intellectual property, trade secrets, or source code exfiltrated.
- **Integrity Loss**: Data maliciously altered, database records modified, or files encrypted (ransomware).

#### 3. Recoverability Effort
- **Regular**: Predictable recovery time with existing in-house CSIRT staff.
- **Supplemented**: Recovery requires external assistance (contracted IR retainers, vendor specialists).
- **Extended**: Recovery time is unpredictable; full infrastructure rebuild required.
- **Not Recoverable**: Data or systems permanently lost (e.g. wiper malware without verified backups).

---

### 2.6 Root-Cause Initial Access Investigation ("How the Criminal Got In")

Use this structured matrix to identify the primary initial access vector:

```
┌──────────────────────────────────────────────────────────────────────────────────────────────────┐
│                             INITIAL ACCESS INVESTIGATION MATRIX                                  │
├───────────────────────┬──────────────────────────────────────────┬───────────────────────────────┤
│ Vector                │ Artifacts & Telemetry to Inspect          │ Vigilante Action              │
├───────────────────────┼──────────────────────────────────────────┼───────────────────────────────┤
│ 1. Exploited Public   │ Web server banners (`http_headers.txt`), │ `vigilante xml` -> [f] CVEs   │
│    Application (CVEs) │ NSE vuln scripts, unpatched services     │ `vigilante ai` -> [2] CVEs    │
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

#### Step A: Verify Ingress Vulnerabilities and Software CVEs
- Review NSE vulnerability scan results in `vigilante xml` to match unpatched web endpoints or database ports against CVE databases (e.g. Log4j CVE-2021-44228, Spring4Shell CVE-2022-22965, OpenSSL CVE-2022-3602).

#### Step B: Check for ARP Gateway Impersonation (MITM)
- Review `arp_neighbors.json`: If the Default Gateway IP (`10.0.1.1`) is mapped to an unexpected MAC address or a vendor mismatch is discovered, an attacker is actively performing **ARP Poisoning** to intercept credentials and session cookies.

#### Step C: Inspect Kubernetes Infrastructure & Workload Integrity
- Run `vigilante pods` to monitor live pods across all namespaces (`-A -o wide`).
- Press **`[d]`** to describe container security contexts. Flag any container running with `privileged: true`, host PID/IPC namespaces, or mounting root host paths (`/host`, `/var/run/docker.sock`).
- Press **`[l]`** to inspect live container logs for spawned shells (`/bin/sh`, `/bin/bash`), unauthorized downloads (`curl`, `wget`), or mining binaries (`xmrig`).

---

### 2.7 AI-Augmented Threat Correlation (Local & Cloud Providers)

Vigilante includes an interactive AI security analyst (`vigilante ai`) grounded in real-time MCP telemetry.

```bash
# Launch interactive AI Security Analyst console
vigilante ai
```

- **100% Private Offline Analysis (Default)**: Connects to local **Ollama** (`http://localhost:11434`) so zero breach telemetry leaves your environment.
- **Multi-Provider Switcher (`[p]`)**: Switch instantly between **Ollama**, **Anthropic (Claude)**, **OpenAI (ChatGPT)**, **Google Gemini**, **DeepSeek**, **Groq**, and **OpenRouter**.
- **Model Switcher (`[m]`)**: Pick specific models (e.g., `llama3.2`, `claude-3-5-sonnet`, `gpt-4o`).

#### Quick Forensic Presets:
- **`[1]` (Recon & Open Ports)**: Summarizes discovered network hosts and highlights unauthenticated exposures.
- **`[2]` (Vulnerabilities & CVEs)**: Identifies software CVEs from banner grabs and outputs remediation rules.
- **`[3]` (Incident Triage Review)**: Correlates `ping.json`, `mtr.txt`, `dns_records.json`, `tls_certificates.pem`, and `arp_neighbors.json` across the Evidence Vault.
- **`[4]` (Kubernetes Pod Audit)**: Detects container crashes, restart loops, and misconfigured ingress rules.
- **`[5]` (Threat Correlation)**: Correlates telemetry against MITRE ATT&CK techniques and generates containment playbooks.

---

### 2.8 Incident Notification & Reporting (NIST § 3.2.7)
NIST requires timely notification to internal and external stakeholders based on predefined escalation thresholds:

- **Internal Notifications**:
  - Chief Information Security Officer (CISO) & VP of Infrastructure.
  - General Counsel / Corporate Legal (attorney-client privilege protections).
  - Public Relations & Corporate Communications.
- **External Notifications (Subject to Legal Guidance)**:
  - Regulatory Bodies (GDPR, HIPAA, SEC 4-day disclosure rule for material cyber incidents, PCI-DSS).
  - Cyber Insurance Carrier & Designated Breach Coach.
  - Law Enforcement (FBI Cyber Division, US Secret Service, local cyber task forces).
  - National CSIRT / Coordination Centers (CISA, US-CERT).

---

## 🛡️ Phase 3: Containment, Eradication & Recovery (NIST SP 800-61 § 3.3)

### 3.1 Choosing a Containment Strategy (NIST § 3.3.1)
Select containment actions by evaluating:
1. **Potential Damage**: Threat to financial, operational, or life-safety assets.
2. **Evidence Preservation**: Ability to preserve RAM and logs prior to network disconnection.
3. **Service Availability**: Business necessity of maintaining partial system uptime.
4. **Time & Resource Requirements**: Speed of applying isolation vs duration of outage.
5. **Solution Effectiveness**: Complete containment vs temporary stopgap.

### 3.2 Containment Execution Procedures
- [ ] **1. Cryptographic Identity Revocation**:
  - Immediately revoke all compromised SSH public keys, API bearer tokens, AWS/GCP IAM credentials, and Kubernetes ServiceAccount secrets.
  - Regenerate local TLS certificates and root CAs using `vigilante up --domain <domain>`.
- [ ] **2. Kubernetes NetworkPolicy Lockdown**:
  - Apply default-deny ingress/egress `NetworkPolicy` objects to isolate compromised pods:
    ```yaml
    apiVersion: networking.k8s.io/v1
    kind: NetworkPolicy
    metadata:
      name: breach-containment-deny-all
      namespace: <affected-namespace>
    spec:
      podSelector: {}
      policyTypes:
      - Ingress
      - Egress
    ```
- [ ] **3. Ingress Route & Domain Cleanup**:
  - Clean up exposed `/etc/hosts` domain mappings if rogue ingress was established:
    ```bash
    vigilante hostr --remove
    ```
- [ ] **4. Firewall Subnet Segmentation**:
  - Isolate the breach subnet (e.g. `10.0.1.0/24`) at the boundary switch or router.

### 3.3 Eradication (NIST § 3.3.3)
- Identify all adversary artifacts across affected hosts (webshells, cron jobs, rogue systemd units, unauthorized SSH `authorized_keys`).
- Close initial access vulnerabilities (apply security patches, update vulnerable Helm chart versions via `vigilante values`).
- Re-deploy workloads from verified clean, immutable container base images into clean namespaces (`vigilante up -n containment-lab -m opensearch,vigil-soc`).

### 3.4 Recovery & Phased Resumption (NIST § 3.3.4)
- **Phased Restoration**: Bring systems back online incrementally, prioritizing core business dependencies.
- **Enhanced Monitoring**: Increase polling and logging frequency (`vigilante pods`, `vigilante status`).
- **Validation**: Confirm normal baselines, verify SSL/TLS certificates, and test application authentication.

---

## 📈 Phase 4: Post-Incident Activity (NIST SP 800-61 § 3.4)

### 4.1 Lessons Learned Conference (NIST § 3.4.1)
Hold a mandatory Lessons Learned meeting within two weeks of incident resolution with all CSIRT members, IT operations, executive leadership, and legal counsel. Answer:
1. Exactly what happened, and at what specific timestamps (UTC)?
2. How well did staff and incident handling procedures perform?
3. What information or forensic telemetry was needed sooner?
4. What precursors or indicators were missed?
5. What corrective actions, firewall rules, or detection playbooks must be implemented to prevent recurrence?

### 4.2 Incident Metrics & CSIRT KPI Tracking (NIST § 3.4.2)
Record authoritative metrics to evaluate defense posture:
- **Mean Time to Detect (MTTD)**: Time from initial intrusion to first detection alert.
- **Mean Time to Triage (MTTT)**: Time from detection alert to completed forensic triage acquisition.
- **Mean Time to Contain (MTTC)**: Time from triage to complete network isolation.
- **Total Dwell Time**: Total elapsed time adversary had unauthorized access.
- **Estimated Financial & Resource Impact**: Cost of downtime, staff hours, and legal/regulatory remediation.

### 4.3 Evidence Retention Policy (NIST § 3.4.3)
- Retain all GPG-signed Evidence Vault artifacts (`net/host/data.ext`) in write-once immutable storage for a minimum of **3 years** (or per organization regulatory requirements) for legal prosecution and audit defense.

---

## 📄 NIST-Compliant Incident Post-Mortem Report Template

```markdown
# 🛡️ Security Incident Post-Mortem & Forensic Audit Report
**Report Standard**: NIST SP 800-61 Rev. 2 Compliant

## 1. Incident Overview & Severity Classification
- **Incident ID**: INC-YYYYMMDD-01
- **NIST Attack Vector**: [Web Application | Impersonation | Attrition | Compromised Credential]
- **NIST Severity**:
  - **Functional Impact**: [High | Medium | Low | None]
  - **Information Impact**: [Proprietary | Privacy Breach | Integrity Loss | None]
  - **Recoverability Effort**: [Regular | Supplemented | Extended | Not Recoverable]
- **Date / Time of Initial Compromise**: YYYY-MM-DD HH:MM:SS UTC
- **Date / Time of Detection**: YYYY-MM-DD HH:MM:SS UTC
- **Date / Time of Complete Containment**: YYYY-MM-DD HH:MM:SS UTC
- **Incident Lead & Responder GPG Key ID**: [Name / GPG Fingerprint]

## 2. Executive Summary
High-level non-technical summary detailing the business impact, affected customer/corporate assets, duration of adversary dwell time, and current containment status.

## 3. Scope of Affected Infrastructure
- **Compromised Subnets**: [e.g. 10.0.1.0/24]
- **Affected Host IPs / Hostnames**: [e.g. 10.0.1.15 (siem.vigilante.local)]
- **Kubernetes Namespaces / Pods**: [e.g. tenant-alpha / opensearch-0]

## 4. Root-Cause Analysis (Initial Access Vector)
- **Primary Attack Technique (MITRE ATT&CK)**: [e.g. T1190 - Exploit Public-Facing Application]
- **Vulnerability / Exploited Flaw**: [e.g. CVE-2021-44228 Log4j RCE on port 8080]
- **Adversary Activity & Lateral Movement**: [Detailed breakdown of commands, backdoors, or scanning tools executed]
- **Authoritative Forensic Evidence**:
  - Path: `evidence/10.0.1.0_24/10.0.1.15/triage_summary.json`
  - GPG Signature: `triage_summary.json.asc` (🔏 Cryptographically Verified)

## 5. Authoritative Incident Timeline (UTC)
| Timestamp (UTC) | Phase | Event Description |
| :--- | :--- | :--- |
| `YYYY-MM-DD 10:14:00` | Intrusion | Initial malicious HTTP POST payload received targeting `/api/v1/auth`. |
| `YYYY-MM-DD 10:15:30` | Detection | Ingress alert triggered in SIEM; network reconnaissance sweep initiated. |
| `YYYY-MM-DD 10:22:00` | Analysis | Volatile forensic triage bundle captured and signed with GPG non-repudiation. |
| `YYYY-MM-DD 10:35:00` | Containment | Subnet segmented; default-deny Kubernetes NetworkPolicy applied. |
| `YYYY-MM-DD 11:10:00` | Eradication | Vulnerable service patched; credentials rotated; clean pods deployed. |
| `YYYY-MM-DD 12:00:00` | Recovery | System returned to production with continuous health monitoring. |

## 6. Corrective Actions & Hardening Roadmap
- [ ] Action 1: Deploy automated NetworkPolicy ingress filters across all Kubernetes namespaces.
- [ ] Action 2: Enable automated GPG signature verification for all CI/CD deployment artifacts.
- [ ] Action 3: Conduct scheduled threat simulation exercises (`vigilante threat-sim --all`).
```

---

## 🚀 Quick Reference Commands Cheat Sheet

| Incident Response Task | Vigilante Command / Hotkey |
| :--- | :--- |
| **Launch Central Operations Hub** | `vigilante menu` *(or press `[Tab]`)* |
| **Execute Subnet Reconnaissance** | `vigilante scan` |
| **Inspect Topology & Port Matrix** | `vigilante xml` |
| **Acquire Full IR Triage Bundle** | Highlight host in `vigilante xml` ➔ Press **`[t]`** |
| **Launch AI Security Analyst** | `vigilante ai` *(or `vigilante ask`)* |
| **Switch AI Provider (Ollama/Claude/GPT)** | Press **`[p]`** inside `vigilante ai` |
| **Run Threat Simulation Playbook** | `vigilante threat-sim -s <scenario-id>` |
| **Audit Live Kubernetes Pods** | `vigilante pods` *(Press `[d]` describe, `[l]` logs)* |
| **Check Infrastructure & TLS Health** | `vigilante status` |
| **Export GPG-Signed Post-Mortem** | Press **`[x]`** inside `vigilante ai` |
| **Launch Stdio MCP Server for LLMs**| `vigilante mcp` |

---

*Authored for security operators, CSIRTs, and incident leads. Adhere to NIST SP 800-61 Rev. 2, preserve volatile memory, and sign all evidence.*
