# 🤖 Vigilante Model Context Protocol (MCP) Server Reference

This document is the complete reference for the **Model Context Protocol (MCP)** server built into Vigilante ([`src/mcp/server.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/mcp/server.js)). It enables AI coding assistants and autonomous agents (such as Claude Desktop, Google Antigravity, and Cursor) to interact directly with cluster infrastructure, security scanners, SOAR containment actions, and forensic data lakes.

---

## 1. Quick Setup & Configuration

The MCP server runs over standard I/O (`stdio`) via the command:
```bash
vigilante mcp
```

### Claude Desktop Integration
Add the following to your `claude_desktop_config.json`:
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

### Antigravity & Cursor MCP Configuration
Add to your project's `.mcp.json` or cursor MCP settings:
```json
{
  "mcpServers": {
    "vigilante": {
      "command": "node",
      "args": ["./bin/vigilante.js", "mcp"],
      "env": {
        "XDG_CONFIG_HOME": "/home/user/.config"
      }
    }
  }
}
```

---

## 2. Complete Tool Catalog (78 Tools)

### Host & Reconnaissance Tools
1. `list_hosts`: Returns all discovered network hosts, open ports, OS guesses, and service banners.
2. `query_topology`: Retrieves the full node-edge network topology graph.
3. `list_evidence`: Enumerates forensic evidence files and GPG signatures in the Evidence Vault.
4. `get_host_dossier`: Returns the unified vulnerability and risk dossier for a specific host IP.
5. `run_nmap_scan`: Triggers a live Nmap network discovery or service scan.
6. `compare_scans`: Performs differential analysis between two historical scans to identify port changes.
7. `export_topology_svg`: Generates a standalone SVG network topology visualization.
8. `export_topology_html`: Generates an interactive HTML NastyMap report.

### Live Diagnostic Probes
9. `run_diagnostic`: Executes targeted diagnostic probes (`ping`, `mtr`, `dns`, `tls`, `http`, `arp`, `bench`, `triage`).

### Cluster & Workload Operations
10. `get_cluster_status`: Returns k3d cluster node readiness and deployed module states.
11. `list_pods`: Queries real-time Kubernetes pods across all namespaces (`-A -o wide`).
12. `get_pod_logs`: Streams standard output and error logs from a target pod.
13. `describe_pod`: Returns detailed Kubernetes pod specification, events, and conditions.
14. `list_instances`: Enumerates local k3d cluster instances and their metadata.
15. `create_cluster`: Programmatically provisions a new k3d cluster with Ingress port bindings.
16. `delete_cluster`: Tears down a specified k3d cluster.

### Security Module & Config Management
17. `list_modules`: Lists all 12 security modules and their active deployment states.
18. `install_module`: Deploys a security module with optional custom values overrides.
19. `uninstall_module`: Removes a deployed security module from the cluster.
20. `get_module_values`: Retrieves the active Helm values YAML configuration for a module.
21. `update_config`: Updates settings in `$XDG_CONFIG_HOME/vigilante/config.yaml`.
22. `verify_signature`: Cryptographically validates GPG detached signatures on evidence files.

### Threat Simulation & Adversary Testing
23. `list_threat_playbooks`: Enumerates available attack simulation scenarios.
24. `execute_threat_playbook`: Launches a network threat simulation job against the SIEM.

### Vulnerability & Compliance Scanners
25. `run_nuclei_scan`: Executes ProjectDiscovery Nuclei vulnerability templates.
26. `run_trivy_scan`: Scans container images or local directories for CVEs.
27. `run_kubeaudit_scan`: Evaluates cluster workloads against Kubernetes security best practices.
28. `run_netexec_scan`: Automates network protocol authentication checks (SMB, SSH, WinRM).
29. `run_zap_scan`: Executes OWASP ZAP spidering and active application security tests.
30. `run_openvas_scan`: Triggers Greenbone OpenVAS vulnerability assessment tasks.
31. `generate_traffic`: Injects synthetic network traffic to validate detection rules.

### SOAR & Active Containment Engine
32. `isolate_pod`: Immediately quarantines a pod using zero-trust NetworkPolicies.
33. `freeze_pod`: Suspends pod execution processes via cgroup freezer (`SIGSTOP`).
34. `block_ip`: Injects network drop rules blocking communication with a malicious IP.
35. `quarantine_account`: Invalidates a compromised ServiceAccount and revokes RBAC permissions.
36. `list_containments`: Lists all active containment and quarantine policies.
37. `release_containment`: Removes containment restrictions from a remediated workload.

### Autonomous SOC & Threat Intelligence
38. `run_agent_soc_investigation`: Initiates an autonomous ReAct investigation loop for an alert.
39. `sync_threat_intel`: Synchronizes Feodo Tracker, URLhaus, and Emerging Threats rules.
40. `generate_mitre_report`: Compiles an executive MITRE ATT&CK coverage and gap analysis.

### Kubernetes Posture & Shift-Left CI/CD Audit
41. `audit_kspm_posture`: Evaluates cluster workloads against Pod Security Standards.
42. `run_pipeline_audit`: Scans Kubernetes manifests and Dockerfiles, producing SARIF v2.1.0 output.

### Google kCTF Cyber Range
43. `list_kctf_challenges`: Enumerates deployed kCTF challenges and templates.
44. `deploy_kctf_challenge`: Provisions a sandboxed CTF challenge instance.
45. `delete_kctf_challenge`: Cleans up a deployed CTF challenge instance.

### Out-of-Band (BMC/IPMI) Management
46. `run_oob_scan`: Probes subnets for exposed IPMI, BMC, and Redfish interfaces.
47. `dump_rakp2_hashes`: Dumps IPMI 2.0 RAKP-2 authentication hashes for Hashcat.

### Next-Gen Autonomous Capabilities
48. `list_canary_tokens`: Enumerates active honeypots, decoy ServiceAccounts, and tripped status.
49. `deploy_canary_asset`: Deploys decoy ServiceAccounts, Secrets, or network honeypots.
50. `run_purple_simulation`: Runs autonomous Red vs. Blue wargame simulations with scorecards.
51. `auto_remediate_finding`: Generates unified diff patches for manifests and Dockerfiles.
52. `query_security_datalake`: Runs SQL analytical queries across normalized security telemetry.
53. `audit_cloud_security`: Audits AWS IRSA, GCP Workload Identity, and cloud storage exposure.
54. `list_carved_files`: Lists forensically carved files and packet payload artifacts.

### Next-Gen Cyber Defense & Autonomous Operations Tools
55. `transpile_sigma_to_sql`: Transpiles SIGMA YAML/JSON detection rule to ANSI SQL for SQLite/DuckDB.
56. `run_sigma_threat_hunt`: Executes automated SIGMA rule threat hunt across Data Lake telemetry.
57. `run_dynamic_adversary_simulation`: Dynamic BloodHound attack-path graph traversal and resilience score calculation.
58. `inspect_process_memory`: Performs in-memory triage of `/proc/$PID/maps` for RWX, unlinked binaries, and fileless execution.
59. `generate_cloud_honeytoken`: Generates realistic decoy cloud credentials (AWS STS, GitHub PAT, Slack webhook, Kubeconfig).
60. `start_canary_webhook_listener`: Starts in-process HTTP webhook honeytoken trap server.
61. `generate_container_sbom`: Generates standard CycloneDX v1.5 or SPDX v2.3 SBOM for container images.
62. `verify_cosign_signature`: Cryptographically verifies Cosign/Sigstore digital signatures and Rekor transparency receipts.
63. `get_socket_connection_matrix`: Builds real-time socket connection matrix and detects lateral egress anomalies.
64. `render_mitre_heatmap`: Renders ANSI/Braille MITRE ATT&CK coverage heatmap grid.
65. `broadcast_mesh_threat`: Cryptographically signs and broadcasts threat indicator across multi-cluster federation mesh.
66. `get_mesh_peers_status`: Inspects multi-cluster federation peer mesh status and local Ed25519 node identity.

### Autonomous Defense, Cryptographic Ledger & Attack Graph Tools
67. `synthesize_bpf_lsm_policy`: Synthesizes Linux Security Module (eBPF LSM) declarative security rules into C kernel hooks or YAML policies.
68. `evaluate_bpf_lsm_event`: Simulates high-speed evaluation of process execution or file open event against synthesized LSM policies.
69. `detect_c2_beaconing`: Statistical C2 beaconing and discrete Fourier transform (DFT) periodicity detector for network connection intervals.
70. `detect_dns_tunneling`: Detects covert data exfiltration and DNS tunneling using Shannon entropy analysis on query domains.
71. `scan_file_entropy`: Calculates 8-bit Shannon entropy across file bytes to detect ransomware encryption spikes or encrypted payloads.
72. `deploy_ransomware_canaries`: Deploys honeypot canary decoy files with known entropy baseline to detect ransomware encryption attempts.
73. `convene_agent_warroom`: Convenes an autonomous multi-agent incident war room (Forensics, Threat Intel, SRE Blast Radius, Incident Commander) to debate consensus containment verdict.
74. `search_semantic_cti`: Performs air-gapped semantic vector search across MITRE ATT&CK techniques and Sigma rules.
75. `append_audit_ledger`: Appends an immutable, SHA-256 hash-chained entry to the cryptographic evidence ledger.
76. `verify_ledger_integrity`: Traverses the cryptographic Merkle ledger to verify hash chaining, signatures, and tamper-free audit integrity.
77. `calculate_attack_blast_radius`: Calculates downstream blast radius impact and discovers shortest pivot paths to high-value Crown Jewels from a compromised asset.
78. `render_terminal_attack_graph`: Renders ANSI/ASCII terminal composite attack graph with colored node tiers and highlighted shortest attack paths.


---

## 3. Static Resources Catalog (16 Resources)

| Resource URI | Description | MIME Type |
| :--- | :--- | :--- |
| `vigilante://hosts` | Discovered network host profiles and fingerprints | `application/json` |
| `vigilante://topology` | Network topology graph data | `application/json` |
| `vigilante://evidence` | Incident Response Evidence Vault hierarchy | `application/json` |
| `vigilante://pods` | Real-time Kubernetes pods (`-A -o wide`) | `application/json` |
| `vigilante://clusters` | Local k3d cluster instance configurations | `application/json` |
| `vigilante://modules` | Security module states and ingress URLs | `application/json` |
| `vigilante://scans` | Saved Nmap XML and text reports | `application/json` |
| `vigilante://config` | Vigilante global configuration file | `application/json` |
| `vigilante://threats` | Built-in threat simulation playbooks | `application/json` |
| `vigilante://nasty/svg` | Standalone NastyMap SVG attack graph | `image/svg+xml` |
| `vigilante://nasty/html` | Standalone NastyMap interactive HTML report | `text/html` |
| `vigilante://kctf/challenges` | Active kCTF challenge instances and archetypes | `application/json` |
| `vigilante://oob/scans` | Saved out-of-band management scan reports | `application/json` |
| `vigilante://oob/hashes` | IPMI 2.0 RAKP-2 hashes formatted for Hashcat | `text/plain` |
| `vigilante://kspm/latest` | Most recent Kubernetes posture evaluation report | `text/markdown` |
| `vigilante://soc/incidents` | Catalog of investigated incidents and post-mortems | `application/json` |

---

## 4. Parameterized Resource Templates (5 Templates)

1. `vigilante://hosts/{hostIp}`: Detailed vulnerability and service report for a specific host.
2. `vigilante://evidence/{network}/{hostIp}`: Forensic evidence triage bundle for a target host.
3. `vigilante://evidence/{network}/{hostIp}/{filename}`: Raw content of a specific forensic artifact.
4. `vigilante://scans/{filename}`: Raw text or XML of a specific saved Nmap scan.
5. `vigilante://oob/scan/{filename}`: Detailed inventory and events for a specific OOB scan report.
