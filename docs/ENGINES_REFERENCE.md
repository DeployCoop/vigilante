# ⚙️ Vigilante Engines Technical Reference

This document provides a technical specification for all 24 security, detection, orchestration, and forensic engines located in [`src/engine/`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/).

---

## 1. SOAR & Active Containment Engine (`soar.js`)
- **File**: [`src/engine/soar.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/soar.js)
- **Role**: Provides programmatic, sub-second active containment actions to halt ongoing cyber attacks without taking down entire clusters.
- **Key Functions**:
  - `isolatePod(podName, namespace)`: Injects an emergency zero-trust `NetworkPolicy` dropping all ingress and egress traffic while preserving the pod container for memory forensics.
  - `freezePod(podName, namespace)`: Dispatches a cgroup freezer signal (`SIGSTOP`) halting all CPU cycles for the target pod processes.
  - `blockIp(ipAddress)`: Injects a cluster-wide iptables/ingress drop rule against malicious external IPs.
  - `quarantineAccount(serviceAccountName, namespace)`: Strips all Kubernetes RBAC ClusterRoleBindings and invalidates active ServiceAccount tokens.
  - `listActiveContainments()`: Enumerates currently active quarantine and isolation measures.
  - `releaseContainment(containmentId)`: Safely removes containment policies and restores normal workload operations.

---

## 2. Autonomous Agentic SOC Engine (`agent-soc.js`)
- **File**: [`src/engine/agent-soc.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/agent-soc.js)
- **Role**: Implements an autonomous ReAct (Reasoning + Acting) investigation loop mimicking a Tier-3 SOC analyst.
- **Workflow**:
  1. Ingests raw alerts from Falco, Suricata, or Honeynets.
  2. Inspects pod logs, active network connections, and process ancestries.
  3. Formulates hypotheses, executes diagnostic probes, and determines incident criticality (CAT-1 through CAT-6 per NIST SP 800-61).
  4. Triggers automatic SOAR containment for critical threats.
  5. Generates comprehensive post-mortem Markdown incident manifests signed via GPG.

---

## 3. Autonomous Deception Mesh ("Canary Kube") (`deception.js`)
- **File**: [`src/engine/deception.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/deception.js)
- **Role**: Manages active deception tokens, decoy ServiceAccounts, and network honeypots.
- **Key Functions**:
  - `generateCanaryServiceAccount(name, namespace)`: Creates a decoy ServiceAccount with enticing names (`cluster-admin-backup`, `vault-sync-sa`) and audit triggers.
  - `generateCanarySecret(name, namespace, tokenType)`: Generates decoy Kubernetes Secrets containing realistic AWS keys, DB passwords, or JWT tokens with tracking payloads.
  - `generateDecoyDeploymentYaml(serviceType)`: Manifest generator for lightweight decoy services (SMB, SSH, Redis, MSSQL).
  - `detectCanaryTripped(auditLogs)`: High-fidelity event sensor detecting unauthorized access to canary assets.
  - `triggerCanaryAlarm(event)`: Emits high-priority alert and invokes `soar.isolatePod` on the intruder.

---

## 4. Autonomous Purple Team Arena (`purpleteam.js`)
- **File**: [`src/engine/purpleteam.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/purpleteam.js)
- **Role**: Multi-agent adversarial simulation platform executing Red Team attack campaigns against Blue Team detection stacks.
- **Phases Simulated**:
  - Phase 1: Reconnaissance & Discovery (`T1046`, `T1082`)
  - Phase 2: Credential Access (`T1552`, `T1558`)
  - Phase 3: Lateral Movement (`T1021.002`)
  - Phase 4: Data Exfiltration (`T1048`)
- **Metrics**: Calculates Mean Time to Detect (MTTD), Mean Time to Remediate (MTTR), and assigns defensive scorecards (A+ through F).

---

## 5. Self-Healing Auto-Remediator Engine (`remediation.js`)
- **File**: [`src/engine/remediation.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/remediation.js)
- **Role**: Automatically remediates audit and Pod Security Standard (PSS) violations.
- **Key Functions**:
  - `generatePatchForFinding(finding, fileContent, fileType)`: Analyzes YAML manifests or Dockerfiles and generates hardened drop-in replacements.
  - `generateUnifiedDiff(originalContent, patchedContent, fileName)`: Produces standard unified diffs for terminal preview or code reviews.
  - `applyPatchToFile(filePath, patchedContent)`: Atomically updates files on disk, creating timestamped backups (`.vigil-bak-*`).
  - `generateRemediationPrScript(patches)`: Produces automated Git branch, commit, and Pull Request creation shell scripts.

---

## 6. Deep PCAP Forensic Extraction Engine (`forensics.js`)
- **File**: [`src/engine/forensics.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/forensics.js)
- **Role**: Reconstructs network protocol sessions and extracts payload artifacts from raw packet captures.
- **Key Functions**:
  - `carveFilesFromPayload(rawBuffer)`: Reconstructs HTTP and SMB payload files, saving them to `$XDG_CONFIG_HOME/vigilante/carved/` with SHA256/MD5 hashes.
  - `ingestTlsSessionKeys(keylogContent)`: Parses NSS `SSLKEYLOGFILE` dumps for decrypting TLS 1.2/1.3 streams.
  - `reconstructTcpStreams(packets)`: Reconstructs bi-directional TCP streams into ordered conversation sessions.
  - `generateFlowLadder(stream)`: Renders terminal ASCII flow ladder sequence diagrams showing packet flow, TCP flags, and payload transfers.

---

## 7. Kernel-Native eBPF Process Lineage Tree (`lineage.js`)
- **File**: [`src/engine/lineage.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/lineage.js)
- **Role**: Parses system process execution events into hierarchical ancestry trees and identifies suspicious behavior.
- **Key Functions**:
  - `buildProcessLineageTree(processEvents)`: Assembles parent-child process execution trees.
  - `detectAnomalousProcessLineage(node)`: Flags container escapes (`T1611`), web server reverse shells (`T1059.004`), and Living-off-the-Land Binaries (LOLBins).
  - `renderAsciiProcessTree(rootNode)`: Generates interactive ASCII process hierarchy trees for the terminal UI.

---

## 8. Multi-Cloud Workload Identity & CSPM Engine (`cloudsec.js`)
- **File**: [`src/engine/cloudsec.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/cloudsec.js)
- **Role**: Audits cloud provider integrations and storage security across Kubernetes clusters.
- **Key Functions**:
  - `auditWorkloadIdentity(workloads)`: Audits AWS IRSA (`eks.amazonaws.com/role-arn`), GCP Workload Identity (`iam.gke.io/gcp-service-account`), and Azure Client IDs, detecting over-privileged roles (`AdministratorAccess`, `Owner`).
  - `auditCloudStorageExposure(storageConfigs)`: Identifies publicly accessible buckets, missing server-side encryption, and disabled versioning.
  - `calculateCloudRiskScore(findings)`: Computes a composite 0–100 risk score and executive Markdown report.

---

## 9. Embedded Security Data Lake Engine (`datalake.js`)
- **File**: [`src/engine/datalake.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/datalake.js)
- **Role**: In-process, high-throughput SQL analytics over security telemetry.
- **Architecture**:
  - **Free First**: Built-in Node.js v26 `node:sqlite` (`DatabaseSync`) for instant, zero-dependency analytics.
  - **Official DuckDB Support**: Dynamically detects and links official `duckdb` or `@duckdb/node-api` when installed or requested via `backend: 'duckdb'`.
  - `getDataLakeBackend()`: Returns active engine (`sqlite` vs `duckdb`).
  - `ingestSecurityEvents(eventType, events)`: Ingests Falco, Zeek, Suricata, Audit, and Canary events.
  - `queryDataLake(sql, params)`: Executes analytical queries with SQL aggregations.
  - `runRetrospectiveThreatHunt(indicators)`: Scans historical event logs against newly ingested CTI IOCs.

---

## 10. WebAssembly (Wasm) Plugin Engine (`wasm.js`)
- **File**: [`src/engine/wasm.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/wasm.js)
- **Role**: Sandboxed runtime executing detection and containment logic compiled from Rust, Go, or AssemblyScript.
- **Key Functions**:
  - `loadWasmPlugin(wasmBytes, imports)`: Instantiates sandboxed WebAssembly modules with memory constraints.
  - `executeWasmDetector(instance, telemetryRecord)`: Dispatches security metrics into the Wasm module and extracts structured anomaly scores.
  - `installWasmPlugin(pluginName, wasmBytes)`: Registers Wasm plugins in `$XDG_CONFIG_HOME/vigilante/wasm/`.

---

## 11. Cyber Threat Intelligence (CTI) Engine (`cti.js`)
- **File**: [`src/engine/cti.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/cti.js)
- **Role**: Threat feed synchronization and detection rule compiler.
- **Features**:
  - Synchronizes active C2 servers from **Feodo Tracker** (abuse.ch).
  - Synchronizes malicious malware download URLs from **URLhaus**.
  - Downloads and compiles over 50,000 active IDS/IPS signatures from **Emerging Threats (ET Open)** into Suricata format.

---

## 12. Continuous Kubernetes Security Posture Management (`kspm.js`)
- **File**: [`src/engine/kspm.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/kspm.js)
- **Role**: Continuous in-cluster security posture management.
- **Features**:
  - Evaluates workloads against Kubernetes Pod Security Standards (PSS: Privileged, Baseline, Restricted).
  - Flags dangerous capabilities (`SYS_ADMIN`), host path mounts, missing read-only root filesystems, and missing resource limits.
  - Produces letter-graded security scorecards (A+ through F).

---

## 13. Shift-Left CI/CD Audit Engine (`audit.js`)
- **File**: [`src/engine/audit.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/audit.js)
- **Role**: Pre-deployment static analysis of Kubernetes manifests and Dockerfiles.
- **Features**:
  - Emits industry-standard **SARIF v2.1.0** reports for integration with GitHub Code Scanning and GitLab SAST.
  - Configurable PR gate thresholds blocking merges on CRITICAL or HIGH security findings.

---

## 14. Out-of-Band Management (OOB) Engine (`oobscan.js`)
- **File**: [`src/engine/oobscan.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/oobscan.js)
- **Role**: Hardware BMC, IPMI 1.5/2.0, and Redfish management controller reconnaissance.
- **Features**:
  - Probes UDP port `623` for IPMI service discovery.
  - Tests for default BMC vendor credentials (Dell iDRAC, HP iLO, Supermicro IPMI).
  - Dumps RAKP-2 cryptographic authentication hashes formatted for Hashcat (`-m 7300`).

---

## 15. Unified Host Security Dossier Engine (`dossier.js`)
- **File**: [`src/engine/dossier.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/dossier.js)
- **Role**: Aggregates findings from all scanners into unified, per-host risk dossiers.
- **Features**:
  - Correlates Nmap open ports, Nuclei CVEs, Trivy container findings, and OpenVAS results.
  - Calculates a composite 0–100 CVSS risk score per host.

---

## 16. MITRE ATT&CK® Matrix Engine (`mitre.js`)
- **File**: [`src/engine/mitre.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/mitre.js)
- **Role**: Maps alerts, detections, and playbooks to the official MITRE ATT&CK enterprise matrix.
- **Features**:
  - Tracks coverage across all 14 tactics (Initial Access through Impact).
  - Highlights defensive coverage gaps and untested adversary techniques.

---

## 17. Specialized Scanners & Utility Engines
- **`recon.js`**: Subnet discovery, CIDR math, passive listening, and port sweeping.
- **`nuclei.js`**: ProjectDiscovery template execution and CVE matching.
- **`trivy.js`**: Vulnerability scanning for container images and filesystems.
- **`kubeaudit.js`**: Pod Security Policy compliance testing.
- **`netexec.js`**: Network protocol automation and credential spraying.
- **`zap.js`**: OWASP ZAP spidering and active application testing.
- **`traffic.js`**: Synthetic traffic injection for SIEM rule validation.
- **`gpg.js` & `evidence.js`**: Cryptographic evidence signing (`.asc`) and vault management.

---

## 18. SIGMA-to-SQL Detection Transpiler & Threat Hunter (`sigma.js`)
- **File**: [`src/engine/sigma.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/sigma.js)
- **Role**: Parses open SIGMA detection rules (YAML/JSON) and transpiles them into ANSI SQL queries optimized for embedded SQLite and DuckDB.
- **Features**:
  - `parseSigmaRule(input)`: Parses rule metadata, MITRE tags, logsource, and detection logic.
  - `transpileSigmaToSql(rule, options)`: Maps SIGMA fields to telemetry schemas, converts wildcard operators (`*pattern*` to `LIKE`), handles boolean aggregations (`1 of selection*`).
  - `runSigmaThreatHunt(rules)`: Executes automated batch threat hunts across historical Data Lake telemetry.
  - `generateHypothesisForTechnique(techniqueId)`: Generates automated hypothesis and candidate detection rules for any MITRE technique.

---

## 19. Autonomous Dynamic Red Team Agent (`adversary.js`)
- **File**: [`src/engine/adversary.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/adversary.js)
- **Role**: Parses BloodHound CE graph topologies and emulates dynamic, multi-step identity attack chains.
- **Features**:
  - `buildAttackGraphFromBloodhound(data, targetHvt)`: Discovers shortest privilege escalation paths using Breadth-First Search (BFS).
  - `simulateDynamicAttackChain(attackPath, options)`: Simulates step-by-step adversary progression with probabilities and detection checks.
  - `calculateAdversaryResilienceScore(simulation)`: Computes organizational defense resilience score (0-100) and breach metrics.
  - `generateAdversaryReport(simulation, scorecard)`: Produces executive post-simulation Markdown reports.

---

## 20. In-Memory & Process Forensics Engine (`memdump.js`)
- **File**: [`src/engine/memdump.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/memdump.js)
- **Role**: Live Linux memory triage of `/proc/$PID/maps` and ELF inspection.
- **Features**:
  - `parseProcMaps(mapsContent)`: Structured segment parser (addresses, perms, offsets, device, inode, pathname).
  - `detectMemoryAnomalies(segments)`: Flags RWX permissions (shellcode injection), unlinked deleted executables, fileless `memfd_create` executions, and `/tmp` shared library loading.
  - `extractProcessStrings(buffer, minLength)`: Extracts ASCII strings and calculates Shannon entropy for identifying encrypted/packed payloads.
  - `saveMemoryArtifact(podName, pid, metadata, buffer)`: Persists forensic memory artifacts in the Evidence Vault.

---

## 21. Cloud Honeytoken & Webhook Trap Mesh (`deception.js`)
- **File**: [`src/engine/deception.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/deception.js)
- **Role**: Generates enticing decoy cloud credentials and runs in-process webhook canary servers.
- **Features**:
  - `generateCloudHoneytoken(provider, options)`: Generates realistic AWS STS access keys, GitHub PATs, Slack incoming webhooks, and Kubeconfig files.
  - `plantDecoyBreadcrumbs(honeytoken, targetType)`: Injects honeytoken breadcrumbs into Kubernetes ConfigMaps, environment variables, or markdown docs.
  - `startCanaryWebhookListener(options)`: Lightweight HTTP server catching inbound adversary token detonations with automated SOAR containment triggers.

---

## 22. Supply Chain Security, SBOM & Container Attestation (`supplychain.js`)
- **File**: [`src/engine/supplychain.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/supplychain.js)
- **Role**: Software Bill of Materials generation and digital container image verification.
- **Features**:
  - `generateCycloneDxSbom(manifests, metadata)`: Generates standard CycloneDX v1.5 JSON SBOMs.
  - `generateSpdxSbom(manifests, metadata)`: Generates SPDX v2.3 JSON SBOM documents.
  - `verifyCosignSignature(imageDigest, signaturePayload, publicKeyPem)`: Verifies Ed25519/ECDSA digital signatures and Rekor transparency log receipts.
  - `evaluateSupplyChainPolicy(sbom, policyRules)`: Audits packages against banned licenses and known critical vulnerabilities.

---

## 23. eBPF Real-Time Syscall Observability & Socket Matrix (`observability.js`)
- **File**: [`src/engine/observability.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/observability.js)
- **Role**: High-speed in-memory circular ring buffer and socket connection matrix analyzer.
- **Features**:
  - `ObservabilityRingBuffer`: Circular ring buffer storing high-frequency syscall events (`execve`, `connect`, `openat`, `setuid`) with FIFO eviction.
  - `buildSocketConnectionMatrix(networkEvents)`: Real-time matrix of pod-to-pod and egress socket connections with byte counters.
  - `detectAnomalousSocketConnections(matrix, baseline)`: Detects C2 reverse shell ports, unauthorized external egress, and high-volume data exfiltration.
  - `streamLiveEvents(options, onEvent)`: Event stream dispatcher with mock/probe harness.

---

## 24. Terminal Braille Heatmaps & ANSI Canvas Visualizations (`src/ui/canvas.js`)
- **File**: [`src/ui/canvas.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/ui/canvas.js)
- **Role**: High-resolution terminal graphics using Unicode Braille and ANSI half-blocks.
- **Features**:
  - `renderBrailleSparkline(dataPoints, width, height)`: 2x4 sub-pixel trendlines using Unicode Braille (`\u2800`–`\u28FF`).
  - `renderHalfBlockHeatmap(gridData, options)`: 2-vertical-pixel ANSI half-block heatmaps (`▀`, `▄`).
  - `renderMitreHeatmapGrid(coverageMap, tacticsList)`: Color-coded MITRE ATT&CK coverage grid with detection gap analysis.

---

## 25. Multi-Cluster Defense Federation & Threat Sharing (`federation.js`)
- **File**: [`src/engine/federation.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/federation.js)
- **Role**: Peer-to-peer threat sharing and automated defense synchronization across multi-cloud clusters.
- **Features**:
  - `createFederationNode(nodeConfig)`: Generates cryptographic Ed25519 identity and manages peer cluster lists.
  - `signThreatRecord(threatData, privateKeyPem, signerInfo)`: Creates tamper-proof digital signatures for threat indicators.
  - `verifyThreatRecord(signedRecord, publicKeyPem)`: Validates authenticity and integrity of peer threat records.
  - `broadcastThreatIndicator(signedRecord, peersList)`: Dispatches threat indicators across mesh nodes.
  - `ingestFederatedThreatRecord(signedRecord, options)`: Ingests inbound threat indicators, triggers local SOAR IP containment, and runs retrospective Data Lake hunts.

---

## 26. Kernel-Level eBPF LSM Policy Synthesizer (`lsm.js`)
- **File**: [`src/engine/lsm.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/lsm.js)
- **Role**: Compiles declarative security rules into Linux Security Module (BPF-LSM) in-kernel hooks.
- **Features**:
  - `generateBpfLsmPolicy(rulesYamlOrObj, options)`: Compiles YAML rules into hooks (`bprm_check_security`, `file_open`, `socket_connect`).
  - `compileLsmRuleToFilter(rule)`: Translates declarative conditions into C BPF helper expressions.
  - `simulateLsmPolicyEvaluation(policy, event)`: High-speed evaluation simulator testing whether events are allowed or rejected (`-EPERM`).
  - `exportLsmCSource(policy)`: Generates ready-to-compile BPF-LSM C source code skeletons.

---

## 27. Statistical C2 Beaconing & FFT Frequency Detector (`beaconing.js`)
- **File**: [`src/engine/beaconing.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/beaconing.js)
- **Role**: Detects periodic command-and-control heartbeats and DNS tunneling exfiltration.
- **Features**:
  - `calculateInterArrivalTime(flowEvents)`: Computes timestamp deltas ($\Delta t$), mean, variance, and standard deviation.
  - `detectBeaconingPeriodicity(intervals, options)`: Uses Discrete Fourier Transform (DFT) and autocorrelation to determine dominant interval, jitter %, and confidence score.
  - `calculateShannonEntropy(str)`: Mathematical 8-bit Shannon entropy calculation.
  - `detectDnsTunneling(dnsQueries, options)`: Flags high-entropy subdomain labels and anomalous length typical of DNS exfiltration.

---

## 28. Anti-Ransomware Canary Traps & Rapid File Entropy Monitor (`ransomware.js`)
- **File**: [`src/engine/ransomware.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/ransomware.js)
- **Role**: Detects ransomware file encryption spikes and deploys decoy canary files.
- **Features**:
  - `generateRansomwareCanaryFiles(targetDirectory, options)`: Plants realistic decoy files with baseline entropy.
  - `calculateFileEntropy(bufferOrPath)`: Calculates 8-bit Shannon block entropy across file bytes.
  - `detectRansomwareEncryption(beforeBuffer, afterBuffer, options)`: Detects sudden entropy jumps ($\Delta H > 2.0$, $H > 7.5$) distinguishing encryption from plain text.
  - `triggerRansomwareContainment(podName, namespace, pid, options)`: Halts processes via `soar.freezePod` (SIGSTOP) and applies `soar.isolatePod` (NetworkPolicy).

---

## 29. Autonomous Multi-Agent Incident War Room & Consensus Debate (`warroom.js`)
- **File**: [`src/engine/warroom.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/warroom.js)
- **Role**: 4-persona autonomous consortium deliberating incident severity and reaching quorum.
- **Features**:
  - `conveneIncidentWarRoom(incidentData, options)`: Orchestrates Forensics, Threat Intel, SRE Blast Radius, and Incident Commander personas.
  - `conductAgentDebateRound(opinions, proposedAction)`: Executes structured debate rounds with confidence adjustments and rebuttals.
  - `calculateConsensusScore(opinions, quorumThreshold)`: Calculates consensus score and quorum approval ($\ge 75\%$).
  - `generateWarRoomTranscript(session)`: Formats full debate and decision log as Markdown for the Evidence Vault.

---

## 30. Local Offline Semantic CTI & Vector Threat Search (`vectorcti.js`)
- **File**: [`src/engine/vectorcti.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/vectorcti.js)
- **Role**: Air-gapped semantic vector search matching natural language analyst queries against MITRE ATT&CK and Sigma rules.
- **Features**:
  - `generateLocalEmbedding(text)`: Pure zero-dependency 128-dimensional dense float vector generator.
  - `cosineSimilarity(vecA, vecB)`: Computes mathematical cosine similarity between feature vectors.
  - `initSemanticThreatCatalog()`: Indexes enterprise MITRE techniques, tactics, and Sigma detections.
  - `semanticThreatSearch(queryText, options)`: Ranked semantic search returning top matching threat techniques.

---

## 31. Cryptographic Merkle Ledger & Legal Chain-of-Custody (`ledger.js`)
- **File**: [`src/engine/ledger.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/ledger.js)
- **Role**: Immutable append-only audit trail with SHA-256 hash chaining, Merkle roots, and legal chain-of-custody.
- **Features**:
  - `initAuditLedger(ledgerDir, options)`: Initializes append-only hash-chained cryptographic ledger.
  - `appendLedgerEntry(entryType, payload, signerInfo, options)`: Records immutable entry with digital HMAC signature.
  - `buildMerkleRoot(entries)`: Constructs balanced binary Merkle tree and root hash.
  - `generateInclusionProof(entryIndex, entries)`: Generates cryptographic Merkle audit path.
  - `verifyInclusionProof(entryHash, proof, merkleRoot)`: Verifies entry membership against Merkle root.
  - `verifyLedgerIntegrity(ledgerDir, options)`: Traverses full ledger chain to detect tampering or corruption.
  - `exportLegalChainOfCustody(incidentId, ledgerDir)`: Generates court-admissible legal affidavit.

---

## 32. Interactive Terminal Attack Graph & Blast-Radius Explorer (`attackgraph.js`)
- **File**: [`src/engine/attackgraph.js`](file:///mnt/unreal/git/DeployCoop/vigilante/src/engine/attackgraph.js)
- **Role**: Merges Network, Kubernetes RBAC, and Identity topologies to calculate lateral movement and blast radius.
- **Features**:
  - `buildCompositeAttackGraph(nmapHosts, k8sWorkloads, bloodhoundPaths, options)`: Constructs unified multi-tier attack graph.
  - `findShortestAttackPath(fromId, toId, graph)`: BFS shortest path discovery between assets.
  - `calculateBlastRadius(startNodeId, graph, options)`: Calculates downstream impact score and critical paths to Crown Jewels.
  - `renderAsciiAttackGraph(graph, options)`: Renders colorized directional ANSI graph for terminals.


