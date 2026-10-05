export { BaseModule } from './modules/base.js';
export { VigilSOCModule } from './modules/vigil-soc/index.js';
export { VigilLocalModule } from './modules/vigil-local/index.js';
export { KCTFModule } from './modules/kctf/index.js';
export { OpenVASModule } from './modules/openvas/index.js';
export { WazuhModule } from './modules/wazuh/index.js';
export { FlamingoModule } from './modules/flamingo/index.js';
export { FalcoModule } from './modules/falco/index.js';
export { SuricataModule } from './modules/suricata/index.js';
export { ZeekModule } from './modules/zeek/index.js';
export { ZAPModule } from './modules/zap/index.js';
export { BloodHoundModule } from './modules/bloodhound/index.js';
export {
  RECON_PROFILES,
  checkReconToolsInstalled,
  runReconScan,
  listSavedReconScans,
  parseNaabuOutput,
  parseHttpxOutput,
  reconToTopology
} from './engine/recon.js';
export {
  NUCLEI_PROFILES,
  checkNucleiInstalled,
  runNucleiScan,
  parseNucleiOutput,
  listSavedNucleiScans
} from './engine/nuclei.js';
export {
  TRIVY_PROFILES,
  checkTrivyInstalled,
  runTrivyAudit,
  parseTrivyOutput,
  listSavedTrivyScans
} from './engine/trivy.js';
export {
  KUBEAUDIT_PROFILES,
  checkKubeAuditToolsInstalled,
  runKubeAudit,
  parseKubeBenchOutput,
  parseKubeHunterOutput,
  listSavedKubeAudits
} from './engine/kubeaudit.js';
export {
  NETEXEC_PROFILES,
  checkNetexecInstalled,
  runNetexecAudit,
  parseNetexecOutput,
  listSavedNetexecAudits
} from './engine/netexec.js';
export {
  ZAP_PROFILES,
  checkZapAvailable,
  runZapScan,
  listSavedZapScans
} from './engine/zap.js';
export {
  parseSuricataEve,
  parseZeekConnLogs,
  summarizeTrafficAlerts,
  replayPcap,
  listPcapRecordings
} from './engine/traffic.js';
export {
  checkBloodhoundAvailable,
  parseBloodhoundData,
  correlateFlamingoCredentials,
  ingestBloodhoundData,
  listBloodhoundIngests
} from './engine/bloodhound.js';
export {
  calculateRiskScore,
  buildHostDossier,
  getHostDossier,
  listHostDossiers
} from './engine/dossier.js';
export {
  MITRE_TACTICS,
  CORE_TECHNIQUES,
  generateMitreCoverageMatrix,
  generateMitreMarkdownReport,
  saveMitreReport
} from './engine/mitre.js';
export { VulnView } from './ui/VulnView.js';
export {
  CHALLENGE_CATEGORIES,
  CHALLENGE_TEMPLATES,
  generateDynamicFlag,
  generateChallengeManifest,
  spinUpChallenge,
  listActiveChallenges,
  deleteChallenge,
  toggleChallengeStatus,
  testChallengeConnection,
  getChallengeLogs
} from './engine/kctf.js';
export { KCTFView } from './ui/KCTFView.js';
export {
  SCAN_PROFILES as OPENVAS_SCAN_PROFILES,
  checkOpenVasStatus,
  runHostVulnerabilityScan,
  getCvssSeverity,
  listSavedOpenVasReports
} from './engine/openvas.js';
export { ModuleRegistry, globalModuleRegistry } from './modules/registry.js';
export { checkPrereqs, REQUIRED_TOOLS } from './engine/prereqs.js';
export { setupCertificates, checkCertificates, applyK8sTlsSecret } from './engine/certs.js';
export { createK3dCluster, deleteK3dCluster, getClusterInfo } from './engine/cluster.js';
export { App } from './ui/App.js';
export { Header } from './ui/Header.js';
export { TaskRunner } from './ui/TaskRunner.js';
export { SelectModules } from './ui/SelectModules.js';
export { StatusDashboard } from './ui/StatusDashboard.js';
export { ThreatSimView } from './ui/ThreatSimView.js';
export {
  BUILTIN_PLAYBOOKS,
  listAvailablePlaybooks,
  loadPlaybook,
  validatePlaybook,
  executeThreatPlaybook,
  createCustomPlaybookTemplate,
  generateThreatJobManifest
} from './engine/threats.js';
export {
  NIST_ATTACK_VECTORS,
  NIST_LIFECYCLE_PHASES,
  NIST_EVIDENCE_VOLATILITY,
  ARTIFACT_VOLATILITY_MAP,
  NIST_IMPACT_LEVELS,
  calculateNistIncidentScore,
  classifyAttackVector,
  generateNistIncidentRecord,
  generateNistPostMortemMarkdown,
  listNistIncidents
} from './engine/nist.js';
export {
  generateTopology,
  compareNmapScans,
  generateHeadlessSvg,
  generateHtmlReport,
  geocodeIp,
  parseNmapXml,
  listSavedXmlScans,
  readXmlScan
} from './engine/nmap-xml.js';
export { OOBScanView } from './ui/OOBScanView.js';
export {
  OOB_SCAN_PROFILES,
  checkOobscanInstalled,
  detectOobTargets,
  runOobScan,
  parseOobReportContent,
  listSavedOobScans,
  readSavedOobScan,
  deleteSavedOobScan,
  exportRakpHashes
} from './engine/oobscan.js';

export {
  generateQuarantineNetworkPolicy,
  isolatePod,
  freezePod,
  blockIp,
  quarantineAccount,
  listActiveContainments,
  releaseContainment
} from './engine/soar.js';

export {
  runAgentSocInvestigation,
  generateSocInvestigatorReport
} from './engine/agent-soc.js';

export {
  syncFeodoTrackerC2,
  syncUrlhausThreats,
  matchCtiIndicators,
  updateSuricataRules
} from './engine/cti.js';

export {
  evaluatePodSecurityStandards,
  generateKspmScorecard,
  generateKspmReport,
  saveKspmReport
} from './engine/kspm.js';

export {
  auditFileContent,
  generateSarifReport,
  runPipelineAudit
} from './engine/audit.js';

export { BattleStationView } from './ui/BattleStationView.js';
export { CommandPalette } from './ui/CommandPalette.js';
export { KspmView } from './ui/KspmView.js';
export { AuditView } from './ui/AuditView.js';

export {
  generateCanaryServiceAccount,
  generateCanarySecret,
  generateDecoyDeploymentYaml,
  detectCanaryTripped,
  triggerCanaryAlarm,
  listActiveCanaries,
  registerCanaryAsset,
  generateCloudHoneytoken,
  plantDecoyBreadcrumbs,
  startCanaryWebhookListener
} from './engine/deception.js';

export {
  WARGAME_SCENARIOS,
  runPurpleTeamSimulation,
  calculatePurpleScorecard,
  generatePurpleReport,
  savePurpleReport
} from './engine/purpleteam.js';

export {
  generatePatchForFinding,
  generateUnifiedDiff,
  applyPatchToFile,
  generateRemediationPrScript
} from './engine/remediation.js';

export {
  initDataLake,
  closeDataLake,
  getDataLakeBackend,
  ingestSecurityEvents,
  queryDataLake,
  runRetrospectiveThreatHunt
} from './engine/datalake.js';

export {
  auditWorkloadIdentity,
  auditCloudStorageExposure,
  calculateCloudRiskScore,
  generateCloudSecReport
} from './engine/cloudsec.js';

export {
  buildProcessLineageTree,
  detectAnomalousProcessLineage,
  renderAsciiProcessTree
} from './engine/lineage.js';

export {
  carveFilesFromPayload,
  ingestTlsSessionKeys,
  reconstructTcpStreams,
  generateFlowLadder,
  listCarvedFiles
} from './engine/forensics.js';

export {
  DEFAULT_DETECTOR_WASM_BYTES,
  loadWasmPlugin,
  executeWasmDetector,
  listWasmPlugins,
  installWasmPlugin
} from './engine/wasm.js';

export {
  parseSigmaRule,
  transpileSigmaToSql,
  runSigmaThreatHunt,
  generateSigmaHypothesis
} from './engine/sigma.js';

export {
  findBloodHoundAttackPaths,
  simulateDynamicAttackChain,
  calculateAdversaryResilienceScore,
  generateAdversaryReport
} from './engine/adversary.js';

export {
  parseProcessMemoryMaps,
  detectMemoryAnomalies,
  extractStringsAndEntropy,
  saveProcessDumpArtifact
} from './engine/memdump.js';

export {
  generateCycloneDxSbom,
  generateSpdxSbom,
  verifyCosignSignature,
  evaluateSupplyChainPolicy
} from './engine/supplychain.js';

export {
  ObservabilityRingBuffer,
  buildSocketConnectionMatrix,
  detectAnomalousSocketConnections,
  streamLiveEvents
} from './engine/observability.js';

export {
  renderBrailleSparkline,
  renderHalfBlockHeatmap,
  renderMitreHeatmapGrid
} from './ui/canvas.js';

export {
  createFederationNode,
  signThreatRecord,
  verifyThreatRecord,
  broadcastThreatIndicator,
  ingestFederatedThreatRecord,
  getVigilanteFederationDir
} from './engine/federation.js';

export { DeceptionView } from './ui/DeceptionView.js';
export { PurpleTeamView } from './ui/PurpleTeamView.js';
export { ForensicsView } from './ui/ForensicsView.js';
export { LineageView } from './ui/LineageView.js';
export { CloudSecView } from './ui/CloudSecView.js';
export { MitreView } from './ui/MitreView.js';
export { AttackGraphView } from './ui/AttackGraphView.js';

export {
  generateBpfLsmPolicy,
  compileLsmRuleToFilter,
  simulateLsmPolicyEvaluation,
  exportLsmCSource
} from './engine/lsm.js';

export {
  calculateInterArrivalTime,
  detectBeaconingPeriodicity,
  calculateShannonEntropy,
  detectDnsTunneling
} from './engine/beaconing.js';

export {
  generateRansomwareCanaryFiles,
  calculateFileEntropy,
  detectRansomwareEncryption,
  triggerRansomwareContainment
} from './engine/ransomware.js';

export {
  conveneIncidentWarRoom,
  conductAgentDebateRound,
  calculateConsensusScore,
  generateWarRoomTranscript
} from './engine/warroom.js';

export {
  generateLocalEmbedding,
  cosineSimilarity,
  initSemanticThreatCatalog,
  semanticThreatSearch
} from './engine/vectorcti.js';

export {
  initAuditLedger,
  appendLedgerEntry,
  getLedgerEntries,
  buildMerkleRoot,
  generateInclusionProof,
  verifyInclusionProof,
  verifyLedgerIntegrity,
  exportLegalChainOfCustody
} from './engine/ledger.js';

export {
  buildCompositeAttackGraph,
  findShortestAttackPath,
  calculateBlastRadius,
  renderAsciiAttackGraph
} from './engine/attackgraph.js';

export {
  BUILTIN_FALCO_RULES,
  FALCO_PRIORITIES,
  PRIORITY_TO_SEVERITY_MAP,
  MITRE_TACTIC_TAG_MAP,
  validateFalcoRule,
  parseFalcoEvent,
  filterFalcoEvents,
  aggregateFalcoMetrics,
  simulateFalcoEvent,
  evaluateFalcoSoarAction,
  renderFalcoRulesYaml,
  parseFalcoRulesYaml,
  saveFalcoEvidence
} from './engine/falco.js';

export {
  parseKallsyms,
  detectSyscallHooking,
  detectHiddenModules,
  analyzeKernelTaint,
  scanRootkitArtifacts,
  generateRootkitReport
} from './engine/rootkit.js';

export {
  compileYaraRule,
  scanBufferWithRules,
  extractCobaltStrikeConfig,
  scanProcessMemory,
  generateYaraMemoryReport
} from './engine/yarascan.js';

export {
  buildCausalTimeline,
  identifyRootCause,
  calculateDwellTime,
  renderAsciiTimeline
} from './engine/timeline.js';

export {
  createSwarmDuel,
  executeDuelRound,
  runFullDuelSimulation,
  evaluateDuelMetrics,
  generateDuelTranscript
} from './engine/swarmduel.js';

export {
  generateStixId,
  parseStixBundle,
  convertMispToStix,
  convertStixToMisp,
  mergeThreatFeeds,
  filterIndicators
} from './engine/stixmisp.js';

export {
  startDecoyService,
  createHoneynetMesh,
  plantBreadcrumbs
} from './engine/honeynet.js';

export {
  captureContainerVolatiles,
  captureContainerDiff,
  createForensicsSnapshot,
  verifySnapshotIntegrity,
  listSavedSnapshots
} from './engine/snapshot.js';

export {
  generateRfc3161Timestamp,
  generateChainOfCustodyRecord,
  createEvidenceBundle,
  verifyEvidenceBundle
} from './engine/evidencepack.js';

export {
  dissectEthernetFrame,
  dissectIpPacket,
  dissectTcpSegment,
  dissectUdpDatagram,
  dissectDnsPayload,
  dissectTlsPayload,
  dissectFullPacket,
  filterPacket,
  formatHexDump,
  exportToPcap,
  generateSyntheticPacketStream
} from './engine/sniffer.js';
