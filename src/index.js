export { BaseModule } from './modules/base.js';
export { VigilSOCModule } from './modules/vigil-soc/index.js';
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

