import fs from 'node:fs/promises';
import path from 'node:path';
import { BUILTIN_PLAYBOOKS } from './threats.js';
import { globalModuleRegistry } from '../modules/registry.js';
import { ensureVigilanteConfig, getVigilanteEvidenceDir, getHostEvidenceDir } from './config.js';
import { saveEvidenceFile } from './evidence.js';
import { autoSignIfConfigured } from './gpg.js';
import { logger } from '../utils/logger.js';

export const MITRE_TACTICS = [
  { id: 'TA0043', name: 'Reconnaissance' },
  { id: 'TA0042', name: 'Resource Development' },
  { id: 'TA0001', name: 'Initial Access' },
  { id: 'TA0002', name: 'Execution' },
  { id: 'TA0003', name: 'Persistence' },
  { id: 'TA0004', name: 'Privilege Escalation' },
  { id: 'TA0005', name: 'Defense Evasion' },
  { id: 'TA0006', name: 'Credential Access' },
  { id: 'TA0007', name: 'Discovery' },
  { id: 'TA0008', name: 'Lateral Movement' },
  { id: 'TA0009', name: 'Collection' },
  { id: 'TA0011', name: 'Command and Control' },
  { id: 'TA0010', name: 'Exfiltration' },
  { id: 'TA0040', name: 'Impact' }
];

export const CORE_TECHNIQUES = [
  { id: 'T1595', name: 'Active Scanning', tactic: 'Reconnaissance', primarySensor: 'Suricata, Zeek' },
  { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'Initial Access', primarySensor: 'Suricata, Nuclei, ZAP' },
  { id: 'T1078', name: 'Valid Accounts', tactic: 'Initial Access', primarySensor: 'Wazuh, BloodHound, NetExec' },
  { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'Execution', primarySensor: 'Falco, Wazuh' },
  { id: 'T1611', name: 'Escape to Host', tactic: 'Privilege Escalation', primarySensor: 'Falco, Kube-Bench' },
  { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'Privilege Escalation', primarySensor: 'Falco, Wazuh' },
  { id: 'T1070', name: 'Indicator Removal on Host', tactic: 'Defense Evasion', primarySensor: 'Falco, Wazuh' },
  { id: 'T1110', name: 'Brute Force', tactic: 'Credential Access', primarySensor: 'Flamingo, NetExec, Wazuh' },
  { id: 'T1558', name: 'Steal or Forge Kerberos Tickets', tactic: 'Credential Access', primarySensor: 'BloodHound, NetExec' },
  { id: 'T1552', name: 'Unsecured Credentials', tactic: 'Credential Access', primarySensor: 'Trivy, Flamingo' },
  { id: 'T1046', name: 'Network Service Discovery', tactic: 'Discovery', primarySensor: 'Suricata, Zeek, Naabu' },
  { id: 'T1087', name: 'Account Discovery', tactic: 'Discovery', primarySensor: 'BloodHound, NetExec' },
  { id: 'T1557', name: 'Adversary-in-the-Middle', tactic: 'Lateral Movement', primarySensor: 'Suricata, Zeek, NetExec' },
  { id: 'T1021', name: 'Remote Services (SMB/RDP/SSH)', tactic: 'Lateral Movement', primarySensor: 'NetExec, Zeek, Wazuh' },
  { id: 'T1071', name: 'Application Layer Protocol', tactic: 'Command and Control', primarySensor: 'Suricata, Zeek' },
  { id: 'T1571', name: 'Non-Standard Port', tactic: 'Command and Control', primarySensor: 'Zeek, Suricata' },
  { id: 'T1041', name: 'Exfiltration Over C2 Channel', tactic: 'Exfiltration', primarySensor: 'Suricata, Zeek' },
  { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'Impact', primarySensor: 'Falco, Wazuh' }
];

/**
 * Generate MITRE ATT&CK coverage matrix comparing simulated playbooks and deployed sensor modules
 * @param {Object} [options]
 * @returns {Object} MITRE coverage report with statistics and gaps
 */
export function generateMitreCoverageMatrix(options = {}) {
  // Collect simulated techniques from built-in playbooks
  const simulatedTechniques = new Map();
  for (const pb of BUILTIN_PLAYBOOKS) {
    for (const mt of pb.mitreTechniques || []) {
      const baseId = mt.id.split('.')[0];
      simulatedTechniques.set(baseId, {
        id: mt.id,
        name: mt.name,
        tactic: mt.tactic,
        playbook: pb.id
      });
    }
  }

  // Check which modules are registered
  const registeredModuleNames = globalModuleRegistry.getAll().map(m => (m.id || m.name || '').toLowerCase());
  const hasSuricata = registeredModuleNames.includes('suricata');
  const hasZeek = registeredModuleNames.includes('zeek');
  const hasFalco = registeredModuleNames.includes('falco');
  const hasWazuh = registeredModuleNames.includes('wazuh');
  const hasBloodhound = registeredModuleNames.includes('bloodhound');
  const hasFlamingo = registeredModuleNames.includes('flamingo');

  const matrix = [];
  let coveredCount = 0;

  for (const tech of CORE_TECHNIQUES) {
    const isSimulated = simulatedTechniques.has(tech.id);
    
    // Determine active sensor coverage
    const sensors = [];
    if (tech.primarySensor.includes('Suricata') && hasSuricata) sensors.push('Suricata');
    if (tech.primarySensor.includes('Zeek') && hasZeek) sensors.push('Zeek');
    if (tech.primarySensor.includes('Falco') && hasFalco) sensors.push('Falco');
    if (tech.primarySensor.includes('Wazuh') && hasWazuh) sensors.push('Wazuh');
    if (tech.primarySensor.includes('BloodHound') && hasBloodhound) sensors.push('BloodHound');
    if (tech.primarySensor.includes('Flamingo') && hasFlamingo) sensors.push('Flamingo');

    // Always include built-in scanners (Nuclei, Trivy, NetExec, Naabu)
    if (tech.primarySensor.includes('Nuclei')) sensors.push('Nuclei');
    if (tech.primarySensor.includes('Trivy')) sensors.push('Trivy');
    if (tech.primarySensor.includes('NetExec')) sensors.push('NetExec');
    if (tech.primarySensor.includes('Naabu')) sensors.push('Naabu');

    const hasSensorCoverage = sensors.length > 0;
    const isFullyCovered = isSimulated && hasSensorCoverage;
    const isPartiallyCovered = isSimulated || hasSensorCoverage;

    if (isFullyCovered || isPartiallyCovered) {
      coveredCount++;
    }

    matrix.push({
      id: tech.id,
      name: tech.name,
      tactic: tech.tactic,
      simulated: isSimulated,
      playbook: simulatedTechniques.get(tech.id)?.playbook || null,
      sensors,
      status: isFullyCovered ? 'FULL' : isPartiallyCovered ? 'PARTIAL' : 'GAP'
    });
  }

  const total = CORE_TECHNIQUES.length;
  const coveragePercent = Math.round((coveredCount / total) * 100);

  // Group by tactic
  const tacticBreakdown = {};
  for (const t of MITRE_TACTICS) {
    const items = matrix.filter(m => m.tactic.toLowerCase() === t.name.toLowerCase());
    const covered = items.filter(m => m.status !== 'GAP').length;
    tacticBreakdown[t.name] = {
      total: items.length,
      covered,
      percent: items.length > 0 ? Math.round((covered / items.length) * 100) : 100
    };
  }

  return {
    generatedAt: new Date().toISOString(),
    totalTechniques: total,
    coveredTechniques: coveredCount,
    gapTechniques: total - coveredCount,
    coveragePercent,
    matrix,
    tacticBreakdown,
    activeModules: registeredModuleNames
  };
}

/**
 * Generate a Markdown report from a MITRE coverage matrix
 * @param {Object} matrixReport
 * @returns {string} GitHub Flavored Markdown formatted report
 */
export function generateMitreMarkdownReport(matrixReport) {
  const { generatedAt, totalTechniques, coveredTechniques, coveragePercent, matrix, tacticBreakdown } = matrixReport;

  let md = `# 🛡️ MITRE ATT&CK® Detection & Simulation Coverage Report\n\n`;
  md += `**Generated**: ${generatedAt}  \n`;
  md += `**Overall Coverage**: ${coveragePercent}% (${coveredTechniques}/${totalTechniques} Core Techniques Covered)\n\n`;

  md += `### 📊 Coverage by Tactic\n\n`;
  md += `| Tactic | Covered / Total | Coverage % |\n`;
  md += `| :--- | :--- | :--- |\n`;
  for (const [tactic, data] of Object.entries(tacticBreakdown)) {
    if (data.total > 0) {
      md += `| **${tactic}** | ${data.covered} / ${data.total} | ${data.percent}% |\n`;
    }
  }

  md += `\n### 🎯 Detailed Technique Coverage & Sensor Mapping\n\n`;
  md += `| Technique ID | Name | Tactic | Simulation Playbook | Active Sensors | Status |\n`;
  md += `| :--- | :--- | :--- | :--- | :--- | :--- |\n`;

  for (const item of matrix) {
    const statusIcon = item.status === 'FULL' ? '🟢 FULL' : item.status === 'PARTIAL' ? '🟡 PARTIAL' : '🔴 GAP';
    const playbookStr = item.playbook || '*(None)*';
    const sensorsStr = item.sensors.length > 0 ? item.sensors.join(', ') : '*(None)*';
    md += `| **${item.id}** | ${item.name} | ${item.tactic} | \`${playbookStr}\` | ${sensorsStr} | ${statusIcon} |\n`;
  }

  const gaps = matrix.filter(m => m.status === 'GAP');
  if (gaps.length > 0) {
    md += `\n### ⚠️ Detection Gaps & Recommendations\n\n`;
    for (const gap of gaps) {
      md += `- **${gap.id}: ${gap.name} (${gap.tactic})**: No simulation playbook or active sensor mapped. Consider deploying complementary sensors or authoring a custom simulation playbook.\n`;
    }
  }

  return md;
}

/**
 * Generate and save signed MITRE coverage report
 * @param {Object} [options]
 * @returns {Promise<Object>}
 */
export async function saveMitreReport(options = {}) {
  await ensureVigilanteConfig();
  const matrix = generateMitreCoverageMatrix(options);
  const markdown = generateMitreMarkdownReport(matrix);

  const reportId = `mitre-${Date.now()}`;
  try {
    await saveEvidenceFile('mitre', 'coverage', `${reportId}.json`, JSON.stringify(matrix, null, 2));
    await saveEvidenceFile('mitre', 'coverage', `${reportId}.md`, markdown);
    await autoSignIfConfigured(path.join(getHostEvidenceDir('mitre', 'coverage'), `${reportId}.md`));
  } catch (err) {
    logger.warn('MITRE', `Failed to save signed report evidence: ${err.message}`);
  }

  return { matrix, markdown, reportId };
}
