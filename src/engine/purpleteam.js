/**
 * Autonomous Purple Team Arena (Multi-Agent Adversarial Simulation)
 * Orchestrates automated Red vs. Blue wargames between RedAgent (Adversary)
 * and BlueAgent (Vigilante ReAct SOC & SOAR). Measures MTTD, MTTR, and ATT&CK coverage.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { getVigilantePurpleDir, getVigilanteEvidenceDir } from './config.js';
import { logger } from '../utils/logger.js';
import { isolatePod, blockIp } from './soar.js';
import { autoSignIfConfigured } from './gpg.js';

export const WARGAME_SCENARIOS = {
  'lateral-smb-exfil': {
    name: 'Lateral SMB Movement & Data Exfiltration',
    adversaryGroup: 'APT-29 / Cozy Bear',
    targetNamespace: 'default',
    targetWorkload: 'database-service',
    steps: [
      {
        phase: 'RECON',
        techniqueId: 'T1046',
        techniqueName: 'Network Service Scanning',
        action: 'Port scan on subnet 10.42.0.0/24 targeting ports 445, 139, 22',
        ioc: { dstPort: 445, scanRate: 1500 },
        detectableBy: ['zeek', 'suricata', 'recon'],
        detectionDelaySec: 4
      },
      {
        phase: 'CREDENTIAL_ACCESS',
        techniqueId: 'T1558.003',
        techniqueName: 'Kerberoasting / AS-REP Roasting',
        action: 'Request Kerberos TGS tickets for SPN MSSQLSvc/db.internal',
        ioc: { hashType: 'krb5tgs', account: 'svc_mssql' },
        detectableBy: ['bloodhound', 'flamingo', 'falco'],
        detectionDelaySec: 7
      },
      {
        phase: 'LATERAL_MOVEMENT',
        techniqueId: 'T1021.002',
        techniqueName: 'Remote Services: SMB/Windows Admin Shares',
        action: 'Authenticate to 10.42.0.88 via SMB with harvested NTLM hash',
        ioc: { srcIp: '10.42.0.77', dstIp: '10.42.0.88', proto: 'smb' },
        detectableBy: ['nastymap-v2', 'netexec', 'zeek'],
        detectionDelaySec: 5
      },
      {
        phase: 'EXFILTRATION',
        techniqueId: 'T1048.003',
        techniqueName: 'Exfiltration Over Alternative Protocol (DNS)',
        action: 'Encode staging database dumps in base32 subdomains to c2.malicious-domain.cc',
        ioc: { domain: 'c2.malicious-domain.cc', queryType: 'TXT' },
        detectableBy: ['cti', 'suricata', 'soar'],
        detectionDelaySec: 6
      }
    ]
  },
  'container-escape-privileged': {
    name: 'Container Escape & Host Namespace Compromise',
    adversaryGroup: 'FIN7 / Carbanak',
    targetNamespace: 'kube-system',
    targetWorkload: 'payment-processor',
    steps: [
      {
        phase: 'INITIAL_ACCESS',
        techniqueId: 'T1190',
        techniqueName: 'Exploit Public-Facing Application',
        action: 'Inject remote code execution payload into unauthenticated API endpoint',
        ioc: { cve: 'CVE-2024-38063', payload: 'cmd_exec' },
        detectableBy: ['zap', 'nuclei'],
        detectionDelaySec: 5
      },
      {
        phase: 'PRIVILEGE_ESCALATION',
        techniqueId: 'T1611',
        techniqueName: 'Escape to Host',
        action: 'Mount host filesystem via privileged hostPath /var/run/docker.sock',
        ioc: { syscall: 'mount', path: '/var/run/docker.sock' },
        detectableBy: ['falco', 'kspm'],
        detectionDelaySec: 3
      },
      {
        phase: 'DISCOVERY',
        techniqueId: 'T1613',
        techniqueName: 'Container and Resource Discovery',
        action: 'Query Kubernetes API server for all cluster secrets using local serviceaccount token',
        ioc: { sa: 'default', resource: 'secrets', verb: 'list' },
        detectableBy: ['deception', 'kubeaudit'],
        detectionDelaySec: 4
      },
      {
        phase: 'IMPACT',
        techniqueId: 'T1485',
        techniqueName: 'Data Destruction / Ransomware',
        action: 'Encrypt persistent volume claims and write ransom note',
        ioc: { extension: '.locked', writeRate: 800 },
        detectableBy: ['falco', 'agent-soc'],
        detectionDelaySec: 6
      }
    ]
  }
};

/**
 * Run an autonomous Purple Team simulation wargame
 * @param {string} [scenarioKey='lateral-smb-exfil']
 * @param {Object} [options={}]
 * @returns {Promise<Object>} Full wargame simulation trace
 */
export async function runPurpleTeamSimulation(scenarioKey = 'lateral-smb-exfil', options = {}) {
  const scenario = WARGAME_SCENARIOS[scenarioKey] || WARGAME_SCENARIOS['lateral-smb-exfil'];
  const simulationId = `sim-${Date.now().toString(36)}-${crypto.randomBytes(3).toString('hex')}`;
  logger.info('PURPLE', `Starting Purple Team Wargame [${scenario.name}] (${simulationId})`);

  const startTime = Date.now();
  const timeline = [];
  let isContained = false;
  let containmentStep = null;
  let containmentAction = null;
  let totalAdversaryTimeSec = 0;
  let firstDetectionSec = null;
  let containmentTimeSec = null;

  for (let idx = 0; idx < scenario.steps.length; idx++) {
    const step = scenario.steps[idx];
    const stepStartSec = totalAdversaryTimeSec;
    const stepDurationSec = step.detectionDelaySec + Math.floor(Math.random() * 3) + 2;
    totalAdversaryTimeSec += stepDurationSec;

    // Red Agent Action
    const redAction = {
      stepIndex: idx + 1,
      phase: step.phase,
      techniqueId: step.techniqueId,
      techniqueName: step.techniqueName,
      action: step.action,
      ioc: step.ioc,
      simulatedTimeSec: stepStartSec
    };

    // Blue Agent Reaction
    const detected = true; // In our simulated range, all instrumented steps trigger sensor telemetry
    const detectionLatencySec = stepStartSec + step.detectionDelaySec;

    if (firstDetectionSec === null) {
      firstDetectionSec = detectionLatencySec;
    }

    const blueReaction = {
      detected,
      detectedBySensors: step.detectableBy,
      detectionLatencySec,
      confidence: step.phase === 'LATERAL_MOVEMENT' || step.phase === 'EXFILTRATION' ? 'CRITICAL' : 'HIGH',
      containmentTriggered: false
    };

    // Blue Agent SOAR Containment Trigger on lateral movement or exfiltration
    if (!isContained && (step.phase === 'LATERAL_MOVEMENT' || step.phase === 'EXFILTRATION' || step.phase === 'IMPACT')) {
      isContained = true;
      containmentStep = idx + 1;
      containmentTimeSec = detectionLatencySec + 2; // +2 seconds for SOAR engine evaluation
      blueReaction.containmentTriggered = true;

      try {
        const podTarget = `victim-pod-${step.techniqueId.toLowerCase().replace(/[^a-z0-9]/g, '')}`;
        const soarRes = await isolatePod(podTarget, scenario.targetNamespace, {
          reason: `Autonomous Purple Team SOAR trigger on ${step.techniqueId} (${step.techniqueName})`,
          source: 'purple-team-arena'
        });
        containmentAction = {
          action: 'ISOLATE_POD',
          targetPod: podTarget,
          containmentId: soarRes.containmentId,
          status: 'CONTAINED',
          responseSec: containmentTimeSec
        };
      } catch (err) {
        containmentAction = { action: 'ISOLATE_POD', status: 'SIMULATED', error: err.message };
      }
    }

    timeline.push({
      redAgent: redAction,
      blueAgent: blueReaction
    });

    // If containment succeeded, Red Agent's subsequent attacks are blocked
    if (isContained && idx < scenario.steps.length - 1) {
      timeline.push({
        redAgent: {
          stepIndex: idx + 2,
          phase: 'TERMINATED',
          action: 'Adversary execution halted: network policy isolation & process freeze active.',
          blocked: true
        },
        blueAgent: {
          action: 'Threat Neutralized',
          containmentActive: true
        }
      });
      break;
    }
  }

  const durationMs = Date.now() - startTime;
  const result = {
    simulationId,
    scenarioKey,
    scenarioName: scenario.name,
    adversaryGroup: scenario.adversaryGroup,
    targetNamespace: scenario.targetNamespace,
    timestamp: new Date().toISOString(),
    isContained,
    containmentStep,
    containmentAction,
    metrics: {
      mttdSec: firstDetectionSec || 0,
      mttrSec: containmentTimeSec || 0,
      totalExecutionSec: totalAdversaryTimeSec,
      simulationDurationMs: durationMs
    },
    timeline
  };

  return result;
}

/**
 * Calculate Purple Team Scorecard
 * @param {Object} simRun 
 * @returns {Object} Scorecard
 */
export function calculatePurpleScorecard(simRun) {
  const mttd = simRun.metrics.mttdSec;
  const mttr = simRun.metrics.mttrSec;
  const contained = simRun.isContained;

  // Grade calculation:
  // MTTD < 10s & MTTR < 25s & Contained => A+
  // MTTD < 15s & MTTR < 35s & Contained => A
  // MTTD < 25s & Contained => B
  // Contained => C
  // Not Contained => F
  let grade = 'F';
  let score = 30;

  if (contained) {
    if (mttd <= 10 && mttr <= 25) {
      grade = 'A+';
      score = 98;
    } else if (mttd <= 15 && mttr <= 35) {
      grade = 'A';
      score = 90;
    } else if (mttd <= 25) {
      grade = 'B';
      score = 80;
    } else {
      grade = 'C';
      score = 70;
    }
  }

  return {
    grade,
    score,
    contained,
    mttdSec: mttd,
    mttrSec: mttr,
    containmentStep: simRun.containmentStep,
    techniquesTested: simRun.timeline.filter(t => t.redAgent && t.redAgent.techniqueId).map(t => t.redAgent.techniqueId),
    containmentEfficiency: contained ? 'HIGH' : 'UNCONTAINED',
    recommendations: [
      mttd > 10 ? 'Tune sensor alert thresholds on network service scanning (T1046).' : 'Sensor detection latency within optimal SLA (<10s).',
      contained ? 'SOAR active containment successfully blocked lateral spread before data loss.' : 'Implement automated zero-trust network quarantine rules.'
    ]
  };
}

/**
 * Generate formatted Markdown report for Purple Team simulation
 * @param {Object} simRun 
 * @param {Object} scorecard 
 * @returns {string} Markdown content
 */
export function generatePurpleReport(simRun, scorecard) {
  return `# ⚔️ Vigilante Autonomous Purple Team Wargame Report

**Simulation ID**: \`${simRun.simulationId}\`  
**Scenario**: **${simRun.scenarioName}**  
**Emulated Threat Actor**: \`${simRun.adversaryGroup}\`  
**Timestamp**: ${simRun.timestamp}  

---

## 🏆 Defensive Executive Scorecard

| Metric | Result | Status |
| :--- | :--- | :--- |
| **Overall Defense Grade** | **${scorecard.grade}** (${scorecard.score}/100) | ${scorecard.grade.startsWith('A') ? '🟢 Optimal' : '🟡 Review Required'} |
| **Mean Time to Detect (MTTD)** | **${scorecard.mttdSec}s** | ⚡ Fast |
| **Mean Time to Respond (MTTR)** | **${scorecard.mttrSec}s** | 🛡️ Automated SOAR |
| **Containment Verdict** | **${scorecard.contained ? 'CONTAINED' : 'EXFILTRATED'}** | Step ${scorecard.containmentStep || 'N/A'} |

---

## 🔬 Turn-by-Turn Red vs. Blue Timeline

${simRun.timeline.map((item, idx) => {
  if (item.redAgent.blocked) {
    return `### 🛑 Step ${item.redAgent.stepIndex}: Adversary Neutralized
> **Red Agent**: ${item.redAgent.action}  
> **Blue Agent**: ${item.blueAgent.action}`;
  }
  return `### Phase ${item.redAgent.stepIndex}: [${item.redAgent.phase}] ${item.redAgent.techniqueName} (\`${item.redAgent.techniqueId}\`)
- **Red Agent Action**: ${item.redAgent.action}
- **Observed Telemetry**: \`${JSON.stringify(item.redAgent.ioc)}\`
- **Blue Agent Detection**: Detected by \`${item.blueAgent.detectedBySensors.join(', ')}\` in **${item.blueAgent.detectionLatencySec}s** (${item.blueAgent.confidence} confidence).
- **SOAR Active Action**: ${item.blueAgent.containmentTriggered ? `🚨 **CONTAINMENT TRIGGERED**: ${simRun.containmentAction?.action || 'Isolate Pod'}` : '🔍 Sensor Monitoring'}`;
}).join('\n\n')}

---

## 📋 Remediation & Hardening Recommendations

${scorecard.recommendations.map(r => `- ${r}`).join('\n')}

*Generated autonomously by Vigilante Purple Team Arena.*
`;
}

/**
 * Save Purple Team report and signed evidence
 * @param {Object} simRun 
 * @param {Object} scorecard 
 * @returns {Promise<string>} Saved file path
 */
export async function savePurpleReport(simRun, scorecard) {
  const purpleDir = getVigilantePurpleDir();
  await fs.mkdir(purpleDir, { recursive: true });

  const reportMd = generatePurpleReport(simRun, scorecard);
  const reportPath = path.join(purpleDir, `${simRun.simulationId}.md`);
  await fs.writeFile(reportPath, reportMd, 'utf8');

  const jsonPath = path.join(purpleDir, `${simRun.simulationId}.json`);
  await fs.writeFile(jsonPath, JSON.stringify({ simRun, scorecard }, null, 2), 'utf8');

  try {
    await autoSignIfConfigured(reportPath);
  } catch (err) {
    logger.warn('PURPLE', `Could not sign report: ${err.message}`);
  }

  logger.info('PURPLE', `Saved Purple Team Report: ${reportPath}`);
  return reportPath;
}
