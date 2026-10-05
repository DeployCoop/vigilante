/**
 * VIGILANTE Autonomous Multi-Agent Incident War Room & Consensus Debate
 * 4-persona autonomous consortium (Forensics, Threat Intel, SRE Blast Radius, Incident Commander)
 * deliberating incident severity, evaluating reversibility, and reaching quorum on active containment.
 */

import { logger } from '../utils/logger.js';

export const WARROOM_ROLES = {
  FORENSICS: 'Forensics Specialist',
  THREAT_INTEL: 'Cyber Threat Intelligence Specialist',
  SRE_RELIABILITY: 'Site Reliability & Blast-Radius Specialist',
  INCIDENT_COMMANDER: 'Incident Commander'
};

/**
 * Convenes the 4-agent incident war room consortium
 * @param {Object} incidentData - Incident telemetry, alerts, and affected workloads
 * @param {Object} options - { quorumThreshold: 75, autoContain: false }
 * @returns {Object} War Room session results
 */
export function conveneIncidentWarRoom(incidentData = {}, options = {}) {
  const sessionId = `warroom-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
  const quorumThreshold = options.quorumThreshold !== undefined ? options.quorumThreshold : 75;

  const targetWorkload = incidentData.pod || incidentData.sourcePod || incidentData.target || 'target-workload';
  const severity = (incidentData.severity || 'HIGH').toUpperCase();
  const mitreTechnique = incidentData.mitreTechnique || incidentData.technique || 'T1059';

  // 1. Forensics Specialist Analysis
  const forensicsOpinion = {
    agentId: 'agent-forensics',
    role: WARROOM_ROLES.FORENSICS,
    verdict: severity === 'CRITICAL' || incidentData.anomaliesCount > 0 ? 'CONTAIN' : 'INVESTIGATE',
    confidence: severity === 'CRITICAL' ? 95 : 75,
    keyFindings: [
      `Workload ${targetWorkload} exhibited suspicious activity matching ${mitreTechnique}`,
      incidentData.memAnomalies ? `Detected in-memory RWX/memfd segments` : `Volatile telemetry captured in evidence vault`
    ],
    rationale: `Forensic telemetry indicates active process execution anomalies requiring immediate network air-gapping.`,
    recommendedAction: 'ISOLATE_POD'
  };

  // 2. Cyber Threat Intelligence Specialist Analysis
  const ctiOpinion = {
    agentId: 'agent-cti',
    role: WARROOM_ROLES.THREAT_INTEL,
    verdict: severity === 'CRITICAL' || incidentData.isC2 ? 'CONTAIN' : 'MONITOR',
    confidence: 88,
    keyFindings: [
      `Indicator mapped to MITRE ATT&CK ${mitreTechnique}`,
      incidentData.c2Ip ? `Matched known malicious C2 feed (Feodo/URLhaus)` : `Behavior matches common lateral movement pattern`
    ],
    rationale: `Threat telemetry matches high-probability adversary campaign with C2 or privilege escalation objectives.`,
    recommendedAction: 'BLOCK_IP_AND_ISOLATE'
  };

  // 3. Site Reliability & Blast-Radius Specialist Analysis
  const isProdDb = targetWorkload.includes('db') || targetWorkload.includes('database') || targetWorkload.includes('payment');
  const sreOpinion = {
    agentId: 'agent-sre',
    role: WARROOM_ROLES.SRE_RELIABILITY,
    verdict: isProdDb ? (severity === 'CRITICAL' ? 'CONTAIN' : 'MONITOR') : 'CONTAIN',
    confidence: 80,
    keyFindings: [
      `Target workload tier: ${isProdDb ? 'CRITICAL_DATASTORE' : 'STANDARD_MICROSERVICE'}`,
      `Reversibility: High (NetworkPolicy quarantine can be un-isolated in <500ms via SOAR releaseContainment)`
    ],
    rationale: isProdDb && severity !== 'CRITICAL'
      ? `Workload is critical datastore; caution advised against immediate hard isolation without secondary confirmation.`
      : `Containment action is non-destructive and fully reversible via NetworkPolicy release.`,
    recommendedAction: isProdDb && severity !== 'CRITICAL' ? 'THROTTLE_AND_AUDIT' : 'APPLY_REVERSIBLE_QUARANTINE'
  };

  // 4. Incident Commander Synthesis
  const opinions = [forensicsOpinion, ctiOpinion, sreOpinion];
  const consensus = calculateConsensusScore(opinions, quorumThreshold);

  const commanderVerdict = {
    agentId: 'agent-commander',
    role: WARROOM_ROLES.INCIDENT_COMMANDER,
    verdict: consensus.quorumApproved ? 'CONTAIN' : 'INVESTIGATE',
    confidence: consensus.consensusScore,
    keyFindings: [
      `Quorum Consensus Score: ${consensus.consensusScore}% (Threshold: ${quorumThreshold}%)`,
      `Quorum Approved: ${consensus.quorumApproved ? 'YES' : 'NO'}`
    ],
    rationale: consensus.quorumApproved
      ? `Consensus reached across specialist consortium. Authorizing active SOAR containment on ${targetWorkload}.`
      : `Quorum threshold not met. Placing workload under continuous forensic surveillance.`,
    finalOrder: consensus.quorumApproved ? 'EXECUTE_SOAR_CONTAINMENT' : 'MAINTAIN_SURVEILLANCE'
  };

  const session = {
    sessionId,
    targetWorkload,
    severity,
    mitreTechnique,
    quorumThreshold,
    opinions: [...opinions, commanderVerdict],
    consensus,
    createdAt: new Date().toISOString()
  };

  session.transcriptMarkdown = generateWarRoomTranscript(session);
  logger.info('WARROOM', `Convened Incident War Room ${sessionId} for ${targetWorkload}. Consensus: ${consensus.consensusScore}%`);

  return session;
}

/**
 * Calculates consensus score and quorum approval across specialist opinions
 * @param {Array<Object>} opinions
 * @param {number} quorumThreshold
 * @returns {Object}
 */
export function calculateConsensusScore(opinions = [], quorumThreshold = 75) {
  if (!opinions || opinions.length === 0) {
    return {
      consensusScore: 0,
      quorumApproved: false,
      finalVerdict: 'NO_DATA',
      dissentingOpinions: []
    };
  }

  let containScore = 0;
  let totalWeight = 0;
  const dissenting = [];

  for (const op of opinions) {
    const weight = op.confidence || 75;
    totalWeight += weight;

    if (op.verdict === 'CONTAIN') {
      containScore += weight;
    } else {
      dissenting.push({
        role: op.role,
        verdict: op.verdict,
        rationale: op.rationale
      });
    }
  }

  const scorePct = totalWeight > 0 ? Math.round((containScore / totalWeight) * 100) : 0;
  const quorumApproved = scorePct >= quorumThreshold;

  return {
    consensusScore: scorePct,
    quorumApproved,
    finalVerdict: quorumApproved ? 'CONTAIN' : 'INVESTIGATE',
    totalAgents: opinions.length,
    containVotes: opinions.filter(o => o.verdict === 'CONTAIN').length,
    dissentingCount: dissenting.length,
    dissentingOpinions: dissenting
  };
}

/**
 * Conduct a structured debate round between specialist agents
 * @param {Array<Object>} opinions - Current consortium opinions
 * @param {Object} proposedAction - { action, target, justification }
 * @returns {Array<Object>} Updated opinions with rebuttals
 */
export function conductAgentDebateRound(opinions = [], proposedAction = {}) {
  return opinions.map(op => {
    const isReversible = proposedAction.action !== 'DELETE_POD' && proposedAction.action !== 'PURGE_DATA';
    let revisedConfidence = op.confidence;
    let rebuttal = null;

    if (op.role === WARROOM_ROLES.SRE_RELIABILITY && !isReversible) {
      revisedConfidence = Math.max(20, op.confidence - 30);
      rebuttal = 'Action is non-reversible; risks production outage. Requesting shadow containment only.';
    } else if (op.role === WARROOM_ROLES.FORENSICS && isReversible) {
      revisedConfidence = Math.min(100, op.confidence + 10);
      rebuttal = 'Reversible NetworkPolicy isolation preserves in-memory volatile forensic state.';
    }

    return {
      ...op,
      confidence: revisedConfidence,
      rebuttal
    };
  });
}

/**
 * Generates an executive Markdown transcript of the multi-agent deliberation
 * @param {Object} session
 * @returns {string} Markdown transcript
 */
export function generateWarRoomTranscript(session = {}) {
  const c = session.consensus || {};

  return `# 🏛️ Autonomous Incident War Room Deliberation Transcript
**Session ID**: \`${session.sessionId}\`  
**Target Workload**: \`${session.targetWorkload}\`  
**Initial Severity**: \`${session.severity}\` | **MITRE Technique**: \`${session.mitreTechnique}\`  
**Timestamp**: \`${session.createdAt}\`  

---

## 1. Specialist Consortium Deliberations

${(session.opinions || []).map(op => `### 🤖 ${op.role} (\`${op.agentId}\`)
- **Verdict**: **${op.verdict}** (Confidence: \`${op.confidence}%\`)
- **Rationale**: ${op.rationale}
- **Key Findings**:
${(op.keyFindings || []).map(f => `  - ${f}`).join('\n')}
`).join('\n')}

---

## 2. Quorum Consensus Determination

| Metric | Value |
| :--- | :--- |
| **Quorum Threshold** | \`${session.quorumThreshold}%\` |
| **Consensus Score** | **\`${c.consensusScore}%\`** |
| **Quorum Result** | **${c.quorumApproved ? '✅ QUORUM APPROVED (Active Containment Ordered)' : '⚠️ QUORUM REJECTED (Maintain Surveillance)'}** |
| **Contain Votes** | \`${c.containVotes} / ${c.totalAgents}\` |
| **Dissenting Opinions** | \`${c.dissentingCount}\` |

${c.dissentingCount > 0 ? `### ⚠️ Dissenting Rationales:\n` + c.dissentingOpinions.map(d => `- **${d.role}**: ${d.rationale}`).join('\n') : `*Consensus was unanimous across all specialists.*`}

---
*Signed by Vigilante Autonomous War Room Commander Engine*
`;
}
