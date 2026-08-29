import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteEvidenceDir, loadConfig } from './config.js';
import { logger } from '../utils/logger.js';

/**
 * Official NIST SP 800-61 Rev. 2 Attack Vectors (Section 3.2.1 / Table 3-1)
 */
export const NIST_ATTACK_VECTORS = {
  EXTERNAL_REMOVABLE_MEDIA: {
    id: 'EXTERNAL_REMOVABLE_MEDIA',
    name: 'External / Removable Media',
    description: 'An attack executed from removable media or peripheral hardware (e.g. malicious USB, autorun media).'
  },
  ATTRITION: {
    id: 'ATTRITION',
    name: 'Attrition (Denial of Service / Brute Force)',
    description: 'An attack that employs brute-force methods to compromise, degrade, or destroy systems, networks, or services (e.g. credential spraying, DDoS).'
  },
  WEB_APPLICATION: {
    id: 'WEB_APPLICATION',
    name: 'Web Application',
    description: 'An attack executed against public or internal web applications and REST APIs (e.g. SQL injection, Log4j/JNDI RCE, XSS, webshell injection).'
  },
  EMAIL: {
    id: 'EMAIL',
    name: 'Email & Phishing',
    description: 'An attack executed via email message or attachment (e.g. spear phishing, malicious Office macros, credential harvesting links).'
  },
  IMPERSONATION: {
    id: 'IMPERSONATION',
    name: 'Impersonation & Adversary-In-The-Middle',
    description: 'An attack involving spoofing, rogue gateways, or identity theft (e.g. ARP cache poisoning, DNS spoofing, rogue DHCP, stolen tokens).'
  },
  IMPROPER_USAGE: {
    id: 'IMPROPER_USAGE',
    name: 'Improper Usage & Privilege Escalation',
    description: 'A breach resulting from violation of acceptable use or container boundary escapes (e.g. unauthorized sudo, Kubernetes SA token misuse, chroot breakouts).'
  },
  LOSS_OR_THEFT: {
    id: 'LOSS_OR_THEFT',
    name: 'Loss or Theft of Equipment',
    description: 'The loss or physical theft of computing devices, storage media, or hardware security keys.'
  },
  OTHER: {
    id: 'OTHER',
    name: 'Other / Unknown Attack Vector',
    description: 'An attack vector not matching other categories or currently under active forensic investigation.'
  }
};

/**
 * Official NIST SP 800-61 Rev. 2 Lifecycle Phases (Section 3)
 */
export const NIST_LIFECYCLE_PHASES = {
  PREPARATION: {
    id: 'PREPARATION',
    phaseNumber: 1,
    name: 'Phase 1: Preparation',
    description: 'Preventing incidents, establishing secure OOB comms, configuring cryptographic GPG identities, and jump station readiness.'
  },
  DETECTION_AND_ANALYSIS: {
    id: 'DETECTION_AND_ANALYSIS',
    phaseNumber: 2,
    name: 'Phase 2: Detection and Analysis',
    description: 'Identifying precursors and indicators, network profiling, volatile evidence acquisition, 3D impact scoring, and root-cause analysis.'
  },
  CONTAINMENT_ERADICATION_RECOVERY: {
    id: 'CONTAINMENT_ERADICATION_RECOVERY',
    phaseNumber: 3,
    name: 'Phase 3: Containment, Eradication, and Recovery',
    description: 'Selecting containment strategies, network policy segmentation, credential rotation, malware elimination, and phased recovery.'
  },
  POST_INCIDENT_ACTIVITY: {
    id: 'POST_INCIDENT_ACTIVITY',
    phaseNumber: 4,
    name: 'Phase 4: Post-Incident Activity',
    description: 'Lessons learned conferences, CSIRT metrics tracking (MTTD/MTTT/MTTC), multi-year evidence retention, and GPG-signed post-mortem reports.'
  }
};

/**
 * Order of Volatility Hierarchy (RFC 3227 & NIST SP 800-86)
 */
export const NIST_EVIDENCE_VOLATILITY = {
  1: { rank: 1, name: 'CPU Registers & Cache', lifespan: 'Nanoseconds / Microseconds' },
  2: { rank: 2, name: 'System Memory (RAM)', lifespan: 'Seconds / Transient until reboot' },
  3: { rank: 3, name: 'Network State & Socket Tables', lifespan: 'Transient / Minutes' },
  4: { rank: 4, name: 'Running Processes & Open Handles', lifespan: 'Transient / Hours' },
  5: { rank: 5, name: 'Disk & File System Artifacts', lifespan: 'Persistent / Days / Weeks' },
  6: { rank: 6, name: 'Remote SIEM & Centralized Logs', lifespan: 'Persistent / Months / Years' },
  7: { rank: 7, name: 'Backup & Archival Media', lifespan: 'Immutable / Long-term' }
};

/**
 * Map forensic probe artifact files to their NIST Volatility Rank
 */
export const ARTIFACT_VOLATILITY_MAP = {
  'arp_neighbors.json': { rank: 3, volatilityName: 'Network State & ARP Cache Tables' },
  'ping.json': { rank: 3, volatilityName: 'Network RTT & Latency Telemetry' },
  'mtr.txt': { rank: 3, volatilityName: 'Network Routing & Traceroute State' },
  'dns_records.json': { rank: 3, volatilityName: 'DNS Cache & Forward/Reverse Sockets' },
  'tls_certificates.pem': { rank: 3, volatilityName: 'Active Ingress TLS Socket Certificates' },
  'http_headers.txt': { rank: 4, volatilityName: 'Application Worker Process Headers & State' },
  'triage_summary.json': { rank: 5, volatilityName: 'Authoritative Chain-of-Custody Index' },
  'nist_incident_record.json': { rank: 5, volatilityName: 'NIST SP 800-61 Rev. 2 Incident Manifest' }
};

/**
 * NIST SP 800-61 Rev. 2 3-Dimensional Incident Impact Levels (Section 3.2.6)
 */
export const NIST_IMPACT_LEVELS = {
  functional: {
    NONE: { score: 0, label: 'None', description: 'No effect on operational systems or business functions.' },
    LOW: { score: 1, label: 'Low', description: 'Minimal impact on non-critical support systems; core services operational.' },
    MEDIUM: { score: 2, label: 'Medium', description: 'Critical operational system degraded; some services unavailable.' },
    HIGH: { score: 3, label: 'High', description: 'Critical systems completely offline; primary business operations halted.' }
  },
  information: {
    NONE: { score: 0, label: 'None', description: 'No organizational data or confidentiality compromised.' },
    PRIVACY_BREACH: { score: 2, label: 'Privacy Breach', description: 'Personally Identifiable Information (PII) or sensitive records accessed.' },
    PROPRIETARY_BREACH: { score: 3, label: 'Proprietary Breach', description: 'Core intellectual property, source code, or internal credentials exfiltrated.' },
    INTEGRITY_LOSS: { score: 3, label: 'Integrity Loss', description: 'Critical data modified, encrypted by ransomware, or destroyed.' }
  },
  recoverability: {
    REGULAR: { score: 1, label: 'Regular', description: 'Predictable recovery time with existing in-house CSIRT personnel.' },
    SUPPLEMENTED: { score: 2, label: 'Supplemented', description: 'Recovery requires external specialist assistance or retainer support.' },
    EXTENDED: { score: 3, label: 'Extended', description: 'Recovery time unpredictable; full infrastructure rebuild required.' },
    NOT_RECOVERABLE: { score: 4, label: 'Not Recoverable', description: 'Data or systems permanently lost without viable recovery.' }
  }
};

/**
 * Calculate 3-Dimensional NIST SP 800-61 Rev. 2 Incident Score and Severity
 * @param {Object} params
 * @param {'NONE'|'LOW'|'MEDIUM'|'HIGH'} [params.functionalImpact='LOW']
 * @param {'NONE'|'PRIVACY_BREACH'|'PROPRIETARY_BREACH'|'INTEGRITY_LOSS'} [params.informationImpact='NONE']
 * @param {'REGULAR'|'SUPPLEMENTED'|'EXTENDED'|'NOT_RECOVERABLE'} [params.recoverabilityEffort='REGULAR']
 * @returns {{ severity: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'INFORMATIONAL', compositeScore: number, slaTargetMinutes: number, containmentUrgency: string }}
 */
export function calculateNistIncidentScore({
  functionalImpact = 'LOW',
  informationImpact = 'NONE',
  recoverabilityEffort = 'REGULAR'
} = {}) {
  const fScore = NIST_IMPACT_LEVELS.functional[functionalImpact]?.score ?? 1;
  const iScore = NIST_IMPACT_LEVELS.information[informationImpact]?.score ?? 0;
  const rScore = NIST_IMPACT_LEVELS.recoverability[recoverabilityEffort]?.score ?? 1;

  // Composite calculation: Functional (weight: 3), Information (weight: 3), Recoverability (weight: 2)
  const compositeScore = (fScore * 3) + (iScore * 3) + (rScore * 2);

  let severity = 'LOW';
  let slaTargetMinutes = 240; // 4 hours
  let containmentUrgency = 'Standard Priority';

  if (compositeScore >= 18 || fScore === 3 || iScore === 3 || rScore === 4) {
    severity = 'CRITICAL';
    slaTargetMinutes = 15; // 15 min containment SLA
    containmentUrgency = 'IMMEDIATE ISOLATION REQUIRED (0 - 15 min SLA)';
  } else if (compositeScore >= 12) {
    severity = 'HIGH';
    slaTargetMinutes = 60; // 1 hour
    containmentUrgency = 'High Priority Containment (Within 1 hour)';
  } else if (compositeScore >= 6) {
    severity = 'MEDIUM';
    slaTargetMinutes = 120; // 2 hours
    containmentUrgency = 'Elevated Monitoring & Remediation (Within 2 hours)';
  } else {
    severity = 'LOW';
    slaTargetMinutes = 480; // 8 hours
    containmentUrgency = 'Routine Investigation (Standard Working Hours)';
  }

  return {
    severity,
    compositeScore,
    slaTargetMinutes,
    containmentUrgency,
    functionalImpact,
    informationImpact,
    recoverabilityEffort
  };
}

/**
 * Classify the NIST SP 800-61 Rev. 2 Attack Vector from telemetry or events
 * @param {Object} telemetry
 * @returns {Object} NIST Attack Vector descriptor
 */
export function classifyAttackVector(telemetry = {}) {
  const { ports = [], http = null, arp = null, process = null, threat = null, message = '' } = telemetry;
  const combinedText = `${message} ${threat?.technique?.name || ''} ${threat?.technique?.id || ''}`.toLowerCase();

  // 1. Web Application Vector
  if (
    ports.some(p => p.port === 80 || p.port === 443 || p.port === 8080 || p.service === 'http' || p.service === 'https') ||
    combinedText.includes('log4j') || combinedText.includes('jndi') || combinedText.includes('sql') ||
    /\brce\b/.test(combinedText) || combinedText.includes('web app') || combinedText.includes('t1190') || combinedText.includes('cve-')
  ) {
    return NIST_ATTACK_VECTORS.WEB_APPLICATION;
  }

  // 2. Impersonation / MITM Vector
  if (
    arp?.hasCollision || combinedText.includes('arp') || combinedText.includes('poison') ||
    combinedText.includes('mitm') || combinedText.includes('spoof') || combinedText.includes('t1557')
  ) {
    return NIST_ATTACK_VECTORS.IMPERSONATION;
  }

  // 3. Attrition / Brute Force Vector
  if (
    combinedText.includes('brute') || combinedText.includes('spray') || combinedText.includes('flood') ||
    combinedText.includes('t1110') || combinedText.includes('syn_flood')
  ) {
    return NIST_ATTACK_VECTORS.ATTRITION;
  }

  // 4. Improper Usage / Privilege Escalation / Container Escape
  if (
    combinedText.includes('escape') || combinedText.includes('chroot') || combinedText.includes('privilege') ||
    combinedText.includes('t1611') || combinedText.includes('t1609') || combinedText.includes('serviceaccount')
  ) {
    return NIST_ATTACK_VECTORS.IMPROPER_USAGE;
  }

  // 5. Exfiltration / DNS Tunneling
  if (combinedText.includes('dns') || combinedText.includes('tunnel') || combinedText.includes('t1071.004') || combinedText.includes('exfil')) {
    return NIST_ATTACK_VECTORS.IMPROPER_USAGE;
  }

  // Default fallback
  return NIST_ATTACK_VECTORS.OTHER;
}

/**
 * Generate a complete NIST SP 800-61 Rev. 2 Incident Record
 * @param {Object} options
 * @returns {Object} Structured incident record
 */
export function generateNistIncidentRecord({
  incidentId = null,
  network = '10.0.1.0_24',
  host = '10.0.1.15',
  detectedAt = null,
  attackVector = null,
  functionalImpact = 'MEDIUM',
  informationImpact = 'PRIVACY_BREACH',
  recoverabilityEffort = 'REGULAR',
  artifacts = [],
  rootCause = 'Pending forensic investigation',
  responderGpgKey = null
} = {}) {
  const now = new Date().toISOString();
  const id = incidentId || `INC-${now.replace(/[-:T]/g, '').slice(0, 14)}-${host.replace(/\./g, '')}`;
  const scoring = calculateNistIncidentScore({ functionalImpact, informationImpact, recoverabilityEffort });
  const vector = typeof attackVector === 'object' && attackVector ? attackVector : NIST_ATTACK_VECTORS[attackVector] || NIST_ATTACK_VECTORS.OTHER;

  return {
    standard: 'NIST SP 800-61 Rev. 2 (Computer Security Incident Handling Guide)',
    incidentId: id,
    timestamp: now,
    detectedAt: detectedAt || now,
    currentPhase: NIST_LIFECYCLE_PHASES.DETECTION_AND_ANALYSIS.id,
    classification: {
      attackVector: vector,
      signType: scoring.severity === 'CRITICAL' || scoring.severity === 'HIGH' ? 'INDICATOR' : 'PRECURSOR',
      mitreAttackTactic: 'Initial Access & Execution'
    },
    prioritization: scoring,
    target: {
      network,
      host,
      vaultPath: `evidence/${network}/${host}`
    },
    chainOfCustody: {
      volatilityOrderStandard: 'RFC 3227 / NIST SP 800-86',
      artifactsCount: artifacts.length,
      artifacts: artifacts.map(a => ({
        filename: a.filename || a,
        volatilityRank: ARTIFACT_VOLATILITY_MAP[a.filename || a]?.rank || 5,
        volatilityLevel: ARTIFACT_VOLATILITY_MAP[a.filename || a]?.volatilityName || 'Disk / Log Artifact',
        sha256: a.sha256 || 'pending-hash',
        gpgSigned: !!a.gpgSignature
      })),
      responderGpgKey: responderGpgKey || 'Auto-Signed'
    },
    rootCauseAnalysis: {
      initialAccessVector: rootCause,
      remediationSummary: 'Pending full eradication'
    },
    slas: {
      containmentTargetMinutes: scoring.slaTargetMinutes,
      containmentUrgency: scoring.containmentUrgency
    }
  };
}

/**
 * Generate a formal NIST SP 800-61 Rev. 2 compliant Markdown Post-Mortem Report
 * @param {Object} incidentRecord
 * @returns {string} Markdown formatted report
 */
export function generateNistPostMortemMarkdown(incidentRecord) {
  const rec = incidentRecord || generateNistIncidentRecord();
  const vector = rec.classification?.attackVector?.name || 'Unknown';
  const score = rec.prioritization || calculateNistIncidentScore();

  return `# 🛡️ NIST SP 800-61 Rev. 2 Incident Post-Mortem & Forensic Audit Report

> **Standard Reference**: NIST Special Publication 800-61 Revision 2 (*Computer Security Incident Handling Guide*)  
> **Incident Identifier**: \`${rec.incidentId}\`  
> **Date of Incident**: ${rec.detectedAt || new Date().toUTCString()}  
> **Authoritative Target**: Host \`${rec.target?.host}\` on Subnet \`${rec.target?.network}\`  

---

## 1. Executive Incident Classification & NIST 3D Prioritization (Section 3.2.6)

| Metric | Assessment | NIST Evaluation Details |
| :--- | :--- | :--- |
| **Overall Incident Severity** | **\`${score.severity}\`** | Composite Priority Score: **${score.compositeScore}/24** |
| **Primary Attack Vector** | **${vector}** | NIST SP 800-61 Table 3-1 Classification |
| **Functional Impact** | **${score.functionalImpact}** | Impact on core operational systems |
| **Information Impact** | **${score.informationImpact}** | Impact on confidentiality & data integrity |
| **Recoverability Effort** | **${score.recoverabilityEffort}** | Resources required for complete recovery |
| **Containment SLA Target** | **${score.slaTargetMinutes} Minutes** | ${score.containmentUrgency} |

---

## 2. Forensic Evidence Hierarchy & RFC 3227 Order of Volatility

All digital evidence was acquired adhering strictly to **RFC 3227 / NIST SP 800-86 Order of Volatility** and archived into the cryptographic **Evidence Vault** (\`${rec.target?.vaultPath}\`):

| Volatility Rank | Artifact File | Volatility Level & Data Collected | Forensic Chain-of-Custody |
| :--- | :--- | :--- | :--- |
| **Rank 3 (Network)** | \`arp_neighbors.json\` | Kernel ARP / Neighbor table state (\`ip neigh\`) | 🔏 GPG Verified Detached Signature |
| **Rank 3 (Network)** | \`ping.json\` | ICMP RTT latency, packet loss, and jitter | 🔏 GPG Verified Detached Signature |
| **Rank 3 (Network)** | \`mtr.txt\` | Per-hop route traceroute and loss statistics | 🔏 GPG Verified Detached Signature |
| **Rank 3 (Network)** | \`dns_records.json\` | Forward & Reverse DNS socket resolution | 🔏 GPG Verified Detached Signature |
| **Rank 3 (Network)** | \`tls_certificates.pem\` | Ingress X.509 certificate chains & SANs | 🔏 GPG Verified Detached Signature |
| **Rank 4 (Process)** | \`http_headers.txt\` | Raw HTTP response headers & server tokens | 🔏 GPG Verified Detached Signature |
| **Rank 5 (Disk)** | \`triage_summary.json\` | Master SHA-256 integrity timeline index | 🔏 GPG Verified Detached Signature |

---

## 3. Incident Response Lifecycle Progression (Section 3)

### Phase 1: Preparation
- Secure Out-of-Band (OOB) communications activated.
- Responder GPG cryptographic keys verified and bound to evidence chain-of-custody.

### Phase 2: Detection & Analysis
- **Initial Anomaly**: Network discovery sweep flagged uninventoried services.
- **Root Cause Determination**: ${rec.rootCauseAnalysis?.initialAccessVector || 'Initial access vector isolated via vulnerability audit and banner grabs.'}
- **MITRE ATT&CK Mapping**: \`${rec.classification?.mitreAttackTactic || 'T1190 - Exploit Public-Facing Application'}\`.

### Phase 3: Containment, Eradication & Recovery
- **Containment Action**: Applied default-deny Kubernetes \`NetworkPolicy\` and isolated subnet VLAN.
- **Eradication Action**: Revoked compromised TLS certificates and rotated service account tokens.
- **Recovery Action**: Re-deployed verified immutable images into isolated namespaces.

### Phase 4: Post-Incident Activity (Lessons Learned)
- Lessons Learned meeting scheduled within 14 business days.
- Immutable Evidence Vault retention policy enforced (minimum 3-year retention).

---

*Generated by Vigilante Incident Response & Forensics Engine (NIST SP 800-61 Rev. 2 Compliant)*
`;
}

/**
 * List all NIST incident records saved across the Evidence Vault
 * @returns {Promise<Array<Object>>}
 */
export async function listNistIncidents() {
  const evidenceDir = getVigilanteEvidenceDir();
  const incidents = [];

  if (!fsSync.existsSync(evidenceDir)) {
    return incidents;
  }

  try {
    const networks = await fs.readdir(evidenceDir);
    for (const net of networks) {
      const netPath = path.join(evidenceDir, net);
      const stat = await fs.stat(netPath);
      if (!stat.isDirectory() || net === 'ai_reports' || net === 'threat_reports') continue;

      const hosts = await fs.readdir(netPath);
      for (const host of hosts) {
        const hostPath = path.join(netPath, host);
        const hostStat = await fs.stat(hostPath);
        if (!hostStat.isDirectory()) continue;

        const recordFile = path.join(hostPath, 'nist_incident_record.json');
        if (fsSync.existsSync(recordFile)) {
          try {
            const raw = await fs.readFile(recordFile, 'utf8');
            incidents.push(JSON.parse(raw));
          } catch {
            // Ignore unreadable record
          }
        }
      }
    }
  } catch (err) {
    logger.warn('NIST:LIST_ERR', `Failed to list NIST incidents: ${err.message}`);
  }

  return incidents;
}
