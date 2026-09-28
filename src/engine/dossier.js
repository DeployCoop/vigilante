import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilanteDossiersDir,
  getVigilanteNmapsDir,
  getVigilanteOobscansDir,
  getVigilanteReconDir,
  getVigilanteNucleiDir,
  getVigilanteTrivyDir,
  getVigilanteNetexecDir,
  getVigilanteZapDir,
  getVigilanteBloodhoundDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

/**
 * Calculate a normalized 0–100 Composite Risk Score and Risk Tier
 * @param {Object} findings
 * @returns {{ score: number, tier: 'CRITICAL'|'HIGH'|'MEDIUM'|'LOW'|'CLEAN', color: string }}
 */
export function calculateRiskScore(findings = {}) {
  let score = 0;

  // Nuclei / CVE findings
  const nucleiCritical = findings.nuclei?.critical || 0;
  const nucleiHigh = findings.nuclei?.high || 0;
  const nucleiMedium = findings.nuclei?.medium || 0;
  score += nucleiCritical * 35;
  score += nucleiHigh * 20;
  score += nucleiMedium * 8;

  // Trivy findings
  const trivyCritical = findings.trivy?.critical || 0;
  const trivyHigh = findings.trivy?.high || 0;
  const trivySecrets = findings.trivy?.secrets || 0;
  score += trivyCritical * 30;
  score += trivyHigh * 15;
  score += trivySecrets * 25;

  // NetExec / Credential / Protocol exposures
  if (findings.netexec?.signingDisabled) score += 25;
  if (findings.netexec?.guestAuthAllowed) score += 20;
  if (findings.netexec?.nullSession) score += 15;

  // OOB / IPMI exposures
  if (findings.oobscan?.isBmc) score += 15;
  if (findings.oobscan?.rakpDumped) score += 35;

  // ZAP alerts
  const zapHigh = findings.zap?.high || 0;
  const zapMedium = findings.zap?.medium || 0;
  score += zapHigh * 25;
  score += zapMedium * 10;

  // BloodHound identity compromise
  if (findings.bloodhound?.tier0Compromised) score += 50;
  else if (findings.bloodhound?.compromised) score += 30;

  // Suricata / Network IDS
  if (findings.traffic?.criticalAlerts) score += 40;
  else if (findings.traffic?.highAlerts) score += 20;

  // Cap at 100
  const normalizedScore = Math.min(100, Math.round(score));

  let tier = 'CLEAN';
  let color = 'green';

  if (normalizedScore >= 80) {
    tier = 'CRITICAL';
    color = 'red';
  } else if (normalizedScore >= 55) {
    tier = 'HIGH';
    color = 'yellow';
  } else if (normalizedScore >= 30) {
    tier = 'MEDIUM';
    color = 'cyan';
  } else if (normalizedScore > 0) {
    tier = 'LOW';
    color = 'blue';
  }

  return { score: normalizedScore, tier, color };
}

/**
 * Scan local directory for JSON files matching a predicate or target
 * @private
 */
async function loadMatchingJsonFiles(dir, filterFn) {
  if (!fsSync.existsSync(dir)) return [];
  try {
    const files = await fs.readdir(dir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        try {
          const raw = await fs.readFile(path.join(dir, f), 'utf8');
          const data = JSON.parse(raw);
          if (!filterFn || filterFn(data, f)) {
            results.push(data);
          }
        } catch {
          // ignore corrupted files
        }
      }
    }
    return results;
  } catch {
    return [];
  }
}

/**
 * Build or refresh a Unified Host Dossier for a target IP/hostname
 * by aggregating scan evidence across all engines
 * @param {string} target - Target IP address or hostname
 * @param {Object} [options]
 * @returns {Promise<Object>} Unified Host Dossier
 */
export async function buildHostDossier(target, options = {}) {
  await ensureVigilanteConfig();
  const dossiersDir = getVigilanteDossiersDir();
  const cleanTarget = String(target).replace(/[^a-zA-Z0-9.-]/g, '_');

  const dossier = {
    target: String(target).trim(),
    cleanTarget,
    updatedAt: new Date().toISOString(),
    network: {
      openPorts: [],
      osGuessed: 'Unknown',
      services: [],
      httpEndpoints: []
    },
    vulnerabilities: {
      cves: [],
      misconfigs: [],
      secrets: [],
      zapAlerts: []
    },
    identity: {
      bloodhoundAlerts: [],
      kerberosExposures: [],
      compromisedAccounts: []
    },
    outOfBand: {
      detected: false,
      details: null
    },
    traffic: {
      alertCount: 0,
      recentAlerts: []
    },
    remediations: [],
    mitreTechniques: []
  };

  // 1. Ingest Nmap evidence
  const nmaps = await loadMatchingJsonFiles(getVigilanteNmapsDir(), d =>
    d.target === target || (d.hosts && d.hosts.some(h => h.ip === target || h.hostname === target))
  );
  if (nmaps.length > 0) {
    const latestNmap = nmaps[0];
    if (latestNmap.hosts) {
      const match = latestNmap.hosts.find(h => h.ip === target || h.hostname === target);
      if (match) {
        if (match.ports) dossier.network.openPorts.push(...match.ports);
        if (match.os) dossier.network.osGuessed = match.os;
      }
    }
  }

  // 2. Ingest Recon (Naabu & Httpx) evidence
  const recons = await loadMatchingJsonFiles(getVigilanteReconDir(), d =>
    d.target === target || (d.naabu?.ports && d.naabu.ports.some(p => p.host === target))
  );
  for (const r of recons) {
    if (r.naabu?.ports) {
      for (const p of r.naabu.ports) {
        if (p.host === target && !dossier.network.openPorts.includes(p.port)) {
          dossier.network.openPorts.push(p.port);
        }
      }
    }
    if (r.httpx?.results) {
      for (const h of r.httpx.results) {
        if (h.host === target || h.url?.includes(target)) {
          dossier.network.httpEndpoints.push({
            url: h.url,
            status: h.status,
            title: h.title,
            tech: h.tech || []
          });
        }
      }
    }
  }

  // 3. Ingest Nuclei findings
  const nucleiScans = await loadMatchingJsonFiles(getVigilanteNucleiDir(), d =>
    d.target === target || (d.findings && d.findings.some(f => f.host?.includes(target) || f.matched?.includes(target)))
  );
  for (const ns of nucleiScans) {
    const matchedFindings = (ns.findings || []).filter(f => f.host?.includes(target) || f.matched?.includes(target));
    for (const mf of matchedFindings) {
      dossier.vulnerabilities.cves.push({
        id: mf.templateId,
        name: mf.name,
        severity: mf.severity,
        cveId: mf.cveId,
        cvssScore: mf.cvssScore,
        description: mf.description,
        remediation: mf.remediation
      });
      if (mf.cveId) {
        dossier.remediations.push(`Patch software component: ${mf.cveId} (${mf.name})`);
      }
      dossier.mitreTechniques.push('T1190'); // Exploit Public-Facing Application
    }
  }

  // 4. Ingest Trivy findings
  const trivyAudits = await loadMatchingJsonFiles(getVigilanteTrivyDir(), d =>
    d.target === target || d.target?.includes(target)
  );
  for (const ta of trivyAudits) {
    if (ta.findings?.vulnerabilities) {
      dossier.vulnerabilities.cves.push(...ta.findings.vulnerabilities.map(v => ({
        id: v.id,
        severity: v.severity,
        package: v.package,
        fixedVersion: v.fixedVersion
      })));
    }
    if (ta.findings?.secrets) {
      dossier.vulnerabilities.secrets.push(...ta.findings.secrets);
      dossier.mitreTechniques.push('T1552'); // Unsecured Credentials
      dossier.remediations.push(`Rotate leaked secret found in container/manifest: ${ta.target}`);
    }
  }

  // 5. Ingest oobscan findings
  const oobscans = await loadMatchingJsonFiles(getVigilanteOobscansDir(), d =>
    d.target === target || (d.bmcs && d.bmcs.some(b => b.ip === target))
  );
  for (const os of oobscans) {
    const bmc = (os.bmcs || []).find(b => b.ip === target);
    if (bmc) {
      dossier.outOfBand.detected = true;
      dossier.outOfBand.details = bmc;
      dossier.mitreTechniques.push('T1584'); // Compromise Infrastructure
      dossier.remediations.push(`Isolate BMC/IPMI interface for ${target} on a dedicated management VLAN.`);
    }
  }

  // 6. Ingest NetExec findings
  const netexecs = await loadMatchingJsonFiles(getVigilanteNetexecDir(), d =>
    d.target === target || (d.results && d.results.some(r => r.host === target))
  );
  let netexecSigningDisabled = false;
  let netexecGuestAllowed = false;
  let netexecNullSession = false;

  for (const ne of netexecs) {
    for (const r of ne.results || []) {
      if (r.host === target) {
        if (r.smbSigning === false) {
          netexecSigningDisabled = true;
          dossier.mitreTechniques.push('T1557.001'); // LLMNR/NBT-NS Poisoning and SMB Relay
          dossier.remediations.push(`Enforce SMB Signing on ${target} to prevent NTLM relay attacks.`);
        }
        if (r.guestAuth) netexecGuestAllowed = true;
        if (r.nullSession) netexecNullSession = true;
      }
    }
  }

  // 7. Ingest ZAP alerts
  const zaps = await loadMatchingJsonFiles(getVigilanteZapDir(), d =>
    d.target === target || d.target?.includes(target)
  );
  for (const z of zaps) {
    for (const a of z.alerts || []) {
      dossier.vulnerabilities.zapAlerts.push(a);
      if (a.risk === 'High') {
        dossier.remediations.push(`Remediate web application flaw: ${a.name} (${a.solution || 'Sanitize input'})`);
      }
    }
  }

  // 8. Ingest BloodHound data
  const bhs = await loadMatchingJsonFiles(getVigilanteBloodhoundDir(), d =>
    d.parsed?.computers?.some(c => c.name?.includes(target)) ||
    d.parsed?.users?.some(u => u.name?.includes(target))
  );
  let bhCompromised = false;
  let bhTier0 = false;
  for (const b of bhs) {
    if (b.correlation?.tier0Compromises?.length > 0) bhTier0 = true;
    if (b.correlation?.compromisedAccounts?.length > 0) bhCompromised = true;
    for (const alert of b.parsed?.attackPathAlerts || []) {
      if (alert.target?.includes(target)) {
        dossier.identity.bloodhoundAlerts.push(alert);
      }
    }
  }

  // Deduplicate open ports & techniques
  dossier.network.openPorts = [...new Set(dossier.network.openPorts)].sort((a, b) => a - b);
  dossier.mitreTechniques = [...new Set(dossier.mitreTechniques)];
  dossier.remediations = [...new Set(dossier.remediations)];

  // Calculate composite risk
  const riskInputs = {
    nuclei: {
      critical: dossier.vulnerabilities.cves.filter(c => c.severity === 'critical').length,
      high: dossier.vulnerabilities.cves.filter(c => c.severity === 'high').length,
      medium: dossier.vulnerabilities.cves.filter(c => c.severity === 'medium').length
    },
    trivy: {
      critical: dossier.vulnerabilities.cves.filter(c => String(c.severity).toUpperCase() === 'CRITICAL').length,
      high: dossier.vulnerabilities.cves.filter(c => String(c.severity).toUpperCase() === 'HIGH').length,
      secrets: dossier.vulnerabilities.secrets.length
    },
    netexec: {
      signingDisabled: netexecSigningDisabled,
      guestAuthAllowed: netexecGuestAllowed,
      nullSession: netexecNullSession
    },
    oobscan: {
      isBmc: dossier.outOfBand.detected,
      rakpDumped: Boolean(dossier.outOfBand.details?.rakpHash)
    },
    zap: {
      high: dossier.vulnerabilities.zapAlerts.filter(a => a.risk === 'High').length,
      medium: dossier.vulnerabilities.zapAlerts.filter(a => a.risk === 'Medium').length
    },
    bloodhound: {
      tier0Compromised: bhTier0,
      compromised: bhCompromised
    },
    traffic: {
      criticalAlerts: dossier.traffic.recentAlerts.some(a => a.severity === 'critical'),
      highAlerts: dossier.traffic.recentAlerts.some(a => a.severity === 'high')
    }
  };

  const risk = calculateRiskScore(riskInputs);
  dossier.riskScore = risk.score;
  dossier.riskTier = risk.tier;
  dossier.riskColor = risk.color;

  // Persist dossier
  const dossierPath = path.join(dossiersDir, `${cleanTarget}.json`);
  await fs.writeFile(dossierPath, JSON.stringify(dossier, null, 2), 'utf8');

  try {
    await saveEvidenceFile('dossiers', cleanTarget, `${cleanTarget}.json`, JSON.stringify(dossier, null, 2));
    await autoSignIfConfigured(path.join(getHostEvidenceDir('dossiers', cleanTarget), `${cleanTarget}.json`));
  } catch (err) {
    logger.warn('DOSSIER', `Failed to save signed evidence: ${err.message}`);
  }

  logger.info('DOSSIER', `Compiled Unified Host Dossier for ${target} (Risk: ${risk.score}/100 [${risk.tier}])`);
  return dossier;
}

/**
 * Retrieve saved dossier for a target
 * @param {string} target
 * @returns {Promise<Object|null>}
 */
export async function getHostDossier(target) {
  await ensureVigilanteConfig();
  const dossiersDir = getVigilanteDossiersDir();
  const cleanTarget = String(target).replace(/[^a-zA-Z0-9.-]/g, '_');
  const dossierPath = path.join(dossiersDir, `${cleanTarget}.json`);

  if (fsSync.existsSync(dossierPath)) {
    try {
      const raw = await fs.readFile(dossierPath, 'utf8');
      return JSON.parse(raw);
    } catch {
      // fallback
    }
  }

  return buildHostDossier(target);
}

/**
 * List all compiled Host Dossiers
 * @returns {Promise<Array<Object>>}
 */
export async function listHostDossiers() {
  await ensureVigilanteConfig();
  const dossiersDir = getVigilanteDossiersDir();

  try {
    const files = await fs.readdir(dossiersDir);
    const dossiers = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        try {
          const raw = await fs.readFile(path.join(dossiersDir, f), 'utf8');
          const data = JSON.parse(raw);
          dossiers.push({
            target: data.target,
            riskScore: data.riskScore || 0,
            riskTier: data.riskTier || 'CLEAN',
            riskColor: data.riskColor || 'green',
            openPortsCount: (data.network?.openPorts || []).length,
            cvesCount: (data.vulnerabilities?.cves || []).length,
            isBmc: Boolean(data.outOfBand?.detected),
            updatedAt: data.updatedAt
          });
        } catch {
          // ignore corrupted files
        }
      }
    }
    return dossiers.sort((a, b) => b.riskScore - a.riskScore);
  } catch (err) {
    logger.warn('DOSSIER', `Failed to list host dossiers: ${err.message}`);
    return [];
  }
}
