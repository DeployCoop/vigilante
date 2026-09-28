import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilanteBloodhoundDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

/**
 * Check if BloodHound CE API endpoint is reachable
 * @param {Object} [options]
 * @param {string} [options.url]
 * @returns {Promise<{ reachable: boolean, endpoint: string, error?: string }>}
 */
export async function checkBloodhoundAvailable(options = {}) {
  const url = options.url || 'http://127.0.0.1:8080/api/v2/health';
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const resp = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);
    return { reachable: resp.ok, endpoint: url, status: resp.status };
  } catch (err) {
    return { reachable: false, endpoint: url, error: err.message };
  }
}

/**
 * Parse BloodHound / SharpHound JSON file or object
 * Supports: users.json, computers.json, groups.json, sessions.json, domains.json
 * @param {string|Object} fileOrData
 * @returns {Object} Extracted Active Directory graph summary
 */
export function parseBloodhoundData(fileOrData) {
  let data = fileOrData;
  if (typeof fileOrData === 'string') {
    if (fsSync.existsSync(fileOrData)) {
      try {
        const raw = fsSync.readFileSync(fileOrData, 'utf8');
        data = JSON.parse(raw);
      } catch (err) {
        logger.error('BLOODHOUND', `Failed to parse file at ${fileOrData}: ${err.message}`);
        return { count: 0, items: [], type: 'unknown' };
      }
    } else {
      try {
        data = JSON.parse(fileOrData);
      } catch {
        return { count: 0, items: [], type: 'unknown' };
      }
    }
  }

  if (!data || typeof data !== 'object') {
    return { count: 0, items: [], type: 'unknown' };
  }

  // BloodHound JSONs typically have: { data: [...], meta: { type: "users", ... } }
  const meta = data.meta || {};
  const dataType = meta.type || (data.users ? 'users' : data.computers ? 'computers' : 'generic');
  const items = Array.isArray(data.data) ? data.data : (Array.isArray(data) ? data : []);

  const users = [];
  const computers = [];
  const groups = [];
  const attackPathAlerts = [];

  for (const item of items) {
    const props = item.Properties || item.properties || item;
    const name = props.name || props.samaccountname || item.name || 'UNKNOWN';
    const domain = props.domain || 'UNKNOWN';

    // User node
    if (props.dontreqpreauth !== undefined || props.pwdneverexpires !== undefined || props.admincount !== undefined) {
      const isAsRepRoastable = Boolean(props.dontreqpreauth);
      const isUnconstrained = Boolean(props.unconstraineddelegation);
      const isAdminCount = Boolean(props.admincount);

      const userObj = {
        name,
        domain,
        distinguishedName: props.distinguishedname,
        enabled: props.enabled !== false,
        adminCount: isAdminCount,
        pwdNeverExpires: Boolean(props.pwdneverexpires),
        asRepRoastable: isAsRepRoastable,
        unconstrainedDelegation: isUnconstrained,
        spnTargets: props.serviceprincipalnames || []
      };
      users.push(userObj);

      if (isAsRepRoastable) {
        attackPathAlerts.push({
          severity: 'HIGH',
          type: 'AS-REP Roasting',
          target: name,
          description: `User ${name} has 'Do not require Kerberos preauthentication' set.`
        });
      }
      if (isAdminCount && isUnconstrained) {
        attackPathAlerts.push({
          severity: 'CRITICAL',
          type: 'Unconstrained Delegation on Privileged Account',
          target: name,
          description: `Privileged account ${name} has unconstrained delegation enabled.`
        });
      }
    }
    // Computer node
    else if (props.operatingsystem !== undefined || props.unconstraineddelegation !== undefined) {
      const compObj = {
        name,
        domain,
        os: props.operatingsystem,
        enabled: props.enabled !== false,
        unconstrainedDelegation: Boolean(props.unconstraineddelegation)
      };
      computers.push(compObj);

      if (compObj.unconstrainedDelegation) {
        attackPathAlerts.push({
          severity: 'HIGH',
          type: 'Unconstrained Delegation',
          target: name,
          description: `Computer ${name} has unconstrained delegation enabled.`
        });
      }
    }
    // Group node
    else if (props.admincount !== undefined || name.toUpperCase().includes('ADMIN')) {
      groups.push({
        name,
        domain,
        membersCount: (item.Members || []).length
      });
    }
  }

  return {
    type: dataType,
    count: items.length,
    users,
    computers,
    groups,
    attackPathAlerts,
    statistics: {
      totalUsers: users.length,
      privilegedUsers: users.filter(u => u.adminCount).length,
      asRepRoastable: users.filter(u => u.asRepRoastable).length,
      totalComputers: computers.length,
      unconstrainedComputers: computers.filter(c => c.unconstrainedDelegation).length,
      totalGroups: groups.length
    }
  };
}

/**
 * Cross-reference Flamingo captured credentials with BloodHound identity graph
 * to spot compromised Domain Admins or Tier-0 assets
 * @param {Object} options
 * @param {Object} options.bloodhoundData - Result from parseBloodhoundData
 * @param {Array<Object>} options.flamingoCredentials - Credential list from Flamingo
 * @returns {Object} Correlation analysis with flagged compromise paths
 */
export function correlateFlamingoCredentials({ bloodhoundData = {}, flamingoCredentials = [] } = {}) {
  const users = bloodhoundData.users || [];
  const compromisedAccounts = [];
  const tier0Compromises = [];

  for (const cred of flamingoCredentials) {
    const credUsername = (cred.username || cred.user || '').toUpperCase().trim();
    if (!credUsername) continue;

    const matchedUser = users.find(u => {
      const uName = (u.name || '').toUpperCase();
      return uName === credUsername || uName.startsWith(`${credUsername}@`) || uName.includes(`\\${credUsername}`);
    });

    if (matchedUser) {
      const comp = {
        username: cred.username,
        domain: matchedUser.domain || cred.domain,
        sourceProtocol: cred.protocol || 'flamingo',
        clientIp: cred.clientIp || cred.ip || 'unknown',
        adminCount: matchedUser.adminCount,
        asRepRoastable: matchedUser.asRepRoastable,
        severity: matchedUser.adminCount ? 'CRITICAL' : 'HIGH'
      };

      compromisedAccounts.push(comp);

      if (matchedUser.adminCount) {
        tier0Compromises.push({
          ...comp,
          alert: `🚨 CRITICAL: Compromised Tier-0 / Domain Admin credential detected: ${cred.username}`
        });
      }
    }
  }

  return {
    totalCompromised: compromisedAccounts.length,
    tier0CompromisedCount: tier0Compromises.length,
    compromisedAccounts,
    tier0Compromises,
    riskScore: tier0Compromises.length > 0 ? 100 : (compromisedAccounts.length > 0 ? 80 : 0)
  };
}

/**
 * Ingest BloodHound data, correlate with Flamingo credentials, and save signed evidence
 * @param {string|Object} fileOrData
 * @param {Object} [options]
 * @param {Array<Object>} [options.flamingoCredentials]
 * @returns {Promise<Object>}
 */
export async function ingestBloodhoundData(fileOrData, options = {}) {
  await ensureVigilanteConfig();
  const bloodhoundDir = getVigilanteBloodhoundDir();

  const parsed = parseBloodhoundData(fileOrData);
  const correlation = correlateFlamingoCredentials({
    bloodhoundData: parsed,
    flamingoCredentials: options.flamingoCredentials || []
  });

  const recordId = `bh-${Date.now()}`;
  const record = {
    id: recordId,
    timestamp: new Date().toISOString(),
    parsed,
    correlation,
    stats: {
      users: parsed.statistics.totalUsers,
      computers: parsed.statistics.totalComputers,
      attackPathAlerts: parsed.attackPathAlerts.length,
      tier0Compromises: correlation.tier0CompromisedCount
    }
  };

  const savePath = path.join(bloodhoundDir, `${recordId}.json`);
  await fs.writeFile(savePath, JSON.stringify(record, null, 2), 'utf8');

  try {
    await saveEvidenceFile('bloodhound', 'identity-graph', `${recordId}.json`, JSON.stringify(record, null, 2));
    await autoSignIfConfigured(path.join(getHostEvidenceDir('bloodhound', 'identity-graph'), `${recordId}.json`));
  } catch (err) {
    logger.warn('BLOODHOUND', `Failed to save signed evidence: ${err.message}`);
  }

  logger.info('BLOODHOUND', `Ingested identity graph data record: ${recordId}`);
  return record;
}

/**
 * List all saved BloodHound ingest records
 * @returns {Promise<Array<Object>>}
 */
export async function listBloodhoundIngests() {
  await ensureVigilanteConfig();
  const bloodhoundDir = getVigilanteBloodhoundDir();

  try {
    const files = await fs.readdir(bloodhoundDir);
    const records = [];
    for (const f of files) {
      if (f.endsWith('.json')) {
        const p = path.join(bloodhoundDir, f);
        try {
          const raw = await fs.readFile(p, 'utf8');
          const data = JSON.parse(raw);
          records.push({
            id: data.id,
            timestamp: data.timestamp,
            stats: data.stats,
            filePath: p
          });
        } catch {
          // Skip corrupt file
        }
      }
    }
    return records.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  } catch (err) {
    logger.warn('BLOODHOUND', `Failed to list BloodHound ingests: ${err.message}`);
    return [];
  }
}
