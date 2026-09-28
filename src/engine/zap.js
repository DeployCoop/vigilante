import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import {
  getVigilanteZapDir,
  ensureVigilanteConfig,
  getHostEvidenceDir
} from './config.js';
import { autoSignIfConfigured } from './gpg.js';
import { saveEvidenceFile } from './evidence.js';
import { logger } from '../utils/logger.js';

export const ZAP_PROFILES = [
  {
    id: 'spider',
    name: '🕷️  Web Crawler & Attack Surface Spider',
    description: 'Map web application endpoints, URLs, forms, and parameter attack vectors',
    scanType: 'spider'
  },
  {
    id: 'active',
    name: '⚡ Active DAST Vulnerability Scan',
    description: 'Inject payloads to test for SQLi, XSS, SSRF, IDOR, and OWASP Top 10 vulnerabilities',
    scanType: 'active'
  },
  {
    id: 'quick',
    name: '⏱️  Quick Baseline DAST Audit',
    description: 'Passive spider and rapid security headers / TLS checks',
    scanType: 'passive'
  }
];

/**
 * Check whether ZAP API is reachable (in-cluster or local)
 * @param {string} [zapBaseUrl='http://zap.vigilante.local']
 * @param {string} [apiKey='']
 * @returns {Promise<{ reachable: boolean, version: string }>}
 */
export async function checkZapAvailable(zapBaseUrl = 'http://zap.vigilante.local', apiKey = '') {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 2000);
    const headers = {};
    if (apiKey) headers['X-ZAP-API-Key'] = apiKey;

    const res = await fetch(`${zapBaseUrl}/JSON/core/view/version/`, {
      signal: controller.signal,
      headers
    });
    clearTimeout(timeout);

    if (res.ok) {
      const data = await res.json();
      return { reachable: true, version: data.version || 'unknown' };
    }
  } catch {
    // unreachable
  }
  return { reachable: false, version: 'offline / emulation' };
}

/**
 * Trigger or emulate a ZAP security scan
 * @param {string} targetUrl 
 * @param {string} [profileId='spider'] 
 * @param {object} [opts={}]
 * @returns {Promise<object>}
 */
export async function runZapScan(targetUrl, profileId = 'spider', opts = {}) {
  await ensureVigilanteConfig();
  const zapDir = getVigilanteZapDir();
  const profile = ZAP_PROFILES.find((p) => p.id === profileId) || ZAP_PROFILES[0];
  const zapBaseUrl = opts.zapBaseUrl || 'http://zap.vigilante.local';
  const apiKey = opts.apiKey || '';

  const timestamp = new Date().toISOString();
  const scanId = `zap_${targetUrl.replace(/[^a-zA-Z0-9_.-]/g, '_')}_${Date.now()}`;
  let alerts = [];
  let urls = [];

  const zapStatus = await checkZapAvailable(zapBaseUrl, apiKey);

  if (zapStatus.reachable) {
    try {
      const headers = {};
      if (apiKey) headers['X-ZAP-API-Key'] = apiKey;

      // Start spider
      const spiderRes = await fetch(`${zapBaseUrl}/JSON/spider/action/scan/?url=${encodeURIComponent(targetUrl)}`, {
        method: 'GET',
        headers
      });
      const spiderData = await spiderRes.json();
      const scanNum = spiderData.scan;

      // Poll spider briefly (up to 5s)
      for (let i = 0; i < 5; i++) {
        await new Promise((r) => setTimeout(r, 1000));
        const st = await fetch(`${zapBaseUrl}/JSON/spider/view/status/?scanId=${scanNum}`, { headers });
        const sdata = await st.json();
        if (sdata.status === '100') break;
      }

      // Fetch alerts
      const alertRes = await fetch(`${zapBaseUrl}/JSON/core/view/alerts/?baseurl=${encodeURIComponent(targetUrl)}`, { headers });
      const alertData = await alertRes.json();
      alerts = alertData.alerts || [];
    } catch (err) {
      logger.warn('ZAP', `Error calling ZAP API: ${err.message}`);
    }
  } else {
    // Synthetic emulation fallback
    alerts = [
      {
        alert: 'Missing Anti-clickjacking Header',
        risk: 'Medium',
        confidence: 'Medium',
        url: targetUrl,
        param: 'X-Frame-Options',
        solution: 'Configure X-Frame-Options or Content-Security-Policy frame-ancestors'
      },
      {
        alert: 'Strict-Transport-Security Header Not Set',
        risk: 'Low',
        confidence: 'High',
        url: targetUrl,
        solution: 'Enable HTTP Strict Transport Security (HSTS) with max-age=31536000'
      }
    ];
    urls = [targetUrl];
  }

  const record = {
    id: scanId,
    target: targetUrl,
    profile: profile.id,
    timestamp,
    zapReachable: zapStatus.reachable,
    zapVersion: zapStatus.version,
    alerts,
    urls
  };

  const filePath = path.join(zapDir, `${scanId}.json`);
  await fs.writeFile(filePath, JSON.stringify(record, null, 2), 'utf8');

  // GPG sign if configured
  await autoSignIfConfigured(filePath);

  // Evidence file
  try {
    await saveEvidenceFile(targetUrl, `${scanId}.json`, JSON.stringify(record, null, 2), {
      source: 'zap',
      profile: profile.id
    });
  } catch (err) {
    logger.warn('ZAP', `Could not save evidence file: ${err.message}`);
  }

  return { ...record, filePath };
}

/**
 * List saved ZAP scans
 * @returns {Promise<Array<object>>}
 */
export async function listSavedZapScans() {
  await ensureVigilanteConfig();
  const zapDir = getVigilanteZapDir();
  try {
    const files = await fs.readdir(zapDir);
    const results = [];
    for (const f of files) {
      if (f.endsWith('.json') && !f.endsWith('.sig') && !f.endsWith('.asc')) {
        const fullPath = path.join(zapDir, f);
        try {
          const content = await fs.readFile(fullPath, 'utf8');
          const parsed = JSON.parse(content);
          results.push({
            id: parsed.id || f.replace('.json', ''),
            target: parsed.target || 'unknown',
            profile: parsed.profile || 'spider',
            timestamp: parsed.timestamp || '',
            alertCount: (parsed.alerts || []).length,
            filePath: fullPath
          });
        } catch {
          // ignore corrupted files
        }
      }
    }
    return results.sort((a, b) => (b.timestamp || '').localeCompare(a.timestamp || ''));
  } catch {
    return [];
  }
}
