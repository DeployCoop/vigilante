import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { getVigilanteCtiDir, ensureVigilanteConfig, loadConfig } from './config.js';
import { parseStixBundle, extractIocFromPattern } from './stixmisp.js';
import { logger } from '../utils/logger.js';

/**
 * OpenCTI threat-intelligence integration (opencti-platform/opencti).
 *
 * Read-first GraphQL client for a self-hosted OpenCTI instance, plus
 * explicit write-back (indicator / observable / relationship creation and
 * STIX-bundle push). The platform is STIX 2.1-native; every query goes to
 * `<url>/graphql` with `Authorization: Bearer <token>`.
 *
 * Credentials: the token is read from `options.token`, `$OPENCTI_TOKEN`, or
 * `opencti.token` in config.yaml (same precedence the LLM engines use for
 * provider keys) — never from argv, never logged. The URL resolves from
 * `options.url`, `$OPENCTI_URL`, `opencti.url` in config.yaml, or
 * `http://localhost:8080`. TLS verification is on by default: Node's fetch
 * verifies the server certificate; there is no insecure-skip option.
 * Deployments behind mkcert TLS need the CA in the system store or
 * `NODE_EXTRA_CA_CERTS` at process start.
 *
 * No live OpenCTI instance exists in this sandbox, so every function here
 * is verified against a local mock GraphQL server (tests/test-opencti.js).
 * Filter keys and mutation shapes follow OpenCTI 7.x's published schema
 * (indicators / stixCyberObservables / stixCoreRelationships queries,
 * indicatorAdd / stixCyberObservableAdd / stixCoreRelationshipAdd
 * mutations); pointing this at a real instance is the operator's step.
 */

export const DEFAULT_OPENCTI_URL = 'http://localhost:8080';
export const DEFAULT_OPENCTI_TIMEOUT_MS = 30000;
export const OPENCTI_CACHE_FILE = 'opencti_indicators.json';
export const OPENCTI_MAX_SYNC_PAGES = 10;
export const OPENCTI_PAGE_SIZE = 100;

const ME_QUERY = `query { me { id name user_email } }`;

const OBSERVABLES_QUERY = `query OpenCtiLookup($filters: FilterGroup, $first: Int) {
  stixCyberObservables(filters: $filters, first: $first) {
    edges {
      node {
        id
        entity_type
        observable_value
        x_opencti_score
        indicators {
          edges {
            node {
              id
              name
              pattern
              pattern_type
              x_opencti_score
              valid_from
              valid_until
              revoked
              confidence
              labels { edges { node { value } } }
              killChainPhases { edges { node { kill_chain_name phase_name } } }
            }
          }
        }
      }
    }
  }
}`;

const INDICATORS_QUERY = `query OpenCtiIndicators($first: Int, $after: ID, $orderBy: IndicatorsOrdering, $orderMode: OrderingMode, $filters: FilterGroup, $toStix: Boolean) {
  indicators(first: $first, after: $after, orderBy: $orderBy, orderMode: $orderMode, filters: $filters, toStix: $toStix) {
    edges {
      node {
        id
        name
        pattern
        pattern_type
        x_opencti_score
        valid_from
        valid_until
        revoked
        confidence
        created
        modified
        labels { edges { node { value } } }
        killChainPhases { edges { node { kill_chain_name phase_name } } }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}`;

/**
 * Resolve the OpenCTI connection config. The token is never logged.
 * @param {Object} [options]
 * @returns {{url: string, graphqlUrl: string, token: string|null, timeoutMs: number, configured: boolean}}
 */
export function resolveOpenCtiConfig(options = {}) {
  let cfg = {};
  try {
    cfg = loadConfig() || {};
  } catch {
    cfg = {};
  }
  const url = (options.url || process.env.OPENCTI_URL || cfg.opencti?.url || DEFAULT_OPENCTI_URL).replace(/\/+$/, '');
  const token = options.token || process.env.OPENCTI_TOKEN || cfg.opencti?.token || null;
  const envTimeout = process.env.OPENCTI_TIMEOUT_MS ? Number(process.env.OPENCTI_TIMEOUT_MS) : null;
  const timeoutMs = options.timeoutMs ?? envTimeout ?? DEFAULT_OPENCTI_TIMEOUT_MS;
  return {
    url,
    graphqlUrl: `${url}/graphql`,
    token,
    timeoutMs: Number.isFinite(timeoutMs) && timeoutMs > 0 ? timeoutMs : DEFAULT_OPENCTI_TIMEOUT_MS,
    configured: Boolean(token)
  };
}

/**
 * POST one GraphQL operation to the OpenCTI instance. Fails closed: a
 * missing token, a non-2xx status, an unparseable body, or a GraphQL
 * `errors` array all throw — a lookup never reports "not found" because
 * the request itself failed.
 */
export async function openCtiGraphQL({ url, token, query, variables = {}, timeoutMs = DEFAULT_OPENCTI_TIMEOUT_MS, signal = null } = {}) {
  const cfg = resolveOpenCtiConfig({ url, token, timeoutMs });
  if (!cfg.token) {
    throw new Error('OpenCTI token is not configured. Set $OPENCTI_TOKEN or opencti.token in config.yaml');
  }
  // A caller-provided signal is honored as-is; otherwise the request aborts
  // after timeoutMs instead of hanging forever on a stalled instance.
  const effectiveSignal = signal ?? AbortSignal.timeout(cfg.timeoutMs);

  const response = await fetch(cfg.graphqlUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${cfg.token}`
    },
    signal: effectiveSignal,
    body: JSON.stringify({ query, variables })
  });

  if (!response.ok) {
    const errBody = await response.text().catch(() => '');
    throw new Error(`OpenCTI API error (${response.status}): ${errBody || response.statusText}`);
  }

  const data = await response.json().catch(() => null);
  if (!data || typeof data !== 'object') {
    throw new Error('OpenCTI API error: unparseable response body');
  }
  if (Array.isArray(data.errors) && data.errors.length > 0) {
    throw new Error(`OpenCTI GraphQL error: ${data.errors[0]?.message || 'unknown error'}`);
  }
  return data.data || {};
}

/**
 * Probe the instance: proves the URL is reachable and the token is valid.
 * Returns a status object instead of throwing so CLI/MCP/web callers can
 * render "not connected" honestly.
 */
export async function checkOpenCtiConnection(options = {}) {
  const cfg = resolveOpenCtiConfig(options);
  if (!cfg.configured) {
    return { ok: false, connected: false, url: cfg.url, error: 'OpenCTI token is not configured. Set $OPENCTI_TOKEN or opencti.token in config.yaml' };
  }
  try {
    const data = await openCtiGraphQL({ ...cfg, query: ME_QUERY });
    const user = data?.me || null;
    if (!user?.id) {
      return { ok: false, connected: false, url: cfg.url, error: 'OpenCTI returned no authenticated user' };
    }
    return { ok: true, connected: true, url: cfg.url, user: { id: user.id, name: user.name || null, email: user.user_email || null } };
  } catch (err) {
    return { ok: false, connected: false, url: cfg.url, error: err?.message || String(err) };
  }
}

/**
 * Classify a raw observable value (IP / domain / URL / hash).
 * @returns {'ipv4'|'ipv6'|'domain'|'url'|'sha256'|'sha1'|'md5'|'unknown'}
 */
export function detectObservableType(value = '') {
  const v = String(value).trim();
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(v)) return 'ipv4';
  if (/^[0-9a-fA-F:]+:+[0-9a-fA-F:]+$/.test(v)) return 'ipv6';
  if (/^https?:\/\/\S+$/i.test(v)) return 'url';
  if (/^[0-9a-fA-F]{64}$/.test(v)) return 'sha256';
  if (/^[0-9a-fA-F]{40}$/.test(v)) return 'sha1';
  if (/^[0-9a-fA-F]{32}$/.test(v)) return 'md5';
  if (/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) return 'domain';
  return 'unknown';
}

/**
 * Normalize one OpenCTI indicator node into vigilante's indicator shape.
 */
export function normalizeOpenCtiIndicator(node = {}) {
  const extracted = extractIocFromPattern(node.pattern || '');
  return {
    id: node.id || null,
    name: node.name || null,
    pattern: node.pattern || null,
    patternType: node.pattern_type || 'stix',
    score: typeof node.x_opencti_score === 'number' ? node.x_opencti_score : null,
    confidence: typeof node.confidence === 'number' ? node.confidence : null,
    validFrom: node.valid_from || null,
    validUntil: node.valid_until || null,
    revoked: node.revoked === true,
    created: node.created || null,
    modified: node.modified || null,
    labels: (node.labels?.edges || []).map((e) => e?.node?.value).filter(Boolean),
    killChainPhases: (node.killChainPhases?.edges || []).map((e) => ({
      killChainName: e?.node?.kill_chain_name || null,
      phaseName: e?.node?.phase_name || null
    })).filter((p) => p.killChainName || p.phaseName),
    iocType: extracted.type,
    iocValue: extracted.value
  };
}

function buildIndicatorFilters({ since = null } = {}) {
  const filters = [
    { key: 'revoked', values: ['false'], operator: 'eq' },
    { key: 'pattern_type', values: ['stix'], operator: 'eq' }
  ];
  if (since) {
    filters.push({ key: 'modified', values: [since], operator: 'gt' });
  }
  return { mode: 'and', filters, filterGroups: [] };
}

/**
 * List indicators from the instance, paginating until the cursor ends or
 * maxPages is reached (bounded so a huge instance cannot loop forever).
 * @param {Object} [options] {since, first, maxPages, url, token, timeoutMs}
 * @returns {Promise<{indicators: Array, count: number, hasMore: boolean}>}
 */
export async function listOpenCtiIndicators(options = {}) {
  const cfg = resolveOpenCtiConfig(options);
  const first = options.first || OPENCTI_PAGE_SIZE;
  const maxPages = options.maxPages || OPENCTI_MAX_SYNC_PAGES;
  const filters = buildIndicatorFilters({ since: options.since || null });
  const indicators = [];
  let after = null;
  let hasMore = false;

  for (let page = 0; page < maxPages; page += 1) {
    const data = await openCtiGraphQL({
      ...cfg,
      query: INDICATORS_QUERY,
      variables: { first, after, orderBy: 'modified', orderMode: 'asc', filters, toStix: false }
    });
    const conn = data?.indicators || {};
    for (const edge of conn.edges || []) {
      if (edge?.node) indicators.push(normalizeOpenCtiIndicator(edge.node));
    }
    if (conn.pageInfo?.hasNextPage && conn.pageInfo?.endCursor) {
      after = conn.pageInfo.endCursor;
      hasMore = true;
    } else {
      hasMore = false;
      break;
    }
  }
  return { indicators, count: indicators.length, hasMore };
}

/**
 * Look one observable value up in OpenCTI: the observable record plus every
 * indicator that references it. Throws on transport/auth failure so a
 * lookup never silently reports "not found".
 */
export async function lookupOpenCtiObservable(value, options = {}) {
  const cfg = resolveOpenCtiConfig(options);
  const raw = String(value || '').trim();
  if (!raw) throw new Error('lookupOpenCtiObservable requires a value');
  const type = detectObservableType(raw);
  if (type === 'unknown') {
    throw new Error(`Cannot look up '${raw}': not a recognized IP, domain, URL, or hash`);
  }
  const data = await openCtiGraphQL({
    ...cfg,
    query: OBSERVABLES_QUERY,
    variables: {
      filters: {
        mode: 'and',
        filters: [{ key: 'observable_value', values: [raw], operator: 'eq' }],
        filterGroups: []
      },
      first: 10
    }
  });
  const observables = [];
  const indicators = [];
  for (const edge of data?.stixCyberObservables?.edges || []) {
    const node = edge?.node;
    if (!node) continue;
    observables.push({
      id: node.id || null,
      entityType: node.entity_type || null,
      observableValue: node.observable_value || null,
      score: typeof node.x_opencti_score === 'number' ? node.x_opencti_score : null
    });
    for (const indEdge of node.indicators?.edges || []) {
      if (indEdge?.node) indicators.push(normalizeOpenCtiIndicator(indEdge.node));
    }
  }
  return {
    value: raw,
    type,
    found: observables.length > 0 || indicators.length > 0,
    observables,
    indicators,
    checkedAt: new Date().toISOString()
  };
}

function getOpenCtiCachePath() {
  return path.join(getVigilanteCtiDir(), OPENCTI_CACHE_FILE);
}

/**
 * Read the synced indicator cache (written by syncOpenCtiIndicators).
 * Returns null when the cache is absent or corrupt — never throws.
 */
export function readOpenCtiIndicatorCache() {
  const cacheFile = getOpenCtiCachePath();
  try {
    if (!fsSync.existsSync(cacheFile)) return null;
    const parsed = JSON.parse(fsSync.readFileSync(cacheFile, 'utf8'));
    if (!parsed || !Array.isArray(parsed.indicators)) return null;
    return parsed;
  } catch (err) {
    logger.warn('OPENCTI', `Ignoring unreadable indicator cache ${cacheFile}: ${err?.message || err}`);
    return null;
  }
}

/**
 * Sync indicators from the instance into the local CTI cache dir (same dir
 * the Feodo/URLhaus caches live in), watermarked on the previous sync so
 * repeat runs only fetch what changed. Explicit action only — matching
 * never triggers a network sync.
 */
export async function syncOpenCtiIndicators(options = {}) {
  const cfg = resolveOpenCtiConfig(options);
  await ensureVigilanteConfig();
  const ctiDir = getVigilanteCtiDir();
  await fs.mkdir(ctiDir, { recursive: true });

  const previous = options.since ? null : readOpenCtiIndicatorCache();
  const since = options.since || previous?.syncedAt || null;
  const { indicators, count, hasMore } = await listOpenCtiIndicators({ ...cfg, since });

  // A watermarked sync returns only changed indicators; keep the previous
  // full set and merge by id so the cache stays complete.
  let merged = indicators;
  if (since && previous) {
    const byId = new Map(previous.indicators.map((i) => [i.id, i]));
    for (const ind of indicators) byId.set(ind.id, ind);
    merged = Array.from(byId.values());
  }

  const cache = {
    syncedAt: new Date().toISOString(),
    url: cfg.url,
    count: merged.length,
    indicators: merged
  };
  await fs.writeFile(getOpenCtiCachePath(), JSON.stringify(cache, null, 2), 'utf8');
  logger.info('OPENCTI', `Synced ${count} indicator(s) from ${cfg.url} (cache now holds ${merged.length})`);
  return { ok: true, synced: count, count: merged.length, hasMore, file: getOpenCtiCachePath(), syncedAt: cache.syncedAt, url: cfg.url };
}

/**
 * Match raw values against the synced OpenCTI cache (offline — no network).
 * Returns match objects in the same shape matchCtiIndicators produces.
 */
export function matchOpenCtiIndicators(values = [], options = {}) {
  const cache = options.cache || readOpenCtiIndicatorCache();
  if (!cache) return [];
  const byValue = new Map();
  for (const ind of cache.indicators) {
    if (!ind?.iocValue) continue;
    const key = String(ind.iocValue).toLowerCase();
    if (!byValue.has(key)) byValue.set(key, ind);
  }
  const matches = [];
  const list = Array.isArray(values) ? values : [values];
  for (const raw of list) {
    const str = String(raw || '').trim();
    if (!str) continue;
    const hit = byValue.get(str.toLowerCase());
    if (!hit) continue;
    const score = typeof hit.score === 'number' ? hit.score : null;
    matches.push({
      indicator: str,
      value: str,
      type: `OPENCTI_${String(hit.iocType || 'indicator').toUpperCase()}`,
      source: 'OpenCTI',
      threat: hit.name || `OpenCTI indicator ${hit.id || ''}`.trim(),
      severity: score === null ? 'MEDIUM' : score >= 80 ? 'CRITICAL' : score >= 50 ? 'HIGH' : 'MEDIUM',
      openctiId: hit.id || null,
      score
    });
  }
  return matches;
}

// ---------------------------------------------------------------------------
// Write-back (slice 2): explicit actions only, never inside a sync loop.
// ---------------------------------------------------------------------------

/**
 * Build a STIX 2.1 pattern from a raw value and its observable type.
 * Throws on an unrecognized type or a malformed value — a push never
 * sends a pattern OpenCTI cannot parse.
 */
export function buildStixPattern(value, type) {
  const v = String(value || '').trim();
  const t = String(type || '').toLowerCase();
  if (!v) throw new Error('buildStixPattern requires a value');
  if (t === 'ipv4') {
    // Four dot-separated octets, each 0-255 (three digits alone is not
    // enough: 999.999.999.999 matches a naive \d{1,3} pattern).
    const octets = v.split('.');
    const valid = octets.length === 4 && octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255);
    if (!valid) throw new Error(`Invalid IPv4 value '${v}'`);
    return `[ipv4-addr:value = '${v}']`;
  }
  if (t === 'ipv6') {
    if (!/^[0-9a-fA-F:]+:+[0-9a-fA-F:]+$/.test(v)) throw new Error(`Invalid IPv6 value '${v}'`);
    return `[ipv6-addr:value = '${v}']`;
  }
  if (t === 'domain') {
    if (!/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(v)) throw new Error(`Invalid domain value '${v}'`);
    return `[domain-name:value = '${v}']`;
  }
  if (t === 'url') {
    if (!/^https?:\/\/\S+$/i.test(v)) throw new Error(`Invalid URL value '${v}'`);
    return `[url:value = '${v}']`;
  }
  if (t === 'sha256' || t === 'sha1' || t === 'md5') {
    const lengths = { sha256: 64, sha1: 40, md5: 32 };
    // STIX spells the algorithms with a hyphen (SHA-256, SHA-1) — the same
    // spelling extractIocFromPattern in stixmisp.js parses back.
    const labels = { sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' };
    if (!new RegExp(`^[0-9a-fA-F]{${lengths[t]}}$`).test(v)) throw new Error(`Invalid ${labels[t]} value '${v}'`);
    return `[file:hashes.'${labels[t]}' = '${v}']`;
  }
  throw new Error(`Unsupported observable type '${type}' (expected ipv4, ipv6, domain, url, sha256, sha1, md5)`);
}

function observableAddArg(type) {
  // OpenCTI's stixCyberObservableAdd takes the observable type plus a
  // per-type input object; the argument names below are the schema's.
  switch (type) {
    case 'ipv4': return 'IPv4Addr';
    case 'ipv6': return 'IPv6Addr';
    case 'domain': return 'DomainName';
    case 'url': return 'Url';
    case 'sha256':
    case 'sha1':
    case 'md5': return 'StixFile';
    default: throw new Error(`Unsupported observable type '${type}'`);
  }
}

/**
 * Create one indicator in OpenCTI. Give either a full STIX `pattern` or a
 * `value` + `type` (the pattern is built for you). Returns the created
 * indicator, normalized.
 */
export async function createOpenCtiIndicator({ value = null, type = null, pattern = null, name = null, description = null, score = null, validFrom = null, validUntil = null, ...options } = {}) {
  const cfg = resolveOpenCtiConfig(options);
  const finalPattern = pattern || (value && type ? buildStixPattern(value, type) : null);
  if (!finalPattern) {
    throw new Error('createOpenCtiIndicator requires a STIX pattern or a value + type');
  }
  const input = {
    pattern_type: 'stix',
    pattern_version: '2.1',
    pattern: finalPattern,
    name: name || (value ? `${type || 'indicator'} ${value}` : 'Vigilante indicator'),
    description: description || null,
    x_opencti_score: typeof score === 'number' ? score : null,
    valid_from: validFrom || new Date().toISOString(),
    valid_until: validUntil || null
  };
  const mutation = `mutation OpenCtiIndicatorAdd($input: IndicatorAddInput!) {
    indicatorAdd(input: $input) {
      id name pattern pattern_type x_opencti_score valid_from valid_until revoked confidence
    }
  }`;
  const data = await openCtiGraphQL({ ...cfg, query: mutation, variables: { input } });
  if (!data?.indicatorAdd) throw new Error('OpenCTI indicatorAdd returned no indicator');
  return normalizeOpenCtiIndicator(data.indicatorAdd);
}

/**
 * Create one observable (a fact, no detection semantics) in OpenCTI.
 */
export async function createOpenCtiObservable({ value, type, score = null, description = null, ...options } = {}) {
  const cfg = resolveOpenCtiConfig(options);
  const raw = String(value || '').trim();
  const t = String(type || '').toLowerCase();
  if (!raw) throw new Error('createOpenCtiObservable requires a value');
  const arg = observableAddArg(t);
  const typeLabel = { ipv4: 'IPv4-Addr', ipv6: 'IPv6-Addr', domain: 'Domain-Name', url: 'Url', sha256: 'StixFile', sha1: 'StixFile', md5: 'StixFile' }[t];
  let typedInput;
  if (t === 'sha256' || t === 'sha1' || t === 'md5') {
    // STIX algorithm spelling: SHA-256, SHA-1, MD5.
    const labels = { sha256: 'SHA-256', sha1: 'SHA-1', md5: 'MD5' };
    typedInput = { hashes: [{ algorithm: labels[t], hash: raw }], name: description || raw };
  } else {
    typedInput = { value: raw };
  }
  // Inline the typed input (JSON-escaped) so the request never depends on
  // the exact generated input-type name for the per-type argument.
  const mutation = `mutation {
    stixCyberObservableAdd(type: ${JSON.stringify(typeLabel)}, ${arg}: ${JSON.stringify(typedInput)}, x_opencti_score: ${typeof score === 'number' ? score : 50}) {
      id entity_type observable_value x_opencti_score
    }
  }`;
  const data = await openCtiGraphQL({ ...cfg, query: mutation, variables: {} });
  const node = data?.stixCyberObservableAdd;
  if (!node?.id) throw new Error('OpenCTI stixCyberObservableAdd returned no observable');
  return { id: node.id, entityType: node.entity_type || null, observableValue: node.observable_value || raw, score: typeof node.x_opencti_score === 'number' ? node.x_opencti_score : null };
}

/**
 * Relate two OpenCTI entities by their internal IDs (e.g. an indicator
 * `indicates` a malware object). Both IDs must already exist in OpenCTI.
 */
export async function createOpenCtiRelationship({ fromId, toId, relationshipType, description = null, startTime = null, stopTime = null, ...options } = {}) {
  const cfg = resolveOpenCtiConfig(options);
  if (!fromId || !toId) throw new Error('createOpenCtiRelationship requires fromId and toId');
  if (!relationshipType) throw new Error('createOpenCtiRelationship requires a relationshipType (e.g. indicates)');
  const input = {
    fromId,
    toId,
    relationship_type: relationshipType,
    description: description || null,
    start_time: startTime || null,
    stop_time: stopTime || null
  };
  const mutation = `mutation OpenCtiRelationshipAdd($input: StixCoreRelationshipAddInput!) {
    stixCoreRelationshipAdd(input: $input) {
      id relationship_type description start_time stop_time
    }
  }`;
  const data = await openCtiGraphQL({ ...cfg, query: mutation, variables: { input } });
  const node = data?.stixCoreRelationshipAdd;
  if (!node?.id) throw new Error('OpenCTI stixCoreRelationshipAdd returned no relationship');
  return { id: node.id, relationshipType: node.relationship_type || relationshipType, description: node.description || description, startTime: node.start_time || startTime, stopTime: node.stop_time || stopTime };
}

/**
 * Push a local STIX 2.1 bundle into OpenCTI: indicators become indicators,
 * cyber-observables (ipv4-addr / domain-name / url / file) become
 * observables. Relationships are counted as skipped — they reference STIX
 * IDs, and OpenCTI relationships need internal IDs, which requires a
 * separate resolution step. Per-object failures are collected, never fatal
 * to the rest of the bundle.
 */
export async function pushStixBundleToOpenCti(bundle, options = {}) {
  const cfg = resolveOpenCtiConfig(options);
  const parsed = parseStixBundle(bundle);
  const result = { pushed: { indicators: 0, observables: 0 }, skipped: { relationships: 0, other: 0 }, failures: [] };

  // parseStixBundle normalizes indicators (pattern, name, validFrom,
  // confidence) and groups the raw objects by type — there is no flat
  // `objects` array on the parsed result.
  for (const ind of parsed.indicators || []) {
    try {
      await createOpenCtiIndicator({
        ...cfg,
        pattern: ind.pattern,
        name: ind.name || null,
        score: typeof ind.confidence === 'number' ? ind.confidence : null,
        validFrom: ind.validFrom || null
      });
      result.pushed.indicators += 1;
    } catch (err) {
      result.failures.push({ id: ind.id || null, type: 'indicator', error: err?.message || String(err) });
    }
  }

  const observableTypes = { 'ipv4-addr': 'ipv4', 'ipv6-addr': 'ipv6', 'domain-name': 'domain', url: 'url', file: 'file' };
  let observableCount = 0;
  for (const [stixType, kind] of Object.entries(observableTypes)) {
    for (const obj of parsed.objectsByType?.[stixType] || []) {
      try {
        if (kind === 'file') {
          const hashes = obj.hashes || {};
          const algo = ['SHA-256', 'SHA-1', 'MD5'].find((a) => hashes[a]);
          if (!algo) { result.skipped.other += 1; continue; }
          await createOpenCtiObservable({ ...cfg, value: hashes[algo], type: algo.toLowerCase(), score: 50, description: obj.name || null });
        } else {
          await createOpenCtiObservable({ ...cfg, value: obj.value, type: kind, score: 50, description: obj.name || null });
        }
        result.pushed.observables += 1;
        observableCount += 1;
      } catch (err) {
        result.failures.push({ id: obj.id || null, type: stixType, error: err?.message || String(err) });
      }
    }
  }

  result.skipped.relationships = (parsed.relationships || []).length;
  const handled = (parsed.indicators?.length || 0) + observableCount + result.skipped.relationships;
  result.skipped.other = Math.max(0, (parsed.totalObjects || 0) - handled);
  result.ok = result.failures.length === 0;
  return result;
}
