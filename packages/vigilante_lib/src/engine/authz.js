import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import { load as yamlLoad, dump as yamlDump } from 'js-yaml';
import { z } from 'zod';
import { AbilityBuilder, createMongoAbility } from '@casl/ability';
import { getVigilanteAuthzFile } from './config.js';

export const PERMISSIONS = [
  'cluster:read',
  'cluster:write',
  'modules:read',
  'modules:deploy',
  'scans:read',
  'scans:run',
  'telemetry:read',
  'telemetry:write',
  'forensics:read',
  'forensics:run',
  'simulations:run',
  'ctf:read',
  'ctf:manage',
  'users:manage_permissions'
];

export const ROLES = ['owner', 'admin', 'operator', 'viewer', 'webhook'];
export const PRINCIPAL_KINDS = ['human', 'service'];

export const ROLE_PERMISSIONS = {
  owner: [...PERMISSIONS],
  admin: PERMISSIONS.filter(p => p !== 'users:manage_permissions'),
  operator: [
    'cluster:read',
    'modules:read',
    'modules:deploy',
    'scans:read',
    'scans:run',
    'telemetry:read',
    'telemetry:write',
    'forensics:read',
    'forensics:run',
    'simulations:run',
    'ctf:read',
    'ctf:manage'
  ],
  viewer: [
    'cluster:read',
    'modules:read',
    'scans:read',
    'telemetry:read',
    'forensics:read',
    'ctf:read'
  ],
  webhook: ['simulations:run', 'scans:run']
};

export const PERMISSION_SUBJECT = {
  'cluster:read': 'Cluster',
  'cluster:write': 'Cluster',
  'modules:read': 'Module',
  'modules:deploy': 'Module',
  'scans:read': 'Scan',
  'scans:run': 'Scan',
  'telemetry:read': 'Telemetry',
  'telemetry:write': 'Telemetry',
  'forensics:read': 'Forensics',
  'forensics:run': 'Forensics',
  'simulations:run': 'Simulation',
  'ctf:read': 'Ctf',
  'ctf:manage': 'Ctf',
  'users:manage_permissions': 'User'
};

export const TOKEN_PREFIX = 'vig_';
export const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours
export const MAX_SESSIONS_PER_PRINCIPAL = 10;
export const MIN_PASSWORD_LENGTH = 12;

export class AuthzInvariantError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AuthzInvariantError';
  }
}

export const GrantScopeSchema = z.object({
  moduleId: z.string().optional(),
  namespace: z.string().optional(),
  clusterName: z.string().optional()
}).strict();

export const GrantContextSchema = z.object({
  notBefore: z.string().datetime().optional(),
  notAfter: z.string().datetime().optional(),
  source: z.enum(['loopback', 'any']).optional(),
  authMethod: z.enum(['session', 'token', 'oidc', 'any']).optional()
}).strict();

export const GrantSchema = z.object({
  permission: z.enum(PERMISSIONS),
  scope: GrantScopeSchema.optional(),
  context: GrantContextSchema.optional()
});

export const PrincipalSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  kind: z.enum(PRINCIPAL_KINDS),
  role: z.enum(ROLES),
  tokenHash: z.string().optional(),
  oidcSubject: z.string().optional(),
  disabled: z.boolean().default(false),
  grants: z.array(GrantSchema).default([]),
  revocations: z.array(z.enum(PERMISSIONS)).default([]),
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime()
});

export const SessionSchema = z.object({
  idHash: z.string().min(1),
  principalId: z.string().min(1),
  createdAt: z.string().datetime(),
  expiresAt: z.string().datetime()
});

export const AuthzStoreSchema = z.object({
  version: z.literal(1),
  principals: z.array(PrincipalSchema).default([]),
  sessions: z.array(SessionSchema).default([])
});

/**
 * Generate a random API token
 */
export function generateToken() {
  return `${TOKEN_PREFIX}${crypto.randomBytes(32).toString('base64url')}`;
}

/**
 * Hash token using SHA-256
 */
export function hashToken(token) {
  return `sha256:${crypto.createHash('sha256').update(token).digest('hex')}`;
}

/**
 * Hash human-chosen password using scrypt
 */
export function hashPassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64);
  return `scrypt:${salt}:${derived.toString('hex')}`;
}

/**
 * Constant-time verification of password or token against stored tokenHash
 */
export function verifyPasswordOrToken(secret, tokenHash) {
  if (!secret || !tokenHash || typeof secret !== 'string' || typeof tokenHash !== 'string') {
    return false;
  }
  try {
    if (tokenHash.startsWith('sha256:')) {
      const computed = hashToken(secret);
      const a = Buffer.from(computed);
      const b = Buffer.from(tokenHash);
      if (a.length !== b.length) return false;
      return crypto.timingSafeEqual(a, b);
    }
    if (tokenHash.startsWith('scrypt:')) {
      const parts = tokenHash.split(':');
      if (parts.length !== 3) return false;
      const [, salt, expectedHashHex] = parts;
      const derived = crypto.scryptSync(secret, salt, 64);
      const a = Buffer.from(derived.toString('hex'));
      const b = Buffer.from(expectedHashHex);
      if (a.length !== b.length) return false;
      return crypto.timingSafeEqual(a, b);
    }
  } catch {
    return false;
  }
  return false;
}

/**
 * Resolve principal by API token or password with constant-time sweep
 */
export function resolvePrincipalByToken(store, rawSecret) {
  if (!rawSecret || !store || !Array.isArray(store.principals)) {
    return null;
  }
  let matched = null;
  for (const p of store.principals) {
    if (!p.tokenHash) continue;
    const ok = verifyPasswordOrToken(rawSecret, p.tokenHash);
    if (ok && !matched) {
      matched = p;
    }
  }
  return matched;
}

/**
 * In-memory cache for authz.yaml
 */
let cachedStore = null;
let cachedMtimeMs = 0;
let cachedSize = 0;
let cachedFilePath = '';

export function invalidateAuthzCache() {
  cachedStore = null;
  cachedMtimeMs = 0;
  cachedSize = 0;
  cachedFilePath = '';
}

/**
 * Load authz store from file.
 * Returns { state: 'disabled' | 'invalid' | 'ready', store?, error? }
 */
export function loadAuthzStore(filePath = getVigilanteAuthzFile(), { forceReload = false } = {}) {
  const envDisabled = process.env.VIGILANTE_AUTHZ === 'off' || process.env.VIGILANTE_AUTHZ === '0';
  if (envDisabled) {
    return { state: 'disabled', store: { version: 1, principals: [], sessions: [] } };
  }

  try {
    if (!fsSync.existsSync(filePath)) {
      invalidateAuthzCache();
      return { state: 'ready', store: { version: 1, principals: [], sessions: [] } };
    }

    const stats = fsSync.statSync(filePath);
    if (!forceReload && cachedStore && cachedFilePath === filePath && cachedMtimeMs === stats.mtimeMs && cachedSize === stats.size) {
      return { state: 'ready', store: cachedStore };
    }

    const raw = fsSync.readFileSync(filePath, 'utf8');
    const parsed = yamlLoad(raw);
    const validated = AuthzStoreSchema.parse(parsed || { version: 1, principals: [], sessions: [] });

    // Prune expired sessions in memory
    const now = Date.now();
    validated.sessions = validated.sessions.filter(s => new Date(s.expiresAt).getTime() > now);

    cachedStore = validated;
    cachedMtimeMs = stats.mtimeMs;
    cachedSize = stats.size;
    cachedFilePath = filePath;

    return { state: 'ready', store: validated };
  } catch (err) {
    invalidateAuthzCache();
    return { state: 'invalid', error: err.message };
  }
}


/**
 * Save authz store to file atomically with 0600 mode
 */
export async function saveAuthzStore(store, filePath = getVigilanteAuthzFile()) {
  const validated = AuthzStoreSchema.parse(store);
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });

  const now = Date.now();
  validated.sessions = validated.sessions.filter(s => new Date(s.expiresAt).getTime() > now);

  const tmpPath = `${filePath}.tmp.${crypto.randomBytes(6).toString('hex')}`;
  const yamlStr = yamlDump(validated, { indent: 2, lineWidth: -1 });

  await fs.writeFile(tmpPath, yamlStr, { encoding: 'utf8', mode: 0o600 });
  await fs.rename(tmpPath, filePath);
  await fs.chmod(filePath, 0o600);

  const stats = await fs.stat(filePath);
  cachedStore = validated;
  cachedMtimeMs = stats.mtimeMs;
  cachedFilePath = filePath;
}

/**
 * Ensure at least one active owner remains
 */
export function assertNotLastOwner(store, targetPrincipalId, actionDescription) {
  const activeOwners = (store.principals || []).filter(p => p.role === 'owner' && !p.disabled);
  if (activeOwners.length === 1 && activeOwners[0].id === targetPrincipalId) {
    throw new AuthzInvariantError(
      `Cannot ${actionDescription}: principal '${targetPrincipalId}' is the last active owner.`
    );
  }
}

/**
 * Create a new browser session for a principal
 */
export async function createSession(principalId, filePath = getVigilanteAuthzFile()) {
  const loaded = loadAuthzStore(filePath);
  if (loaded.state !== 'ready' || !loaded.store) {
    throw new Error('Authz store not ready to create session');
  }
  const store = loaded.store;
  const p = store.principals.find(x => x.id === principalId);
  if (!p) throw new Error(`Principal ${principalId} not found`);
  if (p.disabled) throw new Error(`Principal ${principalId} is disabled`);

  const rawSessionToken = `${TOKEN_PREFIX}sess_${crypto.randomBytes(32).toString('base64url')}`;
  const idHash = hashToken(rawSessionToken);

  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_TTL_MS);

  // Prune existing sessions for this principal to MAX_SESSIONS_PER_PRINCIPAL - 1
  const others = store.sessions.filter(s => s.principalId !== principalId);
  const mine = store.sessions
    .filter(s => s.principalId === principalId && new Date(s.expiresAt).getTime() > now.getTime())
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, MAX_SESSIONS_PER_PRINCIPAL - 1);

  mine.push({
    idHash,
    principalId,
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString()
  });

  store.sessions = [...others, ...mine];
  await saveAuthzStore(store, filePath);

  return { sessionToken: rawSessionToken, expiresAt };
}

/**
 * Resolve principal from raw session token
 */
export function resolvePrincipalBySession(store, rawSessionToken) {
  if (!rawSessionToken || !store || !Array.isArray(store.sessions)) {
    return { principal: null, expired: false };
  }
  const idHash = hashToken(rawSessionToken);
  const now = Date.now();

  const session = store.sessions.find(s => s.idHash === idHash);
  if (!session) {
    return { principal: null, expired: false };
  }

  if (new Date(session.expiresAt).getTime() <= now) {
    return { principal: null, expired: true, principalId: session.principalId };
  }

  const p = store.principals.find(x => x.id === session.principalId);
  return { principal: p || null, expired: false };
}

/**
 * Revoke a session token
 */
export async function revokeSession(rawSessionToken, filePath = getVigilanteAuthzFile()) {
  const loaded = loadAuthzStore(filePath);
  if (loaded.state !== 'ready' || !loaded.store) return;
  const idHash = hashToken(rawSessionToken);
  const before = loaded.store.sessions.length;
  loaded.store.sessions = loaded.store.sessions.filter(s => s.idHash !== idHash);
  if (loaded.store.sessions.length !== before) {
    await saveAuthzStore(loaded.store, filePath);
  }
}

/**
 * Convert internal principal to public representation
 */
export function toPublicPrincipal(p) {
  return {
    id: p.id,
    name: p.name,
    kind: p.kind,
    role: p.role,
    oidcSubject: p.oidcSubject,
    disabled: p.disabled,
    grants: p.grants || [],
    revocations: p.revocations || [],
    hasToken: Boolean(p.tokenHash),
    createdAt: p.createdAt,
    updatedAt: p.updatedAt
  };
}

/**
 * Initialize owner principal (first bootstrap)
 * @param {Object} options
 * @param {string} [options.name='Owner']
 * @param {string} [options.password] - Custom password; takes precedence over token
 * @param {string} [options.token] - Custom API token; a random one is generated when neither is given
 */
export async function initOwner({ name = 'Owner', password, token }, filePath = getVigilanteAuthzFile()) {
  const loaded = loadAuthzStore(filePath);
  if (loaded.state !== 'ready' || !loaded.store) {
    throw new Error('Authz store invalid or unreadable');
  }
  const store = loaded.store;
  if (store.principals.length > 0) {
    throw new AuthzInvariantError('Authz already initialized with existing principals.');
  }

  const id = `user_${crypto.randomBytes(6).toString('hex')}`;
  const now = new Date().toISOString();

  let secretToReturn = '';
  let tokenHash = '';
  let isCustomPassword = false;

  if (password && password.trim()) {
    tokenHash = hashPassword(password.trim());
    secretToReturn = password.trim();
    isCustomPassword = true;
  } else if (token && token.trim()) {
    secretToReturn = token.trim();
    tokenHash = hashToken(secretToReturn);
  } else {
    secretToReturn = generateToken();
    tokenHash = hashToken(secretToReturn);
  }

  const owner = {
    id,
    name,
    kind: 'human',
    role: 'owner',
    tokenHash,
    disabled: false,
    grants: [],
    revocations: [],
    createdAt: now,
    updatedAt: now
  };

  store.principals = [owner];
  await saveAuthzStore(store, filePath);

  return {
    principal: toPublicPrincipal(owner),
    secret: secretToReturn,
    isCustomPassword
  };
}

/**
 * Add a new principal
 */
export async function addPrincipal({ name, kind = 'human', role = 'viewer', oidcSubject, grants = [], revocations = [] }, filePath = getVigilanteAuthzFile()) {
  const loaded = loadAuthzStore(filePath);
  if (loaded.state !== 'ready' || !loaded.store) throw new Error('Authz store not ready');
  const store = loaded.store;

  const id = `${kind === 'service' ? 'svc' : 'user'}_${crypto.randomBytes(6).toString('hex')}`;
  const token = generateToken();
  const tokenHash = hashToken(token);
  const now = new Date().toISOString();

  const newP = {
    id,
    name,
    kind,
    role,
    tokenHash,
    oidcSubject: oidcSubject || undefined,
    disabled: false,
    grants,
    revocations,
    createdAt: now,
    updatedAt: now
  };

  store.principals.push(newP);
  await saveAuthzStore(store, filePath);

  return {
    principal: toPublicPrincipal(newP),
    token
  };
}

/**
 * Update a principal
 */
export async function updatePrincipal(id, patch, filePath = getVigilanteAuthzFile()) {
  const loaded = loadAuthzStore(filePath);
  if (loaded.state !== 'ready' || !loaded.store) throw new Error('Authz store not ready');
  const store = loaded.store;

  const p = store.principals.find(x => x.id === id);
  if (!p) throw new Error(`Principal ${id} not found`);

  if (patch.disabled === true) {
    assertNotLastOwner(store, id, 'disable principal');
  }
  if (patch.role && patch.role !== 'owner' && p.role === 'owner') {
    assertNotLastOwner(store, id, 'change role away from owner');
  }

  if (patch.name !== undefined) p.name = patch.name;
  if (patch.role !== undefined) p.role = patch.role;
  if (patch.disabled !== undefined) p.disabled = patch.disabled;
  if (patch.oidcSubject !== undefined) p.oidcSubject = patch.oidcSubject || undefined;
  if (patch.grants !== undefined) p.grants = patch.grants;
  if (patch.revocations !== undefined) p.revocations = patch.revocations;
  p.updatedAt = new Date().toISOString();

  await saveAuthzStore(store, filePath);
  return toPublicPrincipal(p);
}

/**
 * Remove a principal
 */
export async function removePrincipal(id, filePath = getVigilanteAuthzFile()) {
  const loaded = loadAuthzStore(filePath);
  if (loaded.state !== 'ready' || !loaded.store) throw new Error('Authz store not ready');
  const store = loaded.store;

  assertNotLastOwner(store, id, 'delete principal');

  const before = store.principals.length;
  store.principals = store.principals.filter(x => x.id !== id);
  store.sessions = store.sessions.filter(s => s.principalId !== id);

  if (store.principals.length === before) {
    throw new Error(`Principal ${id} not found`);
  }

  await saveAuthzStore(store, filePath);
}

/**
 * Rotate principal token or set password
 */
export async function rotatePrincipalToken(id, { password } = {}, filePath = getVigilanteAuthzFile()) {
  const loaded = loadAuthzStore(filePath);
  if (loaded.state !== 'ready' || !loaded.store) throw new Error('Authz store not ready');
  const store = loaded.store;

  const p = store.principals.find(x => x.id === id);
  if (!p) throw new Error(`Principal ${id} not found`);

  let secretToReturn = '';
  let tokenHash = '';
  let isCustomPassword = false;

  if (password && password.trim()) {
    tokenHash = hashPassword(password.trim());
    secretToReturn = password.trim();
    isCustomPassword = true;
  } else {
    secretToReturn = generateToken();
    tokenHash = hashToken(secretToReturn);
  }

  p.tokenHash = tokenHash;
  p.updatedAt = new Date().toISOString();

  // Invalidate existing sessions for this principal on credential rotation
  store.sessions = store.sessions.filter(s => s.principalId !== id);

  await saveAuthzStore(store, filePath);

  return { secret: secretToReturn, isCustomPassword };
}

/**
 * Build CASL MongoAbility for principal rules
 */
export function buildAbilityFor(principal) {
  const { can, cannot, build } = new AbilityBuilder(createMongoAbility);

  if (!principal || principal.disabled) {
    return build();
  }

  if (principal.role === 'owner') {
    can('manage', 'all');
  } else {
    // Role default permissions
    const defaults = ROLE_PERMISSIONS[principal.role] || [];
    for (const perm of defaults) {
      const subject = PERMISSION_SUBJECT[perm];
      const [, action] = perm.split(':');
      if (subject && action) {
        can(action, subject);
      }
    }
  }

  // Explicit grants
  if (Array.isArray(principal.grants)) {
    for (const grant of principal.grants) {
      const subject = PERMISSION_SUBJECT[grant.permission];
      const [, action] = grant.permission.split(':');
      if (!subject || !action) continue;

      if (grant.scope && Object.keys(grant.scope).length > 0) {
        can(action, subject, grant.scope);
      } else {
        can(action, subject);
      }
    }
  }

  // Explicit revocations
  if (Array.isArray(principal.revocations)) {
    for (const rev of principal.revocations) {
      const subject = PERMISSION_SUBJECT[rev];
      const [, action] = rev.split(':');
      if (subject && action) {
        cannot(action, subject);
      }
    }
  }

  return build();
}

/**
 * Check if request context satisfies grant context conditions
 */
export function matchesGrantContext(grantContext, reqContext = {}) {
  if (!grantContext) return true;
  const now = Date.now();

  if (grantContext.notBefore && new Date(grantContext.notBefore).getTime() > now) {
    return false;
  }
  if (grantContext.notAfter && new Date(grantContext.notAfter).getTime() < now) {
    return false;
  }
  if (grantContext.source && grantContext.source !== 'any') {
    if (grantContext.source === 'loopback' && reqContext.source !== 'loopback') {
      return false;
    }
  }
  if (grantContext.authMethod && grantContext.authMethod !== 'any') {
    if (grantContext.authMethod !== reqContext.authMethod) {
      return false;
    }
  }
  return true;
}

/**
 * Authoritative single decision function: decide(...)
 *
 * Evaluation order:
 * 1. Store disabled (VIGILANTE_AUTHZ=off/0) -> allow_disabled
 * 2. Store invalid -> deny_invalid_store (fail closed)
 * 3. Store empty & loopback caller -> allow_local_board (zero friction initial dev)
 * 4. Store empty & non-loopback -> deny_unauthenticated
 * 5. Unauthenticated / unknown principal -> deny_unauthenticated / deny_unknown_principal
 * 6. Disabled principal -> deny_disabled_principal
 * 7. Explicit revocation -> deny_revoked
 * 8. Owner role -> allow_owner
 * 9. Role default permissions -> allow_role_default
 * 10. Explicit grant with scope and context -> allow_explicit_grant (or deny_context/deny_scope)
 * 11. Fallback -> deny_missing_grant
 */
export function decide(loadedStore, principal, permission, target = {}, opts = {}) {
  const reqContext = {
    source: opts.source || 'any',
    authMethod: opts.authMethod || 'any',
    ...opts.context
  };

  // 1. Authz store disabled
  if (loadedStore.state === 'disabled') {
    return { allowed: true, reason: 'allow_disabled' };
  }

  // 2. Authz store corrupt / invalid -> Fail closed!
  if (loadedStore.state === 'invalid') {
    return { allowed: false, reason: 'deny_invalid_store' };
  }

  const store = loadedStore.store || { version: 1, principals: [], sessions: [] };
  const isEmpty = store.principals.length === 0;

  // 3 & 4. Uninitialized store
  if (isEmpty) {
    if (reqContext.source === 'loopback' || opts.isLoopback) {
      return { allowed: true, reason: 'allow_local_board' };
    }
    return { allowed: false, reason: 'deny_unauthenticated' };
  }

  // 5. Unauthenticated / unknown
  if (!principal) {
    return { allowed: false, reason: 'deny_unauthenticated' };
  }
  if (!store.principals.some(p => p.id === principal.id)) {
    return { allowed: false, reason: 'deny_unknown_principal' };
  }

  // 6. Disabled
  if (principal.disabled) {
    return { allowed: false, reason: 'deny_disabled_principal', principalId: principal.id };
  }

  // 7. Explicit revocations
  if (Array.isArray(principal.revocations) && principal.revocations.includes(permission)) {
    return { allowed: false, reason: 'deny_revoked', principalId: principal.id };
  }

  // 8. Owner role
  if (principal.role === 'owner') {
    return { allowed: true, reason: 'allow_owner', principalId: principal.id };
  }

  // Check CASL subject and action
  const subject = PERMISSION_SUBJECT[permission];
  const [, action] = permission.split(':');
  if (!subject || !action) {
    return { allowed: false, reason: 'deny_missing_grant', principalId: principal.id };
  }

  // 9. Role default permissions
  const defaults = ROLE_PERMISSIONS[principal.role] || [];
  if (defaults.includes(permission)) {
    return { allowed: true, reason: 'allow_role_default', principalId: principal.id };
  }

  // 10. Explicit grants
  if (Array.isArray(principal.grants)) {
    const matchingGrants = principal.grants.filter(g => g.permission === permission);
    for (const grant of matchingGrants) {
      if (!matchesGrantContext(grant.context, reqContext)) {
        return { allowed: false, reason: 'deny_context', principalId: principal.id };
      }

      if (grant.scope && Object.keys(grant.scope).length > 0) {
        let scopeMatches = true;
        for (const [k, v] of Object.entries(grant.scope)) {
          if (target[k] !== undefined && target[k] !== v) {
            scopeMatches = false;
            break;
          }
        }
        if (scopeMatches) {
          return { allowed: true, reason: 'allow_explicit_grant', principalId: principal.id };
        }
      } else {
        return { allowed: true, reason: 'allow_explicit_grant', principalId: principal.id };
      }
    }
  }

  return { allowed: false, reason: 'deny_missing_grant', principalId: principal.id };
}
