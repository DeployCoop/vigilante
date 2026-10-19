import { NextResponse } from 'next/server';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  loadAuthzStore,
  decide,
  resolvePrincipalByToken,
  resolvePrincipalBySession,
  verifyPasswordOrToken
} from 'vigilante_lib/engine/authz.js';
import {
  getOidcConfig,
  verifyOidcToken
} from 'vigilante_lib/engine/authz-oidc.js';
import { getVigilanteAuditLogFile } from 'vigilante_lib/engine/config.js';
import { errorBody } from './envelope';

export const SESSION_COOKIE_NAME = 'vigilante_session';
export const AUDIT_GENERATIONS = 3;

export const REASON_MESSAGES = {
  allow_disabled: 'Authorization is disabled',
  allow_local_board: 'Local board (bootstrap loopback)',
  allow_role_default: 'Allowed by role default',
  allow_explicit_grant: 'Allowed by explicit grant',
  allow_owner: 'Allowed (owner)',
  deny_unauthenticated: 'Authentication required',
  deny_unknown_principal: 'Identity is not provisioned as a principal',
  deny_disabled_principal: 'Principal is disabled',
  deny_missing_grant: 'Missing required permission',
  deny_scope: 'Permission grant does not cover this resource',
  deny_context: 'Grant is not valid for this request context (time window, source, or sign-in method)',
  deny_revoked: 'Permission has been revoked for this principal',
  deny_invalid_store: 'Authorization store is invalid'
};

export class AuthzError extends Error {
  status: number;
  reason: string;

  constructor(reason: string) {
    super(REASON_MESSAGES[reason as keyof typeof REASON_MESSAGES] || 'Access denied');
    this.name = 'AuthzError';
    this.reason = reason;
    this.status = reason === 'deny_unauthenticated' || reason === 'deny_unknown_principal' ? 401 : 403;
  }
}

export interface PublicPrincipal {
  id: string;
  name: string;
  kind: string;
  role: string;
  oidcSubject?: string;
  disabled: boolean;
  grants: any[];
  revocations: string[];
  hasToken: boolean;
}

export interface AuthzContext {
  loaded: any;
  principal: any | null;
  unknownPrincipal: boolean;
  localBoard: boolean;
  authMethod: 'session' | 'token' | 'oidc' | 'bootstrap' | null;
  expiredSession: boolean;
}

export const BOOTSTRAP_OWNER_PRINCIPAL = {
  id: 'bootstrap-owner',
  name: 'Bootstrap Owner (VIGILANTE_API_TOKEN)',
  kind: 'service',
  role: 'owner',
  disabled: false,
  grants: [],
  revocations: [],
  hasToken: true
};

let warnedBootstrapToken = false;

/**
 * Extract token from request headers (Authorization: Bearer <t> or x-vigilante-token: <t>)
 */
export function extractRequestToken(req: Request): string | null {
  const custom = req.headers.get('x-vigilante-token');
  if (custom && custom.trim() !== '') return custom.trim();
  const auth = req.headers.get('authorization');
  if (auth && auth.startsWith('Bearer ')) {
    const token = auth.substring(7).trim();
    if (token !== '') return token;
  }
  return null;
}

/**
 * Extract session token from httpOnly cookie
 */
export function extractSessionId(req: Request): string | null {
  const cookieHeader = req.headers.get('cookie');
  if (!cookieHeader) return null;
  const match = cookieHeader.match(new RegExp(`(?:^|;\\s*)${SESSION_COOKIE_NAME}=([^;]+)`));
  if (!match || !match[1]) return null;
  try {
    const decoded = decodeURIComponent(match[1]).trim();
    return decoded !== '' ? decoded : null;
  } catch {
    return null;
  }
}

/**
 * Check if request originated from loopback interface
 */
export function isLocalBoardRequest(req: Request): boolean {
  if (req.headers.get('x-forwarded-for') && process.env.VIGILANTE_TRUST_PROXY !== '1') {
    return false;
  }
  let hostname = '';
  try {
    hostname = new URL(req.url).hostname;
  } catch {
    const host = req.headers.get('host') || '';
    hostname = host.replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  }
  hostname = hostname.toLowerCase();
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1';
}

function timingSafeEqual(a: string, b: string): boolean {
  try {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) return false;
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

/**
 * Resolves request caller identity
 */
export async function resolveAuthzContext(req: Request): Promise<AuthzContext> {
  const loaded = loadAuthzStore();
  const localBoard = isLocalBoardRequest(req);
  const base: AuthzContext = {
    loaded,
    principal: null,
    unknownPrincipal: false,
    localBoard,
    authMethod: null,
    expiredSession: false
  };

  if (loaded.state !== 'ready' || !loaded.store) {
    return base;
  }

  // 1. Browser session cookie
  const sessionId = extractSessionId(req);
  if (sessionId) {
    const res = resolvePrincipalBySession(loaded.store, sessionId);
    if (res.expired) {
      return { ...base, expiredSession: true };
    }
    if (res.principal) {
      return { ...base, principal: res.principal, authMethod: 'session' };
    }
  }

  // 2. Token header
  const token = extractRequestToken(req);
  if (!token) return base;

  const byToken = resolvePrincipalByToken(loaded.store, token);
  if (byToken) {
    return { ...base, principal: byToken, authMethod: 'token' };
  }

  // 3. Static bootstrap token (VIGILANTE_API_TOKEN)
  const legacyToken = process.env.VIGILANTE_API_TOKEN;
  if (legacyToken && timingSafeEqual(token, legacyToken)) {
    if (!warnedBootstrapToken) {
      warnedBootstrapToken = true;
      console.warn(
        '[authz] VIGILANTE_API_TOKEN was used as a bootstrap owner credential. Migrate to a store principal (`vigilante authz add`).'
      );
    }
    return { ...base, principal: BOOTSTRAP_OWNER_PRINCIPAL, authMethod: 'bootstrap' };
  }

  // 4. OIDC JWT Bearer
  const oidc = getOidcConfig();
  if (oidc && token.split('.').length === 3) {
    const verified = await verifyOidcToken(token, loaded.store);
    if (verified) {
      return { ...base, principal: verified, authMethod: 'oidc' };
    }
    return { ...base, unknownPrincipal: true, authMethod: 'oidc' };
  }

  return base;
}

// ---------------------------------------------------------------------------
// Audit logging
// ---------------------------------------------------------------------------

export interface AuditEntry {
  ts: string;
  principalId: string | null;
  permission?: string;
  target?: any;
  allowed?: boolean;
  reason?: string;
  route: string;
  event?: string;
}

const READ_PERMISSIONS = new Set([
  'cluster:read',
  'modules:read',
  'scans:read',
  'telemetry:read',
  'forensics:read',
  'ctf:read'
]);

export function auditMaxBytes(): number {
  const raw = Number(process.env.VIGILANTE_AUDIT_MAX_BYTES);
  return Number.isFinite(raw) && raw > 0 ? Math.floor(raw) : 5 * 1024 * 1024;
}

export function rotateAuditIfNeeded(
  file: string,
  incomingBytes: number,
  maxBytes: number = auditMaxBytes(),
  generations: number = AUDIT_GENERATIONS
): void {
  try {
    let size = 0;
    try {
      size = fs.statSync(file).size;
    } catch {
      return;
    }
    if (size + incomingBytes <= maxBytes) return;
    for (let i = generations; i >= 2; i--) {
      try {
        fs.renameSync(`${file}.${i - 1}`, `${file}.${i}`);
      } catch {
        // file absent
      }
    }
    fs.renameSync(file, `${file}.1`);
  } catch {
    // ignore rotation errors
  }
}

function shouldAudit(permission: string, decision: any): boolean {
  if (decision.reason === 'allow_disabled') return false;
  return !decision.allowed || !READ_PERMISSIONS.has(permission);
}

export function recordAudit(
  req: Request,
  permission: string,
  decision: any,
  target?: any
): void {
  try {
    const file = getVigilanteAuditLogFile();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    let route = '';
    try {
      route = new URL(req.url).pathname;
    } catch {
      route = '';
    }
    const entry: AuditEntry = {
      ts: new Date().toISOString(),
      principalId: decision.principalId ?? null,
      permission,
      ...(target ? { target } : {}),
      allowed: decision.allowed,
      reason: decision.reason,
      route
    };
    const line = JSON.stringify(entry) + '\n';
    rotateAuditIfNeeded(file, Buffer.byteLength(line));
    fs.appendFileSync(file, line);
  } catch (err) {
    console.error('[authz] failed to record audit:', err);
  }
}

export function recordAuthEvent(req: Request, event: string, principalId: string | null): void {
  try {
    const file = getVigilanteAuditLogFile();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    let route = '';
    try {
      route = new URL(req.url).pathname;
    } catch {
      route = '';
    }
    const entry: AuditEntry = {
      ts: new Date().toISOString(),
      principalId,
      route,
      event
    };
    const line = JSON.stringify(entry) + '\n';
    rotateAuditIfNeeded(file, Buffer.byteLength(line));
    fs.appendFileSync(file, line);
  } catch (err) {
    console.error('[authz] failed to record auth event:', err);
  }
}

export function readAuditEntries(limit = 200): AuditEntry[] {
  try {
    const base = getVigilanteAuditLogFile();
    const lines: string[] = [];
    for (let i = AUDIT_GENERATIONS; i >= 1; i--) {
      try {
        lines.push(...fs.readFileSync(`${base}.${i}`, 'utf8').split('\n').filter(Boolean));
      } catch {
        // Generation absent
      }
    }
    try {
      lines.push(...fs.readFileSync(base, 'utf8').split('\n').filter(Boolean));
    } catch {
      // Base file absent
    }
    const entries: AuditEntry[] = [];
    for (const line of lines.slice(-limit)) {
      try {
        entries.push(JSON.parse(line));
      } catch {
        // Skip torn lines
      }
    }
    return entries.reverse();
  } catch {
    return [];
  }
}

// ---------------------------------------------------------------------------
// Route Guards
// ---------------------------------------------------------------------------

export async function checkPermission(
  req: Request,
  permission: string,
  target?: any
) {
  const ctx = await resolveAuthzContext(req);
  const opts = {
    isLoopback: ctx.localBoard,
    source: ctx.localBoard ? 'loopback' : 'any',
    authMethod: ctx.authMethod || 'any'
  };

  const decision = decide(ctx.loaded, ctx.principal, permission, target, opts);
  if (shouldAudit(permission, decision)) {
    recordAudit(req, permission, decision, target);
  }

  return {
    allowed: decision.allowed,
    status: decision.allowed ? 200 : new AuthzError(decision.reason).status,
    reason: decision.reason,
    decision,
    ctx
  };
}

export function authzErrorResponse(err: unknown): NextResponse | null {
  if (err instanceof AuthzError) {
    return NextResponse.json(
      errorBody(
        err.status === 401 ? 'unauthenticated' : 'forbidden',
        err.message,
        err.reason
      ),
      { status: err.status }
    );
  }
  return null;
}

export async function authorizeRequest(
  req: Request,
  permission: string,
  target?: any
): Promise<NextResponse | null> {
  const check = await checkPermission(req, permission, target);
  if (check.allowed) return null;
  return authzErrorResponse(new AuthzError(check.reason));
}

export async function requirePermission(
  req: Request,
  permission: string,
  target?: any
): Promise<{ principal: any | null; decision: any }> {
  const check = await checkPermission(req, permission, target);
  if (!check.allowed) throw new AuthzError(check.reason);
  return { principal: check.ctx.principal, decision: check.decision };
}

type RouteHandler<Ctx = unknown> = (req: Request, ctx: Ctx) => Promise<Response>;

export function withAuthz<Ctx = unknown>(
  permission: string,
  handler: RouteHandler<Ctx>,
  opts: { targetFromBody?: (body: any) => any | undefined } = {}
): RouteHandler<Ctx> {
  return async (req: Request, ctx: Ctx) => {
    let target: any = undefined;
    if (opts.targetFromBody && req.body) {
      try {
        const cloned = req.clone();
        const json = await cloned.json();
        target = opts.targetFromBody(json);
      } catch {
        // Ignore JSON parsing failure at guard stage
      }
    }
    const denied = await authorizeRequest(req, permission, target);
    if (denied) return denied;
    return handler(req, ctx);
  };
}
