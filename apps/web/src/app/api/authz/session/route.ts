import { NextResponse } from 'next/server';
import {
  loadAuthzStore,
  resolvePrincipalByToken,
  createSession,
  revokeSession,
  SESSION_TTL_MS
} from 'vigilante_lib/engine/authz.js';
import {
  SESSION_COOKIE_NAME,
  extractSessionId,
  recordAuthEvent,
  resolveAuthzContext,
  BOOTSTRAP_OWNER_PRINCIPAL
} from '@/lib/authz';
import { apiError } from '@/lib/route-error';

export const dynamic = 'force-dynamic';

const SESSION_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'strict' as const,
  path: '/',
  secure: false,
  maxAge: Math.floor(SESSION_TTL_MS / 1000)
};

/**
 * Token/Password -> session exchange
 */
export async function POST(req: Request) {
  const loaded = loadAuthzStore();
  if (loaded.state !== 'ready' || !loaded.store || loaded.store.principals.length === 0) {
    return apiError(409, 'Authorization is not initialized yet.', { reason: 'authz_not_enabled' });
  }
  const store = loaded.store;

  const ctx = await resolveAuthzContext(req);
  let who = ctx.principal && !ctx.principal.disabled ? ctx.principal : null;

  if (!who) {
    const body = await req.json().catch(() => ({}));
    const secret =
      typeof body?.token === 'string' && body.token.trim()
        ? body.token.trim()
        : typeof body?.password === 'string' && body.password.trim()
          ? body.password.trim()
          : null;

    if (secret) {
      const principal = resolvePrincipalByToken(store, secret);
      if (principal) {
        if (principal.disabled) return apiError(403, 'Principal is disabled', { reason: 'deny_disabled_principal' });
        who = principal;
      } else if (
        process.env.VIGILANTE_API_TOKEN &&
        secret === process.env.VIGILANTE_API_TOKEN
      ) {
        who = BOOTSTRAP_OWNER_PRINCIPAL;
      }
    }
  }

  if (!who) {
    return apiError(401, 'Invalid token or password', { reason: 'deny_unauthenticated' });
  }

  const { sessionToken } = await createSession(who.id);
  recordAuthEvent(req, 'session_created', who.id);

  const res = NextResponse.json({
    success: true,
    principal: { id: who.id, name: who.name, kind: who.kind, role: who.role }
  });
  res.cookies.set(SESSION_COOKIE_NAME, sessionToken, SESSION_COOKIE_OPTIONS);
  return res;
}

/**
 * Logout: revoke the presented session and clear the cookie
 */
export async function DELETE(req: Request) {
  const sessionId = extractSessionId(req);
  if (sessionId) {
    await revokeSession(sessionId);
    recordAuthEvent(req, 'session_revoked', null);
  }
  const res = NextResponse.json({ success: true, ok: true });
  res.cookies.set(SESSION_COOKIE_NAME, '', { ...SESSION_COOKIE_OPTIONS, maxAge: 0 });
  return res;
}
