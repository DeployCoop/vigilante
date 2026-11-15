import { NextResponse } from 'next/server';
import {
  loadAuthzStore,
  resolvePrincipalByToken,
  createSession,
  revokeSession,
  syncLdapPrincipal,
  SESSION_TTL_MS
} from 'vigilante_lib/engine/authz.js';
import {
  resolveVigilanteLdapConfig,
  authenticateLdapUser
} from 'vigilante_lib/engine/authz-ldap.js';
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
 * OpenLDAP { username, password } or Token/Password -> session exchange
 */
export async function POST(req: Request) {
  const loaded = loadAuthzStore();
  if (loaded.state !== 'ready' || !loaded.store) {
    return apiError(409, 'Authorization is not initialized yet.', { reason: 'authz_not_enabled' });
  }
  const store = loaded.store;
  const ldapCfg = resolveVigilanteLdapConfig();

  const ctx = await resolveAuthzContext(req);
  let who = ctx.principal && !ctx.principal.disabled ? ctx.principal : null;
  let eventType = 'session_created';

  if (!who) {
    const body = await req.json().catch(() => ({}));
    const username =
      typeof body?.username === 'string' && body.username.trim()
        ? body.username.trim()
        : null;
    const password =
      typeof body?.password === 'string' && body.password.trim()
        ? body.password.trim()
        : null;

    // 1. OpenLDAP { username, password } flow
    if (username && password && (ldapCfg.enabled || body?.authMethod === 'ldap')) {
      const ldapRes = await authenticateLdapUser(username, password);
      if (ldapRes.ok) {
        try {
          const synced = await syncLdapPrincipal(ldapRes, {
            autoProvision: ldapCfg.autoProvisionPrincipals
          });
          if (!synced) {
            return apiError(403, 'OpenLDAP user is not provisioned in Vigilante.', {
              reason: 'deny_unknown_principal'
            });
          }
          who = synced;
          eventType = 'ldap_session_created';
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : 'Principal is disabled';
          return apiError(403, msg, { reason: 'deny_disabled_principal' });
        }
      } else if (
        ldapCfg.allowLocalBreakGlass &&
        (ldapRes.code === 'USER_NOT_FOUND' || ldapRes.code === 'LDAP_UNAVAILABLE')
      ) {
        // Fall through to the local token / break-glass flow below.
      } else {
        // Every other LDAP failure gets the same generic 401. The old
        // code returned the directory error verbatim — "User 'alice' was
        // not found in OpenLDAP directory" — which let anyone enumerate
        // directory users, and the ACCOUNT_LOCKED 403 leaked lock state
        // (and therefore existence) for any guessed username, no
        // password required. The detailed code stays server-side only.
        return apiError(401, 'Invalid username or password', {
          reason: 'deny_unauthenticated'
        });
      }
    }

    // 2. Local token or break-glass password flow
    if (!who) {
      if (store.principals.length === 0) {
        return apiError(409, 'Authorization is not initialized yet.', { reason: 'authz_not_enabled' });
      }

      const secret =
        typeof body?.token === 'string' && body.token.trim()
          ? body.token.trim()
          : password;

      if (secret) {
        const principal = resolvePrincipalByToken(store, secret);
        if (principal) {
          if (principal.disabled) {
            return apiError(403, 'Principal is disabled', { reason: 'deny_disabled_principal' });
          }
          if (!username || principal.name.toLowerCase() === username.toLowerCase()) {
            who = principal;
          }
        } else if (
          process.env.VIGILANTE_API_TOKEN &&
          secret === process.env.VIGILANTE_API_TOKEN
        ) {
          who = BOOTSTRAP_OWNER_PRINCIPAL;
        }
      }
    }
  }

  if (!who) {
    return apiError(401, 'Invalid token or password', { reason: 'deny_unauthenticated' });
  }

  const { sessionToken } = await createSession(who.id);
  recordAuthEvent(req, eventType, who.id);

  const res = NextResponse.json({
    success: true,
    principal: {
      id: who.id,
      name: who.name,
      kind: who.kind,
      role: who.role,
      ...(who.ldapUid ? { ldapUid: who.ldapUid } : {}),
      ...(Array.isArray(who.ldapGroups) ? { ldapGroups: who.ldapGroups } : {})
    }
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
