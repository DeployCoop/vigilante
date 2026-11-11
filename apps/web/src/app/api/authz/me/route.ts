import { NextResponse } from 'next/server';
import { buildAbilityFor } from 'vigilante_lib/engine/authz.js';
import {
  recordAuthEvent,
  resolveAuthzContext,
  resolveVigilanteLdapConfig,
  SESSION_COOKIE_NAME
} from '@/lib/authz';
import { apiError } from '@/lib/route-error';

export const dynamic = 'force-dynamic';

/**
 * Returns the caller's principal and their CASL rules in packed form so
 * the UI can gate controls with the exact rules the API enforces.
 * Doubles as the "who am I" probe for the login flow.
 */
export async function GET(req: Request) {
  const ctx = await resolveAuthzContext(req);
  const ldapCfg = resolveVigilanteLdapConfig();
  // LDAP internals (URI, base DN, source, break-glass flag) go only to
  // authenticated callers. Anonymous callers — including the login probe —
  // get just `enabled`, which the sign-in UI needs to choose the LDAP tab
  // and reveals nothing beyond "LDAP login exists".
  const ldapSummary = !ldapCfg.enabled
    ? undefined
    : ctx.principal
      ? {
          enabled: true,
          uri: ldapCfg.uri,
          baseDN: ldapCfg.baseDN,
          source: ldapCfg.source,
          allowLocalBreakGlass: ldapCfg.allowLocalBreakGlass
        }
      : { enabled: true };

  if (ctx.expiredSession) {
    recordAuthEvent(req, 'session_expired', null);
  }

  if (ctx.loaded.state === 'disabled') {
    return NextResponse.json({
      authzEnabled: false,
      principal: null,
      localBoard: false,
      rules: [],
      ...(ldapSummary ? { ldap: ldapSummary } : {})
    });
  }

  if (ctx.loaded.state === 'invalid') {
    return apiError(500, 'Authorization store is invalid', {
      reason: 'deny_invalid_store',
      route: 'GET /api/authz/me'
    });
  }

  const store = ctx.loaded.store || { principals: [] };

  if (!ctx.principal) {
    // Bootstrap mode: empty store + local request = implicit local board
    if (store.principals.length === 0 && ctx.localBoard) {
      return NextResponse.json({
        authzEnabled: false,
        principal: null,
        localBoard: true,
        rules: [],
        ...(ldapSummary ? { ldap: ldapSummary } : {})
      });
    }

    const reason = ctx.unknownPrincipal ? 'deny_unknown_principal' : 'deny_unauthenticated';
    const res = apiError(
      401,
      reason === 'deny_unknown_principal'
        ? 'Identity is not provisioned as a principal'
        : 'Authentication required',
      { reason, ...(ldapSummary ? { ldap: ldapSummary } : {}) }
    );

    if (ctx.expiredSession) {
      res.cookies.set(SESSION_COOKIE_NAME, '', {
        httpOnly: true,
        sameSite: 'strict',
        path: '/',
        maxAge: 0
      });
    }
    return res;
  }

  const { id, name, kind, role, ldapUid, ldapGroups } = ctx.principal;
  const ability = buildAbilityFor(ctx.principal);

  return NextResponse.json({
    authzEnabled: true,
    principal: {
      id,
      name,
      kind,
      role,
      ...(ldapUid ? { ldapUid } : {}),
      ...(Array.isArray(ldapGroups) ? { ldapGroups } : {})
    },
    localBoard: ctx.localBoard,
    rules: ability.rules,
    ...(ldapSummary ? { ldap: ldapSummary } : {})
  });
}
