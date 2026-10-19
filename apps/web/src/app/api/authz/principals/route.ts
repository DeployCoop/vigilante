import { NextResponse } from 'next/server';
import {
  loadAuthzStore,
  addPrincipal,
  toPublicPrincipal,
  PERMISSIONS,
  ROLES
} from 'vigilante_lib/engine/authz.js';
import { authorizeRequest } from '@/lib/authz';
import { apiError, routeError } from '@/lib/route-error';

export const dynamic = 'force-dynamic';

function notEnabled() {
  return apiError(
    409,
    'Authorization is not enabled yet. Initialize it via POST /api/authz/init or `vigilante authz init`.',
    { reason: 'authz_not_enabled' }
  );
}

/** Lists principals. Secrets are never returned. */
export async function GET(req: Request) {
  const denied = await authorizeRequest(req, 'users:manage_permissions');
  if (denied) return denied;

  const loaded = loadAuthzStore();
  if (loaded.state === 'disabled') {
    return NextResponse.json({ authzEnabled: false, principals: [] });
  }
  if (loaded.state === 'invalid') {
    return apiError(500, 'Authorization store is invalid', {
      reason: 'deny_invalid_store',
      route: 'GET /api/authz/principals'
    });
  }

  const store = loaded.store || { principals: [] };

  return NextResponse.json({
    success: true,
    authzEnabled: store.principals.length > 0,
    principals: store.principals.map(toPublicPrincipal),
    permissions: [...PERMISSIONS],
    roles: [...ROLES]
  });
}

/**
 * Creates a principal. Unless an oidcSubject is given, a token is
 * generated and returned in the response body once.
 */
export async function POST(req: Request) {
  const denied = await authorizeRequest(req, 'users:manage_permissions');
  if (denied) return denied;

  const loaded = loadAuthzStore();
  if (loaded.state !== 'ready' || !loaded.store || loaded.store.principals.length === 0) {
    return notEnabled();
  }

  const body = await req.json().catch(() => ({}));
  const name = typeof body.name === 'string' ? body.name.trim() : '';
  const role = body.role || 'viewer';
  const kind = body.kind === 'service' ? 'service' : 'human';
  const oidcSubject =
    typeof body.oidcSubject === 'string' && body.oidcSubject.trim()
      ? body.oidcSubject.trim()
      : undefined;

  if (!name) {
    return apiError(400, 'A non-empty name is required');
  }
  if (!ROLES.includes(role)) {
    return apiError(400, `role must be one of: ${ROLES.join(', ')}`);
  }

  try {
    const res = await addPrincipal({
      name,
      role,
      kind,
      oidcSubject,
      grants: Array.isArray(body.grants) ? body.grants : [],
      revocations: Array.isArray(body.revocations) ? body.revocations : []
    });

    return NextResponse.json(
      {
        success: true,
        principal: res.principal,
        ...(res.token ? { token: res.token } : {})
      },
      { status: 201 }
    );
  } catch (err) {
    return routeError(err, { route: 'POST /api/authz/principals', status: 400 });
  }
}
