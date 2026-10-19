import { NextResponse } from 'next/server';
import {
  updatePrincipal,
  removePrincipal,
  ROLES
} from 'vigilante_lib/engine/authz.js';
import { authorizeRequest } from '@/lib/authz';
import { apiError, routeError } from '@/lib/route-error';

export const dynamic = 'force-dynamic';

type Ctx = { params: { id: string } | Promise<{ id: string }> };

export async function PATCH(req: Request, { params }: Ctx) {
  const denied = await authorizeRequest(req, 'users:manage_permissions');
  if (denied) return denied;

  const resolvedParams = await params;
  const id = resolvedParams.id;

  const body = await req.json().catch(() => ({}));
  if (body.role && !ROLES.includes(body.role)) {
    return apiError(400, `role must be one of: ${ROLES.join(', ')}`);
  }

  try {
    const updated = await updatePrincipal(id, {
      name: typeof body.name === 'string' && body.name.trim() ? body.name.trim() : undefined,
      role: body.role,
      disabled: typeof body.disabled === 'boolean' ? body.disabled : undefined,
      oidcSubject: body.oidcSubject !== undefined ? body.oidcSubject : undefined,
      grants: Array.isArray(body.grants) ? body.grants : undefined,
      revocations: Array.isArray(body.revocations) ? body.revocations : undefined
    });

    return NextResponse.json({ success: true, principal: updated });
  } catch (err) {
    return routeError(err, { route: 'PATCH /api/authz/principals/[id]', status: 400 });
  }
}

export async function DELETE(req: Request, { params }: Ctx) {
  const denied = await authorizeRequest(req, 'users:manage_permissions');
  if (denied) return denied;

  const resolvedParams = await params;
  const id = resolvedParams.id;

  try {
    await removePrincipal(id);
    return NextResponse.json({ success: true, id });
  } catch (err) {
    return routeError(err, { route: 'DELETE /api/authz/principals/[id]', status: 400 });
  }
}
