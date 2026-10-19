import { NextResponse } from 'next/server';
import { rotatePrincipalToken } from 'vigilante_lib/engine/authz.js';
import { authorizeRequest } from '@/lib/authz';
import { routeError } from '@/lib/route-error';

export const dynamic = 'force-dynamic';

type Ctx = { params: { id: string } | Promise<{ id: string }> };

/**
 * Issues a fresh token or sets a new password for a principal, invalidating old sessions.
 */
export async function POST(req: Request, { params }: Ctx) {
  const denied = await authorizeRequest(req, 'users:manage_permissions');
  if (denied) return denied;

  const resolvedParams = await params;
  const id = resolvedParams.id;

  const body = await req.json().catch(() => ({}));
  const password = typeof body.password === 'string' && body.password.trim() ? body.password.trim() : undefined;

  try {
    const res = await rotatePrincipalToken(id, { password });
    return NextResponse.json({
      success: true,
      secret: res.secret,
      token: res.secret,
      isCustomPassword: res.isCustomPassword
    });
  } catch (err) {
    return routeError(err, { route: 'POST /api/authz/principals/[id]/rotate', status: 400 });
  }
}
