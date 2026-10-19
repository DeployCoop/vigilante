import { NextResponse } from 'next/server';
import {
  loadAuthzStore,
  initOwner,
  MIN_PASSWORD_LENGTH
} from 'vigilante_lib/engine/authz.js';
import { setupCertificates } from 'vigilante_lib/engine/certs.js';
import { isLocalBoardRequest } from '@/lib/authz';
import { apiError, routeError } from '@/lib/route-error';

export const dynamic = 'force-dynamic';

export async function POST(req: Request) {
  try {
    const loaded = loadAuthzStore();

    const needsBootstrap = loaded.state !== 'ready' || (loaded.store?.principals?.length || 0) === 0;
    if (needsBootstrap && !isLocalBoardRequest(req)) {
      return apiError(
        403,
        'Authorization bootstrap is only available from the local board (loopback). Enable authz locally first, or use `vigilante authz init` on the host.',
        { reason: 'bootstrap_requires_local_board' }
      );
    }

    if (loaded.state === 'ready' && (loaded.store?.principals?.length || 0) > 0) {
      return apiError(
        409,
        'Authorization is already initialized. Use POST /api/authz/principals to add principals.',
        { reason: 'authz_already_initialized' }
      );
    }

    const body = await req.json().catch(() => ({}));
    const name = typeof body.name === 'string' && body.name.trim() ? body.name.trim() : 'Owner';
    const customPassword =
      typeof body.password === 'string' && body.password.trim()
        ? body.password.trim()
        : typeof body.token === 'string' && body.token.trim()
          ? body.token.trim()
          : null;

    if (customPassword && customPassword.length < MIN_PASSWORD_LENGTH) {
      return apiError(400, `Password must be at least ${MIN_PASSWORD_LENGTH} characters.`, {
        reason: 'password_too_short'
      });
    }

    const res = await initOwner({ name, password: customPassword || undefined });

    // Setup local TLS certs for domain if possible
    try {
      await setupCertificates('vigilante.local', { clusterName: 'vigilante-dev' });
    } catch (err: any) {
      // Non-fatal if mkcert is missing
    }

    return NextResponse.json(
      {
        success: true,
        principal: res.principal,
        token: res.secret,
        isCustomPassword: res.isCustomPassword
      },
      { status: 201 }
    );
  } catch (err) {
    return routeError(err, { route: 'POST /api/authz/init' });
  }
}
