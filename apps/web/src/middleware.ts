import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

/**
 * Security Middleware for Vigilante Web Ops
 *
 * 1. Restricts mutating requests (POST, PUT, DELETE, PATCH) on /api/* routes
 * 2. Enforces CSRF / Origin validation against host / localhost / loopback
 * 3. Enforces optional token authentication if VIGILANTE_API_TOKEN is defined
 * 4. Defers vigilante_session cookie or vig_-prefixed tokens to route guards
 */
export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Protect mutating API endpoints
  if (pathname.startsWith('/api/') && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(request.method)) {
    // 1. Optional API Token Gate
    const requiredToken = process.env.VIGILANTE_API_TOKEN;
    if (requiredToken) {
      const authHeader = request.headers.get('authorization');
      const customTokenHeader = request.headers.get('x-vigilante-token');
      const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.substring(7) : null;
      const sessionCookie = request.cookies.get('vigilante_session')?.value;

      // If browser session cookie is present, defer to route guards
      if (sessionCookie) {
        return NextResponse.next();
      }

      // If principal token (vig_-prefixed) is present, defer to route guards
      const presented = bearerToken ?? customTokenHeader;
      if (presented && presented.startsWith('vig_')) {
        return NextResponse.next();
      }

      if (bearerToken !== requiredToken && customTokenHeader !== requiredToken) {
        return NextResponse.json(
          {
            success: false,
            error: 'Unauthorized: Missing or invalid API token',
            details: {
              code: 'unauthenticated',
              message: 'Unauthorized: Missing or invalid API token'
            }
          },
          { status: 401 }
        );
      }
    }

    // 2. CSRF & Origin Verification
    const origin = request.headers.get('origin');
    const host = request.headers.get('host');

    if (origin && host) {
      try {
        const originUrl = new URL(origin);
        const hostWithoutPort = host.split(':')[0];
        const isLocalhost = ['localhost', '127.0.0.1', '::1', '[::1]'].includes(originUrl.hostname);
        const matchesHost = originUrl.host === host || originUrl.hostname === hostWithoutPort;

        if (!isLocalhost && !matchesHost) {
          return NextResponse.json(
            {
              success: false,
              error: 'Forbidden: Cross-site request rejected by CSRF origin guard',
              details: {
                code: 'forbidden',
                message: 'Forbidden: Cross-site request rejected by CSRF origin guard'
              }
            },
            { status: 403 }
          );
        }
      } catch {
        return NextResponse.json(
          {
            success: false,
            error: 'Forbidden: Malformed request origin header',
            details: {
              code: 'forbidden',
              message: 'Forbidden: Malformed request origin header'
            }
          },
          { status: 403 }
        );
      }
    }
  }

  return NextResponse.next();
}

export const config = {
  matcher: '/api/:path*',
};
