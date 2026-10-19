import * as jose from 'jose';

let cachedJwks = null;
let cachedIssuer = null;

/**
 * Get OIDC configuration from environment
 */
export function getOidcConfig() {
  const issuer = process.env.VIGILANTE_OIDC_ISSUER;
  const clientId = process.env.VIGILANTE_OIDC_CLIENT_ID;
  if (!issuer || !clientId) return null;
  return { issuer, clientId };
}

/**
 * Reset cached JWKS
 */
export function resetOidcCache() {
  cachedJwks = null;
  cachedIssuer = null;
}

/**
 * Verify an incoming Bearer JWT against the configured OIDC issuer
 * @param {string} token - Raw JWT string
 * @param {Object} store - Authz store
 * @returns {Promise<Object|null>} - Matched principal or null
 */
export async function verifyOidcToken(token, store) {
  const config = getOidcConfig();
  if (!config || !token) return null;

  try {
    if (!cachedJwks || cachedIssuer !== config.issuer) {
      const wellKnownUrl = new URL(
        '/.well-known/openid-configuration',
        config.issuer.endsWith('/') ? config.issuer : `${config.issuer}/`
      );
      const res = await fetch(wellKnownUrl.toString());
      if (!res.ok) {
        throw new Error(`OIDC discovery failed: ${res.status} ${res.statusText}`);
      }
      const discovery = await res.json();
      if (!discovery.jwks_uri) {
        throw new Error('OIDC discovery response missing jwks_uri');
      }
      cachedJwks = jose.createRemoteJWKSet(new URL(discovery.jwks_uri));
      cachedIssuer = config.issuer;
    }

    const { payload } = await jose.jwtVerify(token, cachedJwks, {
      issuer: config.issuer,
      audience: config.clientId
    });

    const subject = payload.sub;
    const email = payload.email;

    if (!subject && !email) return null;

    // Find principal with matching oidcSubject
    const principal = store.principals.find(p => {
      if (!p.oidcSubject || p.disabled) return false;
      return p.oidcSubject === subject || (email && p.oidcSubject === email);
    });

    return principal || null;
  } catch (err) {
    return null;
  }
}
