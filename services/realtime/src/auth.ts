/**
 * Realtime WS/SSE ticket verification — Issue #239.
 *
 * The browser cannot attach an Authorization header to a WebSocket upgrade, so
 * the SPA first calls `POST /api/v1/realtime/ticket` on the API, which mints a
 * short-TTL (≤60s), audience-scoped HS256 ticket signed with the shared
 * `AISOC_REALTIME_JWT_SECRET`. The browser then appends the ticket as
 * `?token=...` on the WS/SSE URL. This module verifies that ticket here at the
 * realtime edge: signature (HS256), `aud`, and `exp`. The subscription tenant
 * is derived from the verified `tenant_id` claim — never from a client-supplied
 * query parameter — so a caller can never subscribe to another tenant.
 *
 * We verify manually with Node's `crypto` rather than pulling in a JWT library
 * to keep the realtime service's dependency surface (and supply chain) minimal.
 * The signing side lives in `services/api/app/core/security.py`
 * (`create_realtime_ticket`) and must stay in sync with the claims checked here.
 */
import crypto from 'crypto';

// Must equal `REALTIME_TICKET_AUDIENCE` in services/api/app/core/security.py.
export const REALTIME_TICKET_AUDIENCE = 'aisoc-realtime';

// Must equal `DEV_REALTIME_TICKET_SECRET` in services/api/app/core/config.py.
// Shared dev fallback so local docker-compose works with zero secret plumbing.
const DEV_REALTIME_TICKET_SECRET = 'aisoc-dev-realtime-ticket-secret-not-for-production';

// Mirror INSECURE_SECRET_KEY_DEFAULTS in services/api/app/core/config.py so a
// placeholder secret is treated as "unset" on this side too.
const INSECURE_SECRET_DEFAULTS = new Set<string>([
  'change-me-in-production-at-least-32-chars',
  'dev_secret_key_change_in_production',
  'changeme',
  'secret',
]);

function isProductionEnv(): boolean {
  const env = (process.env.AISOC_ENV || process.env.ENVIRONMENT || process.env.APP_ENV || '')
    .trim()
    .toLowerCase();
  return env === 'production' || env === 'prod';
}

/**
 * Resolve the effective HS256 secret used to verify realtime tickets.
 *
 * Returns the secret, or `null` when the service is not configured to verify
 * tickets (production with the shared secret unset/insecure) — in which case the
 * caller MUST reject every connection (fail closed). Kept byte-for-byte in sync
 * with `realtime_ticket_secret` in services/api/app/core/config.py.
 */
export function resolveTicketSecret(): string | null {
  const configured = (process.env.AISOC_REALTIME_JWT_SECRET || '').trim();
  if (configured && !INSECURE_SECRET_DEFAULTS.has(configured)) {
    return configured;
  }
  if (!isProductionEnv()) {
    return DEV_REALTIME_TICKET_SECRET;
  }
  return null;
}

function base64UrlDecode(input: string): Buffer {
  // JWT uses base64url; Node's 'base64url' decoder tolerates missing padding.
  return Buffer.from(input, 'base64url');
}

export interface RealtimeClaims {
  sub: string;
  tenant_id: string;
  aud: string;
  exp: number;
  iat?: number;
  type?: string;
}

/**
 * Verify an HS256 realtime ticket. Returns the decoded claims on success, or
 * `null` if the token is malformed, has a bad signature, wrong audience, wrong
 * type, or is expired.
 */
export function verifyRealtimeTicket(token: string, secret: string): RealtimeClaims | null {
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, sigB64] = parts;

  // Verify header advertises HS256 — reject "alg: none" and asymmetric algs so
  // an attacker can't downgrade the verification.
  let header: { alg?: string; typ?: string };
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
  } catch {
    return null;
  }
  if (header.alg !== 'HS256') return null;

  // Recompute and constant-time compare the signature over `header.payload`.
  const expected = crypto
    .createHmac('sha256', secret)
    .update(`${headerB64}.${payloadB64}`)
    .digest();
  let provided: Buffer;
  try {
    provided = base64UrlDecode(sigB64);
  } catch {
    return null;
  }
  if (expected.length !== provided.length) return null;
  if (!crypto.timingSafeEqual(expected, provided)) return null;

  let claims: RealtimeClaims;
  try {
    claims = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    return null;
  }

  if (claims.aud !== REALTIME_TICKET_AUDIENCE) return null;
  if (claims.type && claims.type !== 'realtime_ticket') return null;
  if (typeof claims.exp !== 'number') return null;
  // 30s clock-skew leeway, matching common JWT verifier defaults.
  const now = Math.floor(Date.now() / 1000);
  if (claims.exp + 30 < now) return null;
  if (!claims.tenant_id) return null;

  return claims;
}
