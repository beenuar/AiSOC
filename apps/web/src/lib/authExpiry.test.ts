/**
 * An expired session sends you to sign in, rather than locking you out.
 *
 * The defect, found by a live browser walkthrough and reproduced
 * deterministically: with an expired token in `localStorage`, `/login`
 * redirected straight to `/dashboard`, every call there answered 401, and
 * nothing ever sent the user back. There was no path out of the product
 * short of clearing browser storage by hand, which is not a thing to ask
 * of an operator at two in the morning.
 *
 * Two independent causes, so two independent fixes:
 *
 * 1. `isAuthenticated()` answered "is a token stored", which is a
 *    different question from "can this session make a request".
 * 2. Nothing handled a 401. A session that died mid-shift left every
 *    panel failing with no explanation.
 *
 * Either fix alone leaves a hole: the first still strands a user whose
 * token expires *while* they are working, and the second still bounces a
 * returning user off `/login` before any request is made.
 */

import { describe, expect, it } from 'vitest';

import { isTokenExpired } from './api';

/** A JWT with the given claims. Unsigned: nothing here verifies it. */
function token(claims: Record<string, unknown>): string {
  const b64 = (o: unknown) =>
    btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(claims)}.signature`;
}

const NOW = 1_790_000_000;

describe('isTokenExpired', () => {
  it('reports an expired token as expired', () => {
    expect(isTokenExpired(token({ exp: NOW - 3600 }), NOW)).toBe(true);
  });

  it('reports a live token as live', () => {
    expect(isTokenExpired(token({ exp: NOW + 3600 }), NOW)).toBe(false);
  });

  it('allows a small skew so a session does not bounce mid-request', () => {
    // Expiring in this very second is not a reason to throw the user out
    // of a page that was working a moment ago.
    expect(isTokenExpired(token({ exp: NOW }), NOW)).toBe(false);
  });

  it('treats an unreadable token as expired', () => {
    // The pessimistic answer costs a sign-in; the optimistic one costs
    // the lockout this test exists to prevent.
    expect(isTokenExpired('not-a-jwt', NOW)).toBe(true);
    expect(isTokenExpired('', NOW)).toBe(true);
    expect(isTokenExpired('a.b', NOW)).toBe(true);
    expect(isTokenExpired('a.!!!not-base64!!!.c', NOW)).toBe(true);
  });

  it('treats a token with no exp as live', () => {
    // Some deployments issue non-expiring service tokens. Refusing those
    // would lock out a working configuration to fix a broken one.
    expect(isTokenExpired(token({ sub: 'x' }), NOW)).toBe(false);
  });

  it('decodes base64url, not just base64', () => {
    // A JWT payload containing `-` or `_` must not read as unparseable,
    // which would log a perfectly good session out.
    const claims = { exp: NOW + 3600, email: 'a+b/c@example.com', sub: '?>?>?>' };
    expect(isTokenExpired(token(claims), NOW)).toBe(false);
  });
});

describe('the lockout this prevents', () => {
  it('an expired token must not count as an authenticated session', async () => {
    const { authApi, AUTH_TOKEN_KEY } = await import('./api');

    window.localStorage.setItem(AUTH_TOKEN_KEY, token({ exp: Math.floor(Date.now() / 1000) - 60 }));
    expect(authApi.isAuthenticated()).toBe(false);

    window.localStorage.setItem(AUTH_TOKEN_KEY, token({ exp: Math.floor(Date.now() / 1000) + 600 }));
    expect(authApi.isAuthenticated()).toBe(true);

    window.localStorage.clear();
  });
});
