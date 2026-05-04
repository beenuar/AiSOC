/**
 * Token + session storage for the mobile responder PWA.
 *
 * The desktop console relies on cookies set by the API gateway, but the
 * passkey login on mobile returns the JWT pair in the response body
 * (so we can finish the WebAuthn ceremony in a single fetch). We persist
 * those tokens in `localStorage` and let the global `request()` helper in
 * `lib/api.ts` pick them up via the `Authorization` header.
 */

const ACCESS_KEY = 'aisoc.responder.accessToken';
const REFRESH_KEY = 'aisoc.responder.refreshToken';
const EXPIRES_KEY = 'aisoc.responder.expiresAt';
const PROFILE_KEY = 'aisoc.responder.profile';

export interface ResponderProfile {
  user_id: string;
  email: string | null;
  name: string | null;
}

function safeGet(key: string): string | null {
  if (typeof window === 'undefined') return null;
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeSet(key: string, value: string | null): void {
  if (typeof window === 'undefined') return;
  try {
    if (value === null) window.localStorage.removeItem(key);
    else window.localStorage.setItem(key, value);
  } catch {
    /* private mode etc. */
  }
}

/** Persist the JWT pair returned by `passkeyApi.authenticateFinish`. */
export function saveSession(args: {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  profile?: ResponderProfile;
}): void {
  const expiresAt = Date.now() + args.expires_in * 1000;
  safeSet(ACCESS_KEY, args.access_token);
  safeSet(REFRESH_KEY, args.refresh_token);
  safeSet(EXPIRES_KEY, String(expiresAt));
  if (args.profile) {
    safeSet(PROFILE_KEY, JSON.stringify(args.profile));
  }
}

export function getAccessToken(): string | null {
  const token = safeGet(ACCESS_KEY);
  if (!token) return null;
  const expires = Number(safeGet(EXPIRES_KEY));
  if (Number.isFinite(expires) && expires > 0 && Date.now() > expires) {
    // The token is stale. Leave the refresh token alone so the caller can
    // attempt a silent re-auth, but don't return the expired access token.
    return null;
  }
  return token;
}

export function getRefreshToken(): string | null {
  return safeGet(REFRESH_KEY);
}

export function getProfile(): ResponderProfile | null {
  const raw = safeGet(PROFILE_KEY);
  if (!raw) return null;
  try {
    return JSON.parse(raw) as ResponderProfile;
  } catch {
    return null;
  }
}

export function clearSession(): void {
  safeSet(ACCESS_KEY, null);
  safeSet(REFRESH_KEY, null);
  safeSet(EXPIRES_KEY, null);
  safeSet(PROFILE_KEY, null);
}

/** True when we *think* the user is signed in (token present and unexpired). */
export function isAuthenticated(): boolean {
  return getAccessToken() !== null;
}

/**
 * Decode the payload of a JWT without verifying its signature.
 *
 * The PWA only needs this to surface the user's name/email in the chrome
 * once the passkey ceremony completes — every authenticated request is
 * still verified by the backend, so a tampered token here would simply
 * cause the next API call to return 401.
 */
export function decodeJwt<T = Record<string, unknown>>(
  token: string,
): T | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const padded =
      parts[1] + '='.repeat((4 - (parts[1].length % 4)) % 4);
    const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
    const json =
      typeof atob === 'function'
        ? atob(base64)
        : Buffer.from(base64, 'base64').toString('binary');
    return JSON.parse(decodeURIComponent(escape(json))) as T;
  } catch {
    return null;
  }
}

/** Build a `ResponderProfile` from a freshly minted access token. */
export function profileFromAccessToken(token: string): ResponderProfile | null {
  const payload = decodeJwt<{
    sub?: string;
    user_id?: string;
    email?: string;
    name?: string;
    full_name?: string;
    username?: string;
  }>(token);
  if (!payload) return null;
  const user_id = payload.user_id ?? payload.sub ?? '';
  if (!user_id) return null;
  return {
    user_id,
    email: payload.email ?? null,
    name:
      payload.name ?? payload.full_name ?? payload.username ?? payload.email ?? null,
  };
}
