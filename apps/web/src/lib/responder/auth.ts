/**
 * Token + session storage for the mobile responder PWA.
 *
 * Desktop and passkey sign-ins share the JWT pair in `localStorage`.
 * The API client attaches the bearer credential and renews expired access
 * tokens, so the responder gate must also accept a recoverable session.
 */

import {
  AUTH_REFRESH_KEY as REFRESH_KEY,
  AUTH_TOKEN_KEY as ACCESS_KEY,
  authApi,
  isTokenExpired,
} from '../api';

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
  // Invalidate requests from the previous login before replacing its pair.
  // A desktop user cache must not describe this newly authenticated responder.
  authApi.logout();
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
  // The JWT may have been renewed by a desktop request after the original
  // passkey expiresAt was stored. Only the current token's expiry applies.
  return token && !isTokenExpired(token) ? token : null;
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
  authApi.logout();
  safeSet(EXPIRES_KEY, null);
  safeSet(PROFILE_KEY, null);
}

/** A live access token or a refresh token that can recover the session. */
export function isAuthenticated(): boolean {
  return authApi.isAuthenticated();
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
