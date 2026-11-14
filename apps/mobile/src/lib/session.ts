/**
 * Where the responder app keeps its token, and how it decides it is still good.
 *
 * Storage is injected rather than importing `expo-secure-store` directly, for
 * two reasons. It keeps this module testable without a native module, and it
 * makes the security property explicit at the call site: the token goes in the
 * Keychain or the Android keystore, not in AsyncStorage, because on a phone
 * the realistic threat is a backup or another app on a rooted device rather
 * than an XSS.
 */

export interface SecureStorage {
  getItemAsync(key: string): Promise<string | null>;
  setItemAsync(key: string, value: string): Promise<void>;
  deleteItemAsync(key: string): Promise<void>;
}

const TOKEN_KEY = "aisoc.session.token";

/** Seconds of headroom before expiry at which a token counts as stale. */
const REFRESH_MARGIN_SECONDS = 60;

export interface SessionClaims {
  sub?: string;
  tenant_id?: string;
  exp?: number;
  roles?: string[];
}

/**
 * Decode a JWT payload without verifying it.
 *
 * Deliberately unverified: the client has no key and could not verify if it
 * wanted to. This reads `exp` so the app can avoid firing a request it knows
 * will 401, and reads `tenant_id` for display. Nothing here is a security
 * decision — the API re-checks every claim on every request, and a client
 * that trusted this would be trusting a value the user can edit.
 */
export function decodeClaims(token: string): SessionClaims | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const payload = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = payload.padEnd(payload.length + ((4 - (payload.length % 4)) % 4), "=");
    const decoded = globalThis.atob(padded);
    const parsed = JSON.parse(decoded) as unknown;
    if (typeof parsed !== "object" || parsed === null) return null;
    return parsed as SessionClaims;
  } catch {
    return null;
  }
}

/**
 * Is this token usable right now?
 *
 * A token without an `exp` is treated as expired rather than as eternal. An
 * unreadable expiry is not the same as no expiry, and guessing in the
 * permissive direction means the app sits on a dead token showing an empty
 * approvals queue instead of asking the analyst to log in again.
 */
export function isUsable(token: string | null, now: number = Date.now()): boolean {
  if (!token) return false;
  const claims = decodeClaims(token);
  if (!claims || typeof claims.exp !== "number") return false;
  return claims.exp * 1000 - REFRESH_MARGIN_SECONDS * 1000 > now;
}

export class Session {
  constructor(private readonly storage: SecureStorage) {}

  async load(): Promise<string | null> {
    return this.storage.getItemAsync(TOKEN_KEY);
  }

  async save(token: string): Promise<void> {
    await this.storage.setItemAsync(TOKEN_KEY, token);
  }

  async clear(): Promise<void> {
    await this.storage.deleteItemAsync(TOKEN_KEY);
  }

  /** The token if it is still usable, else null — and the dead one is dropped. */
  async current(now: number = Date.now()): Promise<string | null> {
    const token = await this.load();
    if (isUsable(token, now)) return token;
    if (token) await this.clear();
    return null;
  }
}
