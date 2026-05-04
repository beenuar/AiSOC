/**
 * Tiny WebAuthn helper for the responder PWA.
 *
 * The backend (`services/api/app/api/v1/endpoints/passkeys.py`) returns
 * publicKey options as JSON with binary fields encoded as base64url. The
 * `navigator.credentials.{create,get}` APIs need real `ArrayBuffer`s, and
 * the resulting `PublicKeyCredential` returns `ArrayBuffer`s that we have
 * to base64url-encode before POSTing back. We avoid pulling in the
 * `@simplewebauthn/browser` library because we only need the two
 * conversion paths.
 */
'use client';

/** Base64URL → Uint8Array (tolerant of missing padding). */
function b64urlToBytes(input: string): Uint8Array {
  const padded = input + '='.repeat((4 - (input.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(base64);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) {
    out[i] = raw.charCodeAt(i);
  }
  return out;
}

/** ArrayBuffer-ish → Base64URL (no padding). */
function bytesToB64url(buffer: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    buffer instanceof ArrayBuffer
      ? new Uint8Array(buffer)
      : new Uint8Array(buffer.buffer, buffer.byteOffset, buffer.byteLength);
  let bin = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    bin += String.fromCharCode(bytes[i]);
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

interface PublicKeyOptionsJSON {
  challenge: string;
  user?: { id: string; name: string; displayName: string };
  excludeCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  allowCredentials?: Array<{
    id: string;
    type: 'public-key';
    transports?: AuthenticatorTransport[];
  }>;
  [key: string]: unknown;
}

/** Inflate the JSON publicKey options returned by the server. */
function inflateCreateOptions(
  options: PublicKeyOptionsJSON,
): PublicKeyCredentialCreationOptions {
  const inflated: Record<string, unknown> = { ...options };
  inflated.challenge = b64urlToBytes(options.challenge);
  if (options.user) {
    inflated.user = {
      ...options.user,
      id: b64urlToBytes(options.user.id),
    };
  }
  if (options.excludeCredentials) {
    inflated.excludeCredentials = options.excludeCredentials.map((c) => ({
      ...c,
      id: b64urlToBytes(c.id),
    }));
  }
  return inflated as unknown as PublicKeyCredentialCreationOptions;
}

function inflateGetOptions(
  options: PublicKeyOptionsJSON,
): PublicKeyCredentialRequestOptions {
  const inflated: Record<string, unknown> = { ...options };
  inflated.challenge = b64urlToBytes(options.challenge);
  if (options.allowCredentials) {
    inflated.allowCredentials = options.allowCredentials.map((c) => ({
      ...c,
      id: b64urlToBytes(c.id),
    }));
  }
  return inflated as unknown as PublicKeyCredentialRequestOptions;
}

interface AttestationResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  authenticatorAttachment?: AuthenticatorAttachment | null;
  response: {
    attestationObject: string;
    clientDataJSON: string;
    transports?: AuthenticatorTransport[];
  };
}

interface AssertionResponseJSON {
  id: string;
  rawId: string;
  type: 'public-key';
  authenticatorAttachment?: AuthenticatorAttachment | null;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string | null;
  };
}

/**
 * Run `navigator.credentials.create` against the JSON options returned by
 * `passkeyApi.registerBegin`, and return a JSON-serializable attestation
 * payload to send back to `passkeyApi.registerFinish`.
 */
export async function createPasskey(
  options: PublicKeyOptionsJSON,
): Promise<AttestationResponseJSON> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('WebAuthn is not available in this browser');
  }
  const cred = (await navigator.credentials.create({
    publicKey: inflateCreateOptions(options),
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No credential returned');

  const att = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: 'public-key',
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    response: {
      attestationObject: bytesToB64url(att.attestationObject),
      clientDataJSON: bytesToB64url(att.clientDataJSON),
      transports:
        typeof att.getTransports === 'function' ? att.getTransports() : [],
    },
  };
}

/**
 * Run `navigator.credentials.get` against the JSON options returned by
 * `passkeyApi.authenticateBegin`, and return a JSON-serializable assertion
 * payload to send back to `passkeyApi.authenticateFinish`.
 */
export async function getPasskey(
  options: PublicKeyOptionsJSON,
): Promise<AssertionResponseJSON> {
  if (typeof navigator === 'undefined' || !navigator.credentials) {
    throw new Error('WebAuthn is not available in this browser');
  }
  const cred = (await navigator.credentials.get({
    publicKey: inflateGetOptions(options),
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No credential returned');

  const ass = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bytesToB64url(cred.rawId),
    type: 'public-key',
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    response: {
      authenticatorData: bytesToB64url(ass.authenticatorData),
      clientDataJSON: bytesToB64url(ass.clientDataJSON),
      signature: bytesToB64url(ass.signature),
      userHandle: ass.userHandle ? bytesToB64url(ass.userHandle) : null,
    },
  };
}

/** Best-effort feature detection so the UI can grey out the button. */
export function isWebAuthnSupported(): boolean {
  if (typeof window === 'undefined') return false;
  return Boolean(
    window.PublicKeyCredential &&
      typeof navigator !== 'undefined' &&
      navigator.credentials,
  );
}
