/**
 * Unit tests for the realtime WS/SSE ticket verifier — Issue #239.
 *
 * These run on Node's built-in test runner via `tsx --test` (no extra deps).
 * The HMAC signing helper here mirrors `create_realtime_ticket` in
 * services/api/app/core/security.py so the test proves the two sides agree on
 * the exact wire format (HS256 over `base64url(header).base64url(payload)`).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import {
  REALTIME_TICKET_AUDIENCE,
  resolveTicketSecret,
  verifyRealtimeTicket,
  type RealtimeClaims,
} from '../src/auth';

const SECRET = 'a'.repeat(64);

function b64url(buf: Buffer | string): string {
  return Buffer.from(buf).toString('base64url');
}

/** Mint an HS256 ticket the same way the Python API does. */
function mintTicket(
  claims: Record<string, unknown>,
  opts: { secret?: string; alg?: string } = {},
): string {
  const secret = opts.secret ?? SECRET;
  const header = b64url(JSON.stringify({ alg: opts.alg ?? 'HS256', typ: 'JWT' }));
  const payload = b64url(JSON.stringify(claims));
  const sig = crypto
    .createHmac('sha256', secret)
    .update(`${header}.${payload}`)
    .digest('base64url');
  return `${header}.${payload}.${sig}`;
}

function validClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  return {
    sub: 'user-123',
    tenant_id: 'tenant-abc',
    aud: REALTIME_TICKET_AUDIENCE,
    iat: now,
    exp: now + 60,
    type: 'realtime_ticket',
    ...overrides,
  };
}

test('accepts a well-formed ticket and returns claims with the verified tenant', () => {
  const claims = verifyRealtimeTicket(mintTicket(validClaims()), SECRET) as RealtimeClaims;
  assert.ok(claims, 'expected claims');
  assert.equal(claims.tenant_id, 'tenant-abc');
  assert.equal(claims.sub, 'user-123');
  assert.equal(claims.aud, REALTIME_TICKET_AUDIENCE);
});

test('rejects an empty / malformed token', () => {
  assert.equal(verifyRealtimeTicket('', SECRET), null);
  assert.equal(verifyRealtimeTicket('not-a-jwt', SECRET), null);
  assert.equal(verifyRealtimeTicket('a.b', SECRET), null);
});

test('rejects a tampered signature', () => {
  const token = mintTicket(validClaims());
  // Tamper the FIRST character of the signature, not the last.
  //
  // Two earlier forms were both no-ops, for the same underlying reason:
  // the end of a base64url signature does not carry the bits you would
  // assume. HMAC-SHA256 is 32 bytes, which encodes to 43 characters
  // carrying 258 bits, so the final character's low four bits are padding
  // and decode to nothing.
  //
  //   - overwriting the last two characters with a fixed 'xx' left the
  //     token unchanged whenever the signature already ended in 'xx',
  //     about 1 run in 4,096;
  //   - flipping the last character to a different one changed only those
  //     padding bits, so the decoded signature was *identical* every time
  //     and the test failed deterministically.
  //
  // The first character's six bits are all significant, so this changes
  // the signature bytes for certain. The decode assertion below is what
  // makes that a checked property rather than a claim.
  const [header, payload, signature] = token.split('.');
  const flipped = (signature[0] === 'A' ? 'B' : 'A') + signature.slice(1);
  assert.notEqual(
    Buffer.from(flipped, 'base64url').toString('hex'),
    Buffer.from(signature, 'base64url').toString('hex'),
    'the tamper must change the decoded signature, not just the text',
  );
  assert.equal(verifyRealtimeTicket(`${header}.${payload}.${flipped}`, SECRET), null);
});

test('rejects a token signed with a different secret', () => {
  const token = mintTicket(validClaims(), { secret: 'b'.repeat(64) });
  assert.equal(verifyRealtimeTicket(token, SECRET), null);
});

test('rejects alg:none (algorithm downgrade)', () => {
  const header = b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }));
  const payload = b64url(JSON.stringify(validClaims()));
  // Unsigned token — the classic "alg: none" forgery.
  assert.equal(verifyRealtimeTicket(`${header}.${payload}.`, SECRET), null);
});

test('rejects a foreign audience', () => {
  const token = mintTicket(validClaims({ aud: 'some-other-service' }));
  assert.equal(verifyRealtimeTicket(token, SECRET), null);
});

test('rejects a wrong token type', () => {
  const token = mintTicket(validClaims({ type: 'access' }));
  assert.equal(verifyRealtimeTicket(token, SECRET), null);
});

test('rejects an expired ticket (beyond clock-skew leeway)', () => {
  const now = Math.floor(Date.now() / 1000);
  const token = mintTicket(validClaims({ iat: now - 120, exp: now - 60 }));
  assert.equal(verifyRealtimeTicket(token, SECRET), null);
});

test('accepts a ticket within the 30s clock-skew leeway', () => {
  const now = Math.floor(Date.now() / 1000);
  // Expired 10s ago — still inside the 30s leeway, so accepted.
  const token = mintTicket(validClaims({ exp: now - 10 }));
  assert.ok(verifyRealtimeTicket(token, SECRET));
});

test('rejects a ticket missing tenant_id', () => {
  const claims = validClaims();
  delete claims.tenant_id;
  assert.equal(verifyRealtimeTicket(mintTicket(claims), SECRET), null);
});

test('rejects a non-numeric exp', () => {
  const token = mintTicket(validClaims({ exp: 'soon' }));
  assert.equal(verifyRealtimeTicket(token, SECRET), null);
});

// GHSA-4m55-xhcm-wjcr. This asserted the fallback and was the vulnerability:
// the constant is published in this repository, and the production check read
// an environment variable no shipped manifest passed to this container, so it
// was the effective HMAC key in every deployment.
test('resolveTicketSecret does not fall back to the published dev secret', () => {
  const prev = { ...process.env };
  try {
    delete process.env.AISOC_REALTIME_JWT_SECRET;
    process.env.ENVIRONMENT = 'development';
    delete process.env.AISOC_ENV;
    delete process.env.APP_ENV;
    assert.equal(resolveTicketSecret(), null);
  } finally {
    process.env = prev;
  }
});

test('the retired dev secret is refused even when set explicitly', () => {
  const prev = { ...process.env };
  try {
    process.env.AISOC_REALTIME_JWT_SECRET =
      'aisoc-dev-realtime-ticket-secret-not-for-production';
    assert.equal(resolveTicketSecret(), null);
  } finally {
    process.env = prev;
  }
});

test('resolveTicketSecret fails closed (null) in production when unset', () => {
  const prev = { ...process.env };
  try {
    delete process.env.AISOC_REALTIME_JWT_SECRET;
    process.env.ENVIRONMENT = 'production';
    assert.equal(resolveTicketSecret(), null);
  } finally {
    process.env = prev;
  }
});

test('resolveTicketSecret rejects a known insecure placeholder in production', () => {
  const prev = { ...process.env };
  try {
    process.env.AISOC_REALTIME_JWT_SECRET = 'changeme';
    process.env.ENVIRONMENT = 'production';
    assert.equal(resolveTicketSecret(), null);
  } finally {
    process.env = prev;
  }
});

test('resolveTicketSecret returns a real configured secret in production', () => {
  const prev = { ...process.env };
  try {
    process.env.AISOC_REALTIME_JWT_SECRET = SECRET;
    process.env.ENVIRONMENT = 'production';
    assert.equal(resolveTicketSecret(), SECRET);
  } finally {
    process.env = prev;
  }
});
