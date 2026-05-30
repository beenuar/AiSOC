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
  const tampered = `${token.slice(0, -2)}xx`;
  assert.equal(verifyRealtimeTicket(tampered, SECRET), null);
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
  delete (claims as Record<string, unknown>).tenant_id;
  assert.equal(verifyRealtimeTicket(mintTicket(claims), SECRET), null);
});

test('rejects a non-numeric exp', () => {
  const token = mintTicket(validClaims({ exp: 'soon' }));
  assert.equal(verifyRealtimeTicket(token, SECRET), null);
});

test('resolveTicketSecret falls back to the dev secret outside production', () => {
  const prev = { ...process.env };
  try {
    delete process.env.AISOC_REALTIME_JWT_SECRET;
    process.env.ENVIRONMENT = 'development';
    delete process.env.AISOC_ENV;
    delete process.env.APP_ENV;
    assert.equal(
      resolveTicketSecret(),
      'aisoc-dev-realtime-ticket-secret-not-for-production',
    );
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
