/**
 * Web Push must not take the tenant from whoever asks.
 *
 * `tenantOf` read the `x-tenant-id` header, then a `tenant_id` query
 * parameter, then fell back to the literal string `'default'`. Both fallbacks
 * were ways to get the wrong answer quietly:
 *
 * - the query parameter is caller-supplied, and the three `POST /v1/push/*`
 *   routes carried only a rate limiter, so any caller who could reach the
 *   port could enrol a push endpoint against any tenant, unsubscribe another
 *   tenant's devices, or make this service send a notification;
 * - `'default'` is not a tenant. Migration 001 seeds the canonical tenant
 *   with that *slug* and the demo seed renames it, so every subscription that
 *   reached the fallback was filed under a Redis key belonging to nobody.
 *
 * The routes now require the same internal token `/internal/*` does, which
 * makes the API's `/api/v1/push/*` proxy the only way in — the arrangement
 * the module's own comments already assumed. These tests exercise the
 * resolver directly, because standing up Express, Redis and a VAPID keypair
 * to assert a 400 would test the harness rather than the rule.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { __testing } from '../src/push';

const { tenantOf, userOf } = __testing;

function req(headers: Record<string, string | string[]> = {}, query: Record<string, string> = {}) {
  return { headers, query } as never;
}

test('the tenant comes from the header the proxy stamps', () => {
  assert.equal(tenantOf(req({ 'x-tenant-id': 'tenant-a' })), 'tenant-a');
});

test('a repeated header is read as its first value, not joined', () => {
  assert.equal(tenantOf(req({ 'x-tenant-id': ['tenant-a', 'tenant-b'] })), 'tenant-a');
});

test('a caller-supplied query parameter is not a tenant claim', () => {
  assert.throws(() => tenantOf(req({}, { tenant_id: 'tenant-victim' })), /X-Tenant-Id is required/);
});

test('no tenant at all throws rather than inventing one', () => {
  // The assertion that matters. This used to return 'default'.
  assert.throws(() => tenantOf(req()), /X-Tenant-Id is required/);
});

test('an empty header is not a tenant either', () => {
  assert.throws(() => tenantOf(req({ 'x-tenant-id': '' })), /X-Tenant-Id is required/);
});

test('the user comes from the stamped header in preference to the body', () => {
  // This was the other way round, under a comment saying the API gateway
  // "is expected to" validate the body field against the bearer token. It
  // does not: it stamps X-User-Id from the authenticated principal and
  // forwards the body untouched, so preferring the body let a caller enrol a
  // push endpoint against another user in their own tenant.
  assert.equal(
    userOf(req({ 'x-user-id': 'real-user' }), { user_id: 'someone-else' } as never),
    'real-user',
  );
});

test('the body is still read when no header was stamped', () => {
  assert.equal(userOf(req(), { user_id: 'body-user' } as never), 'body-user');
});

test('an anonymous subscription is still allowed to have no user', () => {
  assert.equal(userOf(req(), {} as never), null);
});
