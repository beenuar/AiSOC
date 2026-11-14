/**
 * Native push: three outcomes that must never be collapsed into one.
 *
 * Depth 9.6. `push.ts` sent every subscription through `web-push`, which
 * signs a VAPID JWT and POSTs to the endpoint URL. A bare APNs device token
 * is not a URL, so a subscription saved by `apps/mobile` was accepted,
 * counted and failed on every send — the worst of the three possible
 * states, because the subscription count looked healthy while no
 * responder's phone ever rang.
 *
 * Asserted by name below:
 *
 * * a real Web Push subscription is **not** mistaken for a native one, in
 *   both directions — routing a browser to APNs would break a path that
 *   works today;
 * * missing credentials produce `not_configured` **naming each one**, never
 *   a success and never a bare failure: a deployment that stores native
 *   tokens and cannot send to them is a responder who believes they are
 *   covered and is not;
 * * a dead token prunes and a transient error does not;
 * * the request this code really makes carries the headers APNs and FCM
 *   require, asserted against the captured request rather than against a
 *   mock that agrees with it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';

import { missingCredentials, nativePlatformOf, sendNative } from '../src/native-push';

/** A real P-256 key pair, so the "not native" case uses a real p256dh. */
const { publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const REAL_P256DH = publicKey.export({ type: 'spki', format: 'der' }).toString('base64url');

/** A throwaway EC key so the APNs provider JWT really signs. */
const APNS_KEY = crypto
  .generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();

const APNS_ENV = {
  APNS_KEY_ID: 'ABC123DEFG',
  APNS_TEAM_ID: 'TEAM123456',
  APNS_PRIVATE_KEY: APNS_KEY,
  APNS_BUNDLE_ID: 'com.example.aisoc',
} as NodeJS.ProcessEnv;

const FCM_ENV = {
  FCM_PROJECT_ID: 'aisoc-test',
  FCM_SERVICE_ACCOUNT_JSON: JSON.stringify({
    client_email: 'push@aisoc-test.iam.gserviceaccount.com',
    private_key: 'unused — the access token is injected',
    token_uri: 'https://oauth2.example/token',
  }),
} as NodeJS.ProcessEnv;

interface Captured {
  url: string;
  /** Narrowed to what every assertion below reads. `RequestInit['body']` is
   *  a union wide enough that `String(...)` on it is a lint error, and the
   *  only bodies this module sends are JSON strings. */
  init: Omit<RequestInit, 'body'> & { body?: string };
}

function capturing(status: number, body = ''): { fetchImpl: typeof fetch; calls: Captured[] } {
  const calls: Captured[] = [];
  const fetchImpl = (async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), init: (init ?? {}) as Captured['init'] });
    return new Response(body, { status });
  }) as unknown as typeof fetch;
  return { fetchImpl, calls };
}

test('a real Web Push subscription is not mistaken for a native one', () => {
  assert.equal(nativePlatformOf({ p256dh: REAL_P256DH, auth: 'x' }), null);
  assert.equal(nativePlatformOf({}), null);
  assert.equal(nativePlatformOf({ p256dh: '' }), null);
});

test('the mobile app’s convention is recognised, case-insensitively', () => {
  assert.equal(nativePlatformOf({ p256dh: 'ios' }), 'ios');
  assert.equal(nativePlatformOf({ p256dh: 'Android' }), 'android');
});

test('missing credentials are named, one by one', () => {
  assert.deepEqual(missingCredentials('ios', {}), [
    'APNS_KEY_ID',
    'APNS_TEAM_ID',
    'APNS_PRIVATE_KEY',
    'APNS_BUNDLE_ID',
  ]);
  assert.deepEqual(missingCredentials('android', {}), [
    'FCM_PROJECT_ID',
    'FCM_SERVICE_ACCOUNT_JSON',
  ]);
  assert.deepEqual(missingCredentials('ios', APNS_ENV), []);
});

test('an unconfigured deployment refuses rather than reporting a delivery', async () => {
  const { fetchImpl, calls } = capturing(200);
  const outcome = await sendNative(
    { endpoint: 'token', platform: 'ios' },
    { title: 't', body: 'b' },
    { env: {}, fetchImpl },
  );
  assert.equal(outcome.kind, 'not_configured');
  assert.deepEqual((outcome).missing.length, 4);
  // Nothing was sent, and nothing was pruned either: the token is fine, the
  // deployment is not.
  assert.equal(calls.length, 0);
});

test('an APNs delivery carries the headers Apple requires', async () => {
  const { fetchImpl, calls } = capturing(200);
  const outcome = await sendNative(
    { endpoint: 'devicetoken123', platform: 'ios' },
    { title: 'Containment approval', body: 'isolate WKS-14', critical: true, tag: 'alert-1' },
    { env: APNS_ENV, fetchImpl, apnsHost: 'https://apns.example' },
  );
  assert.equal(outcome.kind, 'delivered');
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'https://apns.example/3/device/devicetoken123');
  const headers = calls[0].init.headers as Record<string, string>;
  assert.equal(headers['apns-topic'], 'com.example.aisoc');
  assert.equal(headers['apns-push-type'], 'alert');
  // A containment approval is "deliver immediately"; anything else lets the
  // OS batch.
  assert.equal(headers['apns-priority'], '10');
  assert.equal(headers['apns-collapse-id'], 'alert-1');
  assert.match(headers.authorization, /^bearer eyJ/);
});

test('a non-critical notification lets the OS batch it', async () => {
  const { fetchImpl, calls } = capturing(200);
  await sendNative(
    { endpoint: 'd', platform: 'ios' },
    { title: 't', body: 'b' },
    { env: APNS_ENV, fetchImpl, apnsHost: 'https://apns.example' },
  );
  assert.equal((calls[0].init.headers as Record<string, string>)['apns-priority'], '5');
});

test('APNs 410 prunes the token and a 429 does not', async () => {
  const gone = capturing(410, 'Unregistered');
  const limited = capturing(429, 'TooManyRequests');
  const a = await sendNative(
    { endpoint: 'd', platform: 'ios' },
    { title: 't', body: 'b' },
    { env: APNS_ENV, fetchImpl: gone.fetchImpl, apnsHost: 'https://apns.example' },
  );
  const b = await sendNative(
    { endpoint: 'd', platform: 'ios' },
    { title: 't', body: 'b' },
    { env: APNS_ENV, fetchImpl: limited.fetchImpl, apnsHost: 'https://apns.example' },
  );
  assert.equal(a.kind, 'unregistered');
  // Transient. Pruning here would lose a working device for a rate limit.
  assert.equal(b.kind, 'failed');
});

test('a BadDeviceToken 400 prunes, because it means the same thing', async () => {
  const { fetchImpl } = capturing(400, '{"reason":"BadDeviceToken"}');
  const outcome = await sendNative(
    { endpoint: 'd', platform: 'ios' },
    { title: 't', body: 'b' },
    { env: APNS_ENV, fetchImpl, apnsHost: 'https://apns.example' },
  );
  assert.equal(outcome.kind, 'unregistered');
});

test('an FCM message stringifies its data, because FCM rejects anything else', async () => {
  const { fetchImpl, calls } = capturing(200, '{"name":"ok"}');
  const outcome = await sendNative(
    { endpoint: 'fcm-token', platform: 'android' },
    { title: 't', body: 'b', data: { alert_id: 42, url: '/alerts/42' }, critical: true },
    {
      env: FCM_ENV,
      fetchImpl,
      fcmHost: 'https://fcm.example',
      accessToken: async () => 'injected-access-token',
    },
  );
  assert.equal(outcome.kind, 'delivered');
  assert.equal(calls[0].url, 'https://fcm.example/v1/projects/aisoc-test/messages:send');
  const body = JSON.parse(calls[0].init.body ?? '{}');
  assert.equal(body.message.token, 'fcm-token');
  // Numbers would be a 400 the caller cannot act on.
  assert.deepEqual(body.message.data, { alert_id: '42', url: '/alerts/42' });
  assert.equal(body.message.android.priority, 'HIGH');
});

test('FCM UNREGISTERED prunes and a 503 does not', async () => {
  const gone = capturing(404, '{"error":{"status":"UNREGISTERED"}}');
  const down = capturing(503, 'unavailable');
  const a = await sendNative(
    { endpoint: 't', platform: 'android' },
    { title: 't', body: 'b' },
    { env: FCM_ENV, fetchImpl: gone.fetchImpl, fcmHost: 'https://fcm.example', accessToken: async () => 'x' },
  );
  const b = await sendNative(
    { endpoint: 't', platform: 'android' },
    { title: 't', body: 'b' },
    { env: FCM_ENV, fetchImpl: down.fetchImpl, fcmHost: 'https://fcm.example', accessToken: async () => 'x' },
  );
  assert.equal(a.kind, 'unregistered');
  assert.equal(b.kind, 'failed');
});

test('an unreachable provider is a transient failure, not a dead token', async () => {
  const fetchImpl = (async () => {
    throw new Error('ECONNREFUSED');
  }) as unknown as typeof fetch;
  const outcome = await sendNative(
    { endpoint: 'd', platform: 'ios' },
    { title: 't', body: 'b' },
    { env: APNS_ENV, fetchImpl, apnsHost: 'https://apns.example' },
  );
  assert.equal(outcome.kind, 'failed');
  // Dropping the subscription because the network blipped would silently
  // unsubscribe a responder.
  assert.match((outcome).reason, /unreachable/);
});
