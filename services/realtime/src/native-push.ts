/**
 * Deliver a push to a native device, through APNs or FCM.
 *
 * Depth 9.6. `push.ts` sends every subscription through `webpush`, which is
 * correct for a browser and wrong for a native token: `web-push` signs a
 * VAPID JWT and POSTs to the endpoint URL, and a bare APNs device token is
 * not a URL. So before this, a native subscription stored by `apps/mobile`
 * was accepted, counted, and then failed on every send — which is the worst
 * of the three possible states, because the subscription count looked
 * healthy.
 *
 * How a native record is recognised
 * ---------------------------------
 * `apps/mobile/src/lib/push.ts` puts the device token in the `endpoint`
 * slot and the platform in the key fields, deliberately, so there is one
 * subscription table rather than two. That convention is the detector:
 * `keys.p256dh` of `"ios"` or `"android"` means native, and a real Web Push
 * `p256dh` is a 65-byte base64url public key that cannot collide with
 * either word.
 *
 * Credentials
 * -----------
 * Neither provider is reachable without credentials the maintainer has to
 * supply — an APNs `.p8` signing key with its key and team ids, and an FCM
 * service account. The plan records both as maintainer items. So this
 * module is written to work the day they arrive and, until then, to
 * **refuse by name**: `classify()` returns `not_configured` listing exactly
 * which variables are missing, the caller records that, and nothing
 * pretends a notification was delivered.
 *
 * That distinction is the whole point. "Delivered", "the device is gone",
 * and "this deployment cannot send to iOS at all" are three different facts
 * and an operator has to be able to tell them apart — a native path that
 * silently reported success would make a responder believe they are
 * covered.
 */

import { createSign } from 'node:crypto';

export type NativePlatform = 'ios' | 'android';

export interface NativeRecord {
  /** The device token. See the module header for why it lives here. */
  endpoint: string;
  platform: NativePlatform;
}

export interface NativePayload {
  title: string;
  body: string;
  data?: Record<string, unknown>;
  /** APNs collapse id / FCM collapse key. */
  tag?: string;
  critical?: boolean;
}

export type NativeOutcome =
  | { kind: 'delivered' }
  /** The device is gone. The caller prunes the subscription. */
  | { kind: 'unregistered'; reason: string }
  /** Transient. The caller counts an error and keeps the subscription. */
  | { kind: 'failed'; reason: string }
  /** This deployment cannot send to this platform at all. Never a success. */
  | { kind: 'not_configured'; missing: string[] };

const APNS_VARS = ['APNS_KEY_ID', 'APNS_TEAM_ID', 'APNS_PRIVATE_KEY', 'APNS_BUNDLE_ID'] as const;
const FCM_VARS = ['FCM_PROJECT_ID', 'FCM_SERVICE_ACCOUNT_JSON'] as const;

/**
 * Whether a stored subscription is a native device token.
 *
 * Exported so a test can assert the convention in both directions: a real
 * Web Push subscription must not be mistaken for a native one, because
 * routing a browser to APNs would break a path that works today.
 */
export function nativePlatformOf(keys: { p256dh?: string; auth?: string }): NativePlatform | null {
  const marker = (keys.p256dh ?? '').trim().toLowerCase();
  if (marker === 'ios' || marker === 'android') return marker;
  return null;
}

/** Which credentials a platform needs, and which of them are absent. */
export function missingCredentials(
  platform: NativePlatform,
  env: NodeJS.ProcessEnv = process.env,
): string[] {
  const names = platform === 'ios' ? APNS_VARS : FCM_VARS;
  return names.filter((name) => !(env[name] ?? '').trim());
}

/**
 * The APNs provider JWT: ES256 over `{iss, iat}` with the key id in the
 * header. Built here rather than pulled from a library because it is
 * fifteen lines and this service's dependency surface is deliberately
 * small — the same reasoning `services/mcp` applies to its arg parser.
 */
export function apnsProviderToken(env: NodeJS.ProcessEnv = process.env, now = Date.now()): string {
  const keyId = (env.APNS_KEY_ID ?? '').trim();
  const teamId = (env.APNS_TEAM_ID ?? '').trim();
  const privateKey = (env.APNS_PRIVATE_KEY ?? '').trim().replace(/\\n/g, '\n');
  const b64 = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString('base64url');
  const header = b64({ alg: 'ES256', kid: keyId });
  const claims = b64({ iss: teamId, iat: Math.floor(now / 1000) });
  const signer = createSign('SHA256');
  signer.update(`${header}.${claims}`);
  const signature = signer.sign({ key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  return `${header}.${claims}.${signature}`;
}

export interface NativeSenderOptions {
  env?: NodeJS.ProcessEnv;
  /** Injected so tests drive the real request shape without a network. */
  fetchImpl?: typeof fetch;
  /** Overridable so a test does not have to reach Apple's or Google's host. */
  apnsHost?: string;
  fcmHost?: string;
  /** Injected so the FCM access token can be stubbed; see `fcmAccessToken`. */
  accessToken?: () => Promise<string>;
}

/**
 * Send one notification to one device.
 *
 * Returns an outcome rather than throwing, because the caller has to
 * distinguish three things and an exception collapses them into one.
 */
export async function sendNative(
  record: NativeRecord,
  payload: NativePayload,
  options: NativeSenderOptions = {},
): Promise<NativeOutcome> {
  const env = options.env ?? process.env;
  const missing = missingCredentials(record.platform, env);
  if (missing.length > 0) {
    // Never a success and never a silent failure. An operator reading
    // "APNS_PRIVATE_KEY is unset" knows what to do.
    return { kind: 'not_configured', missing };
  }
  const doFetch = options.fetchImpl ?? fetch;

  if (record.platform === 'ios') {
    const host = options.apnsHost ?? 'https://api.push.apple.com';
    let res: Response;
    try {
      res = await doFetch(`${host}/3/device/${encodeURIComponent(record.endpoint)}`, {
        method: 'POST',
        headers: {
          authorization: `bearer ${apnsProviderToken(env)}`,
          'apns-topic': (env.APNS_BUNDLE_ID ?? '').trim(),
          'apns-push-type': 'alert',
          // 10 is "deliver immediately"; 5 lets the OS batch. A containment
          // approval is the former, everything else the latter.
          'apns-priority': payload.critical ? '10' : '5',
          ...(payload.tag ? { 'apns-collapse-id': payload.tag.slice(0, 64) } : {}),
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          aps: { alert: { title: payload.title, body: payload.body }, sound: 'default' },
          ...(payload.data ?? {}),
        }),
      });
    } catch (err) {
      return { kind: 'failed', reason: `APNs unreachable: ${String(err)}` };
    }
    if (res.status === 200) return { kind: 'delivered' };
    // 410 is APNs' own "this token is no longer active". 400 with
    // BadDeviceToken means the same thing and is what a simulator token
    // produces, so both prune rather than retrying forever.
    const text = await res.text().catch(() => '');
    if (res.status === 410 || text.includes('BadDeviceToken') || text.includes('Unregistered')) {
      return { kind: 'unregistered', reason: `APNs ${res.status} ${text.slice(0, 120)}` };
    }
    return { kind: 'failed', reason: `APNs ${res.status} ${text.slice(0, 200)}` };
  }

  // Android / FCM HTTP v1.
  const projectId = (env.FCM_PROJECT_ID ?? '').trim();
  const host = options.fcmHost ?? 'https://fcm.googleapis.com';
  let token: string;
  try {
    token = options.accessToken ? await options.accessToken() : await fcmAccessToken(env, doFetch);
  } catch (err) {
    return { kind: 'failed', reason: `FCM access token: ${String(err)}` };
  }
  let res: Response;
  try {
    res = await doFetch(`${host}/v1/projects/${projectId}/messages:send`, {
      method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({
        message: {
          token: record.endpoint,
          notification: { title: payload.title, body: payload.body },
          // FCM data values must be strings; anything else is a 400 the
          // caller cannot act on.
          data: Object.fromEntries(
            Object.entries(payload.data ?? {}).map(([k, v]) => [k, String(v)]),
          ),
          android: {
            priority: payload.critical ? 'HIGH' : 'NORMAL',
            ...(payload.tag ? { collapse_key: payload.tag } : {}),
          },
        },
      }),
    });
  } catch (err) {
    return { kind: 'failed', reason: `FCM unreachable: ${String(err)}` };
  }
  if (res.ok) return { kind: 'delivered' };
  const text = await res.text().catch(() => '');
  if (res.status === 404 || text.includes('UNREGISTERED') || text.includes('NOT_FOUND')) {
    return { kind: 'unregistered', reason: `FCM ${res.status} ${text.slice(0, 120)}` };
  }
  return { kind: 'failed', reason: `FCM ${res.status} ${text.slice(0, 200)}` };
}

/**
 * Exchange the FCM service account for an access token.
 *
 * Google's own libraries do this; pulling one in for a single JWT exchange
 * would add a large dependency to a service that deliberately has few.
 */
export async function fcmAccessToken(
  env: NodeJS.ProcessEnv,
  doFetch: typeof fetch,
  now = Date.now(),
): Promise<string> {
  const raw = (env.FCM_SERVICE_ACCOUNT_JSON ?? '').trim();
  const account = JSON.parse(raw) as { client_email?: string; private_key?: string; token_uri?: string };
  if (!account.client_email || !account.private_key) {
    throw new Error('FCM_SERVICE_ACCOUNT_JSON has no client_email or private_key');
  }
  const b64 = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const issued = Math.floor(now / 1000);
  const header = b64({ alg: 'RS256', typ: 'JWT' });
  const claims = b64({
    iss: account.client_email,
    scope: 'https://www.googleapis.com/auth/firebase.messaging',
    aud: account.token_uri ?? 'https://oauth2.googleapis.com/token',
    iat: issued,
    exp: issued + 3600,
  });
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${claims}`);
  const assertion = `${header}.${claims}.${signer.sign(account.private_key).toString('base64url')}`;

  const res = await doFetch(account.token_uri ?? 'https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion,
    }).toString(),
  });
  if (!res.ok) {
    throw new Error(`token endpoint returned ${res.status}`);
  }
  const body = (await res.json()) as { access_token?: string };
  if (!body.access_token) throw new Error('token endpoint returned no access_token');
  return body.access_token;
}
