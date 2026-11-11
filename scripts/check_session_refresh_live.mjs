/**
 * Exercise the production browser client over HTTP against a real API/database.
 *
 * Run with Node 22.18+:
 *   node scripts/check_session_refresh_live.mjs /path/to/isolated-fixture.json
 *
 * The fixture supplies base_url, email, password, user_id, tenant_id and an
 * expired_access_token signed by that isolated API. Never use a production
 * account. Only browser storage/navigation are simulated; fetch responses,
 * password verification, JWT validation and user lookup are real.
 * An optional third argument selects a baseline api.ts for a negative control.
 */
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

assert.ok(process.argv[2], 'Pass the path to an isolated API fixture');
const fixture = JSON.parse(await readFile(process.argv[2], 'utf8'));
const origin = new URL(fixture.base_url).origin;
assert.ok(['127.0.0.1', 'localhost'].includes(new URL(origin).hostname), 'Use an isolated loopback API');
// The fixture's credentials flow into requests by design: this harness's
// negative control sends an expired token signed by the isolated API and
// asserts the 401. The destination cannot leave loopback (asserted above),
// and the token must at least be a structurally valid JWT — a malformed
// fixture should fail here with a clear message, not as a confusing
// assertion three calls later. CodeQL's js/file-access-to-http sees the
// file-to-request flow and cannot see either constraint; if the alert
// persists it is dismissed with this reasoning, per the repo's documented
// disposition for guards the tracker cannot follow.
const JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
assert.ok(JWT_SHAPE.test(fixture.expired_access_token), 'expired_access_token must be a structurally valid JWT');

const storage = new Map();
const redirects = [];
globalThis.window = {
  localStorage: {
    getItem: (key) => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: (key) => storage.delete(key),
  },
  location: { origin, pathname: '/alerts', search: '', assign: (url) => redirects.push(url) },
};
process.env.NEXT_PUBLIC_API_URL = origin;
const source = process.argv[3]
  ? pathToFileURL(resolve(process.argv[3]))
  : new URL('../apps/web/src/lib/api.ts', import.meta.url);
const { apiRequest, apiFetch, authApi, AUTH_TOKEN_KEY, AUTH_REFRESH_KEY } = await import(source.href);

const realFetch = globalThis.fetch;
const calls = [];
globalThis.fetch = async (url, init) => {
  const response = await realFetch(url, init);
  calls.push({ path: new URL(url).pathname, status: response.status });
  return response;
};

const login = await authApi.login(fixture.email, fixture.password);
assert.equal(login.user.id, fixture.user_id);
const expired = await realFetch(`${origin}/api/v1/auth/me`, {
  headers: { Authorization: `Bearer ${fixture.expired_access_token}` },
});
assert.equal(expired.status, 401, 'The negative access credential must really be expired');

storage.set(AUTH_TOKEN_KEY, fixture.expired_access_token);
calls.length = 0;
const users = await Promise.all(Array.from({ length: 4 }, () => apiRequest('/api/v1/auth/me')));
assert.ok(users.every((user) => user.id === fixture.user_id && user.tenant_id === fixture.tenant_id));
assert.equal(calls.filter((call) => call.path.endsWith('/refresh')).length, 1);
assert.equal(redirects.length, 0);
assert.ok(storage.get(AUTH_REFRESH_KEY));
console.log('PASS: four concurrent production-client requests renew once against real HTTP/API/PostgreSQL');

storage.set(AUTH_TOKEN_KEY, fixture.expired_access_token);
const raw = await apiFetch('/api/v1/auth/me');
assert.equal(raw.status, 200);
assert.equal(raw.bodyUsed, false);
assert.equal((await raw.json()).id, fixture.user_id);
assert.equal(redirects.length, 0);
console.log('PASS: raw-response client renews and leaves the real response body unread');

// A well-formed but unsigned access token looks live to the browser. The real
// API rejects it, forcing the reactive 401 -> refresh -> replay path.
const encode = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
storage.set(AUTH_TOKEN_KEY, `${encode({ alg: 'HS256' })}.${encode({
  sub: fixture.user_id, tenant_id: fixture.tenant_id, exp: Math.floor(Date.now() / 1000) + 600,
})}.invalid-signature`);
calls.length = 0;
assert.equal((await apiRequest('/api/v1/auth/me')).id, fixture.user_id);
assert.deepEqual(calls.map((call) => call.status), [401, 200, 200]);
assert.equal(redirects.length, 0);
console.log('PASS: real server 401 is recovered through refresh and one successful replay');

storage.set(AUTH_TOKEN_KEY, fixture.expired_access_token);
storage.set(AUTH_REFRESH_KEY, 'invalid-refresh-credential');
await assert.rejects(apiRequest('/api/v1/auth/me'), (error) => error.status === 401);
assert.equal(storage.has(AUTH_TOKEN_KEY), false);
assert.equal(storage.has(AUTH_REFRESH_KEY), false);
assert.deepEqual(redirects, ['/login?next=%2Falerts']);
console.log('PASS: real refresh rejection clears credentials and redirects to sign-in');
