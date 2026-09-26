#!/usr/bin/env node
/**
 * Re-resolve the Next.js rewrite table from the live environment.
 *
 * WHY THIS EXISTS
 * ---------------
 * `next build` evaluates `rewrites()` once and compiles the results —
 * destinations included — into `.next/routes-manifest.json`. `next start`
 * loads `next.config.js` again (it prints "Running next.config.js took …"),
 * but production routing is served from that manifest, so the destinations
 * are build-time constants. Setting `API_URL` on a *pulled* image therefore
 * changes nothing, and the same is true of every `NEXT_PUBLIC_*` value, which
 * Next inlines into the JS bundle at build time.
 *
 * The practical result was that the console could only ever talk to the hosts
 * the image happened to be built with (`http://api:8000`, `http://agents:8084`,
 * `http://realtime:4000`). That is correct by coincidence on the bundled
 * Compose network, where the service DNS names match, and wrong everywhere
 * else — notably on Kubernetes, where the Services are `<release>-api` and the
 * baked hostname resolves to nothing at all.
 *
 * This script closes that gap: it re-evaluates `rewrites()` against the
 * current process environment and writes the resulting destinations back into
 * the manifest before the server starts. `next.config.js` stays the single
 * definition of the routing table — nothing here duplicates a route — so a
 * rewrite added later is picked up with no change to this file.
 *
 * Entries are matched on `source`, which is static in `next.config.js`; only
 * `destination` varies with the environment. The compiled `regex` is left
 * untouched because it is derived from `source`, which we never change.
 *
 * FAILURE POSTURE
 * ---------------
 * An operator who set an upstream variable and did not get it applied is
 * misconfigured in a way no retry clears, and booting anyway would serve a
 * console silently pointed at the wrong host. So: if an upstream variable is
 * set explicitly and cannot be applied, exit non-zero and name it. If nothing
 * was set, a manifest we cannot read is not worth refusing to boot over —
 * warn, and start on the built-in defaults.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const APP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST = resolve(APP_DIR, '.next', 'routes-manifest.json');
const CONFIG = resolve(APP_DIR, 'next.config.js');

/**
 * The environment variables `next.config.js` reads to build destinations.
 * Used only to decide whether the operator asked for something specific —
 * the values themselves are read by the config, not by this script.
 */
const UPSTREAM_VARS = [
  'API_URL',
  'AGENTS_URL',
  'REALTIME_URL',
  'FUSION_URL',
  'ENRICHMENT_URL',
  'OSQUERY_TLS_URL',
];

const log = (msg) => process.stdout.write(`[runtime-routes] ${msg}\n`);
const warn = (msg) => process.stderr.write(`[runtime-routes] ${msg}\n`);

const explicit = UPSTREAM_VARS.filter((v) => (process.env[v] ?? '') !== '');

function fail(reason) {
  warn(`cannot apply ${explicit.join(', ')}: ${reason}`);
  warn('Refusing to start: the console would silently use the addresses this');
  warn('image was built with, not the ones you configured. Unset those');
  warn('variables to start on the built-in defaults.');
  process.exit(1);
}

function giveUp(reason) {
  if (explicit.length > 0) fail(reason);
  warn(`${reason} — starting on the addresses baked in at build time.`);
  process.exit(0);
}

/** Every rewrite bucket the manifest may carry, flattened to one list. */
function entriesOf(rewrites) {
  if (Array.isArray(rewrites)) return rewrites;
  if (rewrites && typeof rewrites === 'object') {
    return ['beforeFiles', 'afterFiles', 'fallback'].flatMap((k) =>
      Array.isArray(rewrites[k]) ? rewrites[k] : [],
    );
  }
  return [];
}

let manifest;
try {
  manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));
} catch (err) {
  giveUp(`could not read ${MANIFEST} (${err.message})`);
}

let desired;
try {
  const config = require(CONFIG);
  desired = entriesOf(await config.rewrites());
} catch (err) {
  giveUp(`could not evaluate rewrites() in next.config.js (${err.message})`);
}

const wanted = new Map(desired.map((r) => [r.source, r.destination]));
const baked = entriesOf(manifest.rewrites);

let changed = 0;
const origins = new Map();
for (const entry of baked) {
  const next = wanted.get(entry.source);
  if (typeof next !== 'string') continue;
  wanted.delete(entry.source);
  if (next === entry.destination) continue;
  entry.destination = next;
  changed += 1;
  try {
    origins.set(new URL(next).origin, true);
  } catch {
    /* relative destination — nothing to report as an origin */
  }
}

// A source the config emits now but the manifest never compiled cannot be
// added here: the manifest entry carries a `regex` that only `next build`
// produces. Say so rather than dropping it silently.
for (const source of wanted.keys()) {
  warn(
    `"${source}" is routed by next.config.js under this environment but was ` +
      'not compiled into this image. Rebuild the image to enable it.',
  );
}

if (changed === 0) {
  log('upstream addresses already match the environment; nothing to re-point.');
  process.exit(0);
}

try {
  writeFileSync(MANIFEST, JSON.stringify(manifest));
} catch (err) {
  giveUp(`could not write ${MANIFEST} (${err.message})`);
}

log(
  `re-pointed ${changed} route${changed === 1 ? '' : 's'} to ` +
    `${[...origins.keys()].sort().join(', ')}`,
);
