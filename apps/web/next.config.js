/** @type {import('next').NextConfig} */

const fs = require('fs');
const path = require('path');

// Repo-root VERSION file is the single source of truth for the app version
// shown in Settings → About. Baked into the bundle at build time since the
// browser has no way to read a file off the deployed container's disk.
// Falls back to "0.0.0" rather than failing the build if some build context
// doesn't carry the file through (e.g. a Dockerfile COPY list falling out of
// sync, or `next build` invoked from an unexpected working directory).
let APP_VERSION = '0.0.0';
try {
  APP_VERSION = fs
    .readFileSync(path.resolve(__dirname, '..', '..', 'VERSION'), 'utf8')
    .trim();
} catch {
  console.warn('[next.config.js] Could not read repo-root VERSION file; using 0.0.0');
}

// ─── Server-side rewrite targets ────────────────────────────────────────────
//
// These are the *origin* URLs the Next.js server uses when proxying
// `/api/v1/*`, `/api/v1/contextual/*`, `/ws/*` and `/sse` to downstream
// services. They never reach the browser — only the Node.js process.
//
// Defaults are localhost for `pnpm --filter @aisoc/web dev` outside Docker.
// In the demo Compose stack the `web` service overrides these via env to
// Docker DNS names (`http://api:8000`, `http://agents:8084`,
// `http://realtime:4000`).
const REALTIME_HOST = process.env.REALTIME_URL || 'http://localhost:8086';
const API_HOST = process.env.API_URL || 'http://localhost:8000';
const AGENTS_HOST = process.env.AGENTS_URL || 'http://localhost:8001';
// Fusion service exposes /entity-risk/*, /ml/*, /metrics, /health at root.
// We surface those to the browser under the same-origin namespace
// /api/v1/fusion/* so the bundle stays host-agnostic.
//
// When FUSION_URL is unset (e.g. the demo Fly.io stack with no fusion
// deployment), the rewrite is omitted entirely so /api/v1/fusion/* falls
// through to the core API catch-all, which exposes a graceful fusion
// gateway (services/api/app/api/v1/endpoints/fusion.py).
const FUSION_HOST = process.env.FUSION_URL || '';
const ENRICHMENT_HOST = process.env.ENRICHMENT_URL || 'http://localhost:8083';
const OSQUERY_TLS_HOST = process.env.OSQUERY_TLS_URL || 'http://localhost:8090';

const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ['@aisoc/ui', '@aisoc/types', '@aisoc/report-card'],
  // pnpm monorepo: anchor Turbopack at the repository root so it can resolve
  // the hoisted `next` package via apps/web/node_modules/next (symlink into
  // the root .pnpm store). Setting this to __dirname caused Turbopack to
  // fail in CI with "We couldn't find the Next.js package (next/package.json)".
  turbopack: {
    root: path.resolve(__dirname, '..', '..'),
  },
  // Mock data in views uses shapes that diverge from the strict typed API
  // contracts. We rely on per-package type-checks (pnpm --filter <pkg> tsc)
  // for correctness; during the production build we skip Next.js's strict
  // gate so the dev container ships even when mock fixtures lag behind a
  // type change. Real API responses are validated at runtime.
  typescript: {
    ignoreBuildErrors: true,
  },
  // ─── Client-side env (baked into the JS bundle at build time) ────────────
  //
  // Defaults are empty strings, which makes every fetch in `lib/api.ts`
  // emit a same-origin path (e.g. `/api/v1/alerts`). Next.js then proxies
  // those paths to the correct service via the rewrites below. This keeps
  // a single image working on:
  //   - localhost:3000 (developer machine)
  //   - https://tryaisoc.com (Cloudflare Tunnel)
  //   - any reverse-proxy in between
  //
  // Override via build args / docker-compose if you ever want the bundle to
  // call a different origin directly (skipping the Next proxy).
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || '',
    NEXT_PUBLIC_AGENTS_URL: process.env.NEXT_PUBLIC_AGENTS_URL || '',
    NEXT_PUBLIC_ACTIONS_URL: process.env.NEXT_PUBLIC_ACTIONS_URL || '',
    NEXT_PUBLIC_FUSION_URL: process.env.NEXT_PUBLIC_FUSION_URL || '',
    NEXT_PUBLIC_THREATINTEL_URL: process.env.NEXT_PUBLIC_THREATINTEL_URL || '',
    NEXT_PUBLIC_ENRICHMENT_URL: process.env.NEXT_PUBLIC_ENRICHMENT_URL || '',
    NEXT_PUBLIC_WS_URL: process.env.NEXT_PUBLIC_WS_URL || '',
    NEXT_PUBLIC_REALTIME_URL: process.env.NEXT_PUBLIC_REALTIME_URL || '',
    NEXT_PUBLIC_TENANT_ID: process.env.NEXT_PUBLIC_TENANT_ID || 'default',
    NEXT_PUBLIC_PURPLE_TEAM_API: process.env.NEXT_PUBLIC_PURPLE_TEAM_API || '',
    NEXT_PUBLIC_HONEYTOKENS_URL: process.env.NEXT_PUBLIC_HONEYTOKENS_URL || '',
    NEXT_PUBLIC_OSQUERY_TLS_URL: process.env.NEXT_PUBLIC_OSQUERY_TLS_URL || '',
    NEXT_PUBLIC_APP_VERSION: APP_VERSION,
  },
  // ─── Permanent URL redirects (browser-visible) ───────────────────────────
  //
  // These run *before* rewrites and emit real 308 responses (so search
  // engines update their index, cached links retain SEO value, and
  // share-card crawlers follow the redirect). Use this surface only for
  // *retired* public URLs that still get external traffic — every other
  // route should live under apps/web/src/app/.
  async redirects() {
    return [
      // /signup is intentionally not a page. AiSOC is MIT-licensed and
      // self-hostable, so the public entry point is the interactive
      // demo at /dashboard (anonymous, demo-tenant, no account needed).
      // The /signup URL still appears in cached search results, old
      // blog posts, and a few external decks, so we 308 it to the
      // intended destination instead of letting Next.js render the
      // bare unbranded 404 page. The /waitlist surface is for the
      // managed-instance invite-only beta — a different flow with its
      // own page.
      {
        source: '/signup',
        destination: '/dashboard',
        permanent: true,
      },
    ];
  },

  // ─── Same-origin proxy rules ─────────────────────────────────────────────
  //
  // Order matters: more specific paths (contextual, realtime healthz) must
  // come before the generic `/api/v1/:path*` catch-all so they hit the
  // right downstream service.
  async rewrites() {
    return [
      // WebSocket / SSE — realtime gateway.
      {
        source: '/ws/:path*',
        destination: `${REALTIME_HOST}/ws/:path*`,
      },
      {
        source: '/sse',
        destination: `${REALTIME_HOST}/sse`,
      },
      // Realtime health probe (used by status pages).
      {
        source: '/api/v1/realtime/healthz',
        destination: `${REALTIME_HOST}/healthz`,
      },
      // Agents service owns contextual actions, playbooks, hunt search,
      // and copilot chat. These must come before the `/api/v1/:path*`
      // catch-all so they don't get sent to the core API.
      //
      // NOTE: `/api/v1/investigations*` is intentionally NOT routed here.
      // The agents service only exposes the *write* side (POST to start a
      // run, GET /{run_id} for the in-memory orchestrator state). The
      // browser-facing *read* side — list runs, replay events, explain
      // step, fetch artifacts, cost aggregates — is owned by the core API
      // (see services/api/app/api/v1/endpoints/investigations.py, backed
      // by the persistent ledger in Postgres). Routing those reads to
      // agents returns 405/404 and breaks the case workspace ledger pane.
      // We let `/api/v1/investigations*` fall through to the core API
      // catch-all at the bottom of this list.
      {
        source: '/api/v1/contextual/:path*',
        destination: `${AGENTS_HOST}/api/v1/contextual/:path*`,
      },
      {
        source: '/api/v1/playbooks/:path*',
        destination: `${AGENTS_HOST}/api/v1/playbooks/:path*`,
      },
      {
        source: '/api/v1/playbooks',
        destination: `${AGENTS_HOST}/api/v1/playbooks`,
      },
      // Hunt search + saved searches (singular /hunt, distinct from /hunts corpus)
      {
        source: '/api/v1/hunt/:path*',
        destination: `${AGENTS_HOST}/api/v1/hunt/:path*`,
      },
      {
        source: '/api/v1/hunt',
        destination: `${AGENTS_HOST}/api/v1/hunt`,
      },
      // Copilot persistent chat conversations
      {
        source: '/api/v1/copilot/:path*',
        destination: `${AGENTS_HOST}/api/v1/copilot/:path*`,
      },
      {
        source: '/api/v1/copilot',
        destination: `${AGENTS_HOST}/api/v1/copilot`,
      },
      // Hunt corpus management (plural /hunts)
      {
        source: '/api/v1/hunts/:path*',
        destination: `${AGENTS_HOST}/api/v1/hunts/:path*`,
      },
      {
        source: '/api/v1/hunts',
        destination: `${AGENTS_HOST}/api/v1/hunts`,
      },
      // osquery-TLS service: pack catalog, FIM events, distributed queries
      {
        source: '/api/v1/osquery/:path*',
        destination: `${OSQUERY_TLS_HOST}/api/v1/osquery/:path*`,
      },
      // Enrichment service (Go service; paths differ from /api/v1 prefix)
      {
        source: '/api/v1/enrichment/lookup',
        destination: `${ENRICHMENT_HOST}/enrich`,
      },
      {
        source: '/api/v1/enrichment/bulk',
        destination: `${ENRICHMENT_HOST}/enrich/bulk`,
      },
      // Fusion service exposes the Risk-Based Alerting (entity rollup) queue
      // and ML scoring endpoints at its own root (no /api/v1 prefix on the
      // service side). Proxy /api/v1/fusion/:path* → fusion's /:path* so the
      // browser only ever sees same-origin URLs.
      //
      // Only emit the fusion-specific rewrite when FUSION_URL is configured.
      // Without it, /api/v1/fusion/* falls through to the core API, which
      // now hosts a fusion gateway that returns graceful empty payloads
      // when no upstream fusion is reachable.
      ...(FUSION_HOST
        ? [
            {
              source: '/api/v1/fusion/:path*',
              destination: `${FUSION_HOST}/:path*`,
            },
          ]
        : []),
      // Catch-all for the core API.
      {
        source: '/api/v1/:path*',
        destination: `${API_HOST}/api/v1/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
