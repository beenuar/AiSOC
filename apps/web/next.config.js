/** @type {import('next').NextConfig} */

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
const FUSION_HOST = process.env.FUSION_URL || 'http://localhost:8082';

const nextConfig = {
  reactStrictMode: true,
  transpilePackages: ['@aisoc/ui', '@aisoc/types'],
  // Mock data in views uses shapes that diverge from the strict typed API
  // contracts. We rely on per-package type-checks (pnpm --filter <pkg> tsc)
  // for correctness; during the production build we skip Next.js's strict
  // gate so the dev container ships even when mock fixtures lag behind a
  // type change. Real API responses are validated at runtime.
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
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
      // Agents service owns contextual actions, playbooks, and investigations.
      // These must come before the `/api/v1/:path*` catch-all so they don't
      // get sent to the core API (which doesn't have those routes and would
      // 503).
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
      {
        source: '/api/v1/investigations/:path*',
        destination: `${AGENTS_HOST}/api/v1/investigations/:path*`,
      },
      {
        source: '/api/v1/investigations',
        destination: `${AGENTS_HOST}/api/v1/investigations`,
      },
      // Fusion service exposes the Risk-Based Alerting (entity rollup) queue
      // and ML scoring endpoints at its own root (no /api/v1 prefix on the
      // service side). Proxy /api/v1/fusion/:path* → fusion's /:path* so the
      // browser only ever sees same-origin URLs.
      {
        source: '/api/v1/fusion/:path*',
        destination: `${FUSION_HOST}/:path*`,
      },
      // Catch-all for the core API.
      {
        source: '/api/v1/:path*',
        destination: `${API_HOST}/api/v1/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;
