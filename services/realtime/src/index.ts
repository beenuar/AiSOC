import express from 'express';
import cors from 'cors';
import http from 'http';
import { WebSocketServer } from 'ws';
import { Kafka } from 'kafkajs';
import Redis from 'ioredis';
import pino from 'pino';
import rateLimit from 'express-rate-limit';

import { PushManager } from './push';
import { resolveTicketSecret, verifyRealtimeTicket } from './auth';

const log = pino({ level: process.env.LOG_LEVEL || 'info' });

const PORT = parseInt(process.env.PORT || '8086', 10);
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379/4';
const KAFKA_BROKERS = (process.env.KAFKA_BOOTSTRAP_SERVERS || 'localhost:9092').split(',');
const KAFKA_TOPIC_FUSED = process.env.KAFKA_TOPIC_FUSED || 'aisoc.alerts.fused';
// T1.4 (v8.0): graph-update channel. The ingest-side graph writer publishes
// one envelope per node/edge upsert on `security.graph_updates`; we fan out
// to WebSocket clients subscribed to `/ws/graph`. Topic name matches the
// default in services/ingest/internal/config/config.go (env
// `AISOC_GRAPH_UPDATES_TOPIC`) so the two services agree without manual
// plumbing. Set to an empty string to disable the consumer entirely (useful
// in tests that don't spin up Kafka for graph traffic).
const KAFKA_TOPIC_GRAPH_UPDATES =
  process.env.AISOC_GRAPH_UPDATES_TOPIC ||
  process.env.KAFKA_TOPIC_GRAPH_UPDATES ||
  'security.graph_updates';
const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_SUBJECT = process.env.VAPID_SUBJECT || 'mailto:soc@example.com';
const PUSH_REDIS = new Redis(REDIS_URL);

// Mirror the shared Python helper in services/api/app/core/cors.py:
//   1. AISOC_CORS_ORIGINS (canonical, comma-separated)
//   2. CORS_ORIGINS (legacy alias kept for Helm charts / dev scripts)
//   3. Default allow-list (local dev + tryaisoc.com)
// SSE + WebSocket connections from the console carry the auth cookie, so
// allow_credentials is effectively in play here. If an operator sets the
// allow-list to "*" we refuse to start in production rather than silently
// turn /sse into a cross-origin CSRF target.
const DEFAULT_CORS_ORIGINS = [
  'http://localhost:3000',
  'http://localhost:3001',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:3001',
  'https://tryaisoc.com',
  'https://www.tryaisoc.com',
];

function resolveCorsOrigins(): string[] {
  for (const env of ['AISOC_CORS_ORIGINS', 'CORS_ORIGINS']) {
    const raw = (process.env[env] || '').trim();
    if (!raw) continue;
    const parts = raw.split(',').map((s) => s.trim()).filter(Boolean);
    if (parts.length > 0) return parts;
  }
  return [...DEFAULT_CORS_ORIGINS];
}

function isProductionEnv(): boolean {
  const env = (process.env.AISOC_ENV || process.env.ENVIRONMENT || process.env.APP_ENV || '')
    .trim()
    .toLowerCase();
  return env === 'production' || env === 'prod';
}

const CORS_ORIGINS = resolveCorsOrigins();
const CORS_ALLOW_CREDENTIALS = !CORS_ORIGINS.includes('*');
if (CORS_ORIGINS.includes('*')) {
  if (isProductionEnv()) {
    // Fail loud at startup instead of silently exposing /sse + /internal/*.
    throw new Error(
      'realtime: refusing to start with wildcard CORS origin in production. ' +
        'Set AISOC_CORS_ORIGINS to an explicit allow-list.',
    );
  }
  log.warn(
    'CORS wildcard origin in dev — disabling credentials for the SSE + internal routes',
  );
}
log.info(
  { origins: CORS_ORIGINS, allowCredentials: CORS_ALLOW_CREDENTIALS },
  'CORS configured',
);

// --- Realtime ticket auth (Issue #239) -------------------------------------
// Resolve the shared HS256 secret used to verify the short-lived tickets the
// API mints at POST /api/v1/realtime/ticket. `null` means we are NOT configured
// to verify (production with AISOC_REALTIME_JWT_SECRET unset/insecure) — in that
// case every WS upgrade and SSE request is rejected (fail closed) rather than
// silently accepting unauthenticated subscribers (the bug Issue #239 closes).
const REALTIME_TICKET_SECRET = resolveTicketSecret();
if (REALTIME_TICKET_SECRET === null) {
  log.error(
    'AISOC_REALTIME_JWT_SECRET is unset or insecure in a production environment — ' +
      'realtime WS/SSE connections will be rejected until a real secret is wired.',
  );
} else if (
  REALTIME_TICKET_SECRET === 'aisoc-dev-realtime-ticket-secret-not-for-production'
) {
  log.warn('Using the shared development realtime ticket secret — do NOT use in production.');
}

/**
 * Verify the `?token=` ticket on a realtime request URL. Returns the verified
 * tenant_id, or `null` if the request must be rejected. Centralises the
 * fail-closed decision for both the WS upgrade and the SSE handler.
 */
function authenticateRealtime(url: URL): string | null {
  if (REALTIME_TICKET_SECRET === null) return null;
  const token = url.searchParams.get('token') || '';
  const claims = verifyRealtimeTicket(token, REALTIME_TICKET_SECRET);
  if (!claims) return null;
  return claims.tenant_id;
}

const pushManager = new PushManager({
  redis: PUSH_REDIS,
  logger: log,
  vapidPublicKey: VAPID_PUBLIC_KEY,
  vapidPrivateKey: VAPID_PRIVATE_KEY,
  vapidSubject: VAPID_SUBJECT,
});

// --- Express setup ---
const app = express();
// Use an explicit allow-list rather than the default reflective CORS. The
// console (apps/web) sends a session cookie on `/v1/push/*` and `/internal/*`
// calls go agent-to-realtime over the private network; we must never echo
// back a wildcard with credentials enabled.
app.use(
  cors({
    origin(origin, callback) {
      if (!origin) {
        // Same-origin / curl / health probes — let them through.
        callback(null, true);
        return;
      }
      if (CORS_ORIGINS.includes('*') || CORS_ORIGINS.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error(`Origin ${origin} not allowed by CORS`));
    },
    credentials: CORS_ALLOW_CREDENTIALS,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: [
      'Accept',
      'Authorization',
      'Content-Type',
      'X-Tenant-ID',
      'X-Internal-Token',
    ],
    maxAge: 300,
  }),
);
app.use(express.json());

const server = http.createServer(app);

// --- WebSocket server ---
// Accept both `/ws` (legacy) and `/ws/:channel` (preferred). The channel lets
// callers say up-front what they care about (alerts, cases, agents, insights,
// graph, all) so we can avoid spamming a panel that only renders alerts with
// case/agent traffic.
//
// The `insights` channel (T3.1) is consumed by
// apps/web/src/app/(app)/dashboards/soc-insights/page.tsx to know when to
// re-fetch the aggregator endpoint. The payload itself stays small —
// it's a poke, not a data delivery.
//
// The `graph` channel (T1.4, v8.0) is consumed by the Investigation Rail and
// Attack Chain views to light up new entity nodes / edges in near-real-time.
// Unlike `insights`, the payload IS the delivery: each message carries the
// full GraphUpdate envelope from `security.graph_updates` (entity_id,
// change_type, label, rel_type, from, to, properties, schema_version), so
// the client can apply the mutation locally without re-querying Neo4j.
type Channel = 'alerts' | 'cases' | 'agents' | 'insights' | 'graph' | 'all';
const VALID_CHANNELS: Channel[] = ['alerts', 'cases', 'agents', 'insights', 'graph', 'all'];

const wss = new WebSocketServer({ noServer: true });

server.on('upgrade', (req, socket, head) => {
  const url = new URL(req.url || '/', `http://localhost`);
  const parts = url.pathname.split('/').filter(Boolean);
  // /ws            → channel "all"
  // /ws/<channel>  → that channel (must be in VALID_CHANNELS)
  if (parts[0] !== 'ws') {
    socket.destroy();
    return;
  }
  const requested = (parts[1] as Channel | undefined) || 'all';
  if (!VALID_CHANNELS.includes(requested)) {
    socket.destroy();
    return;
  }
  // Authenticate the connection from the short-lived ticket BEFORE completing
  // the upgrade. Reject (401 + close) when the ticket is missing/invalid or the
  // service is not configured to verify — never accept an anonymous subscriber.
  const verifiedTenant = authenticateRealtime(url);
  if (verifiedTenant === null) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    (ws as any)._aisocChannel = requested;
    // Tenant is derived from the verified ticket claim, NOT the URL query, so a
    // client can never subscribe to another tenant's fan-out.
    (ws as any)._aisocTenant = verifiedTenant;
    wss.emit('connection', ws, req);
  });
});

// Client registry keyed by tenantId. We additionally tag each socket with the
// channel it subscribed to so broadcasts can filter cheaply.
const clients = new Map<string, Set<any>>();

// Simple IP-based connection rate limiter: max 20 WS connections per IP per minute.
const wsConnectCounts = new Map<string, { count: number; resetAt: number }>();
const WS_RATE_LIMIT = 20;
const WS_RATE_WINDOW_MS = 60_000;

function wsRateLimitExceeded(ip: string): boolean {
  const now = Date.now();
  let entry = wsConnectCounts.get(ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + WS_RATE_WINDOW_MS };
    wsConnectCounts.set(ip, entry);
  }
  entry.count += 1;
  return entry.count > WS_RATE_LIMIT;
}

wss.on('connection', (ws, req) => {
  const ip = (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim()
    || req.socket.remoteAddress
    || 'unknown';
  if (wsRateLimitExceeded(ip)) {
    ws.close(1008, 'Rate limit exceeded');
    return;
  }
  // Tenant comes from the verified ticket claim stashed during the upgrade
  // (see server.on('upgrade')), never from a client-supplied query parameter.
  const tenantId = (ws as any)._aisocTenant || 'default';
  const channel: Channel = (ws as any)._aisocChannel ?? 'all';

  if (!clients.has(tenantId)) {
    clients.set(tenantId, new Set());
  }
  clients.get(tenantId)!.add(ws);
  log.info(
    { tenantId, channel, totalClients: clients.get(tenantId)!.size },
    'WebSocket client connected',
  );

  ws.on('close', () => {
    clients.get(tenantId)?.delete(ws);
    log.info({ tenantId, channel }, 'WebSocket client disconnected');
  });

  ws.send(JSON.stringify({ type: 'connected', tenantId, channel }));
});

/**
 * Map message type → which channel(s) should receive it. "all" always wins.
 * Add new mappings here when you wire additional Kafka topics through.
 */
const CHANNEL_FOR_TYPE: Record<string, Channel[]> = {
  'alert.fused': ['alerts', 'all'],
  'case.updated': ['cases', 'all', 'insights'],
  'agent.event': ['agents', 'all'],
  // T3.1: SOC Insights dashboard tick. Both the dedicated `insights`
  // subscribers and any `all`-subscribed admin consoles get the poke.
  'insights_updated': ['insights', 'all'],
  // T1.4 (v8.0): graph-mutation fan-out from the ingest-side writer.
  // `graph.update` carries the full GraphUpdate envelope; `graph` and
  // `all` subscribers both receive it. We deliberately do NOT include
  // `insights` here — the SOC Insights dashboard is a stats poke, not a
  // graph-render surface.
  'graph.update': ['graph', 'all'],
};

function broadcastToTenant(tenantId: string, message: { type: string } & Record<string, unknown>) {
  const tenantClients = clients.get(tenantId);
  if (!tenantClients) return;

  const allowed = CHANNEL_FOR_TYPE[message.type] ?? ['all'];
  const payload = JSON.stringify(message);
  for (const client of tenantClients) {
    if (client.readyState !== 1 /* OPEN */) continue;
    const subscribed: Channel = (client as any)._aisocChannel ?? 'all';
    if (subscribed === 'all' || allowed.includes(subscribed)) {
      client.send(payload);
    }
  }
}

// --- Insights tick (T3.1) ---------------------------------------------------
// The SOC Insights dashboard (apps/web/src/app/(app)/dashboards/soc-insights)
// renders 7 rolling-window tiles that need to stay fresh while an analyst
// keeps the page open. Rather than have the client poll on a setInterval
// (which fights React's strict-mode double-renders and burns auth headers),
// we drive the cadence from the server: every 30s, broadcast a tiny
// `insights_updated` poke to every tenant with an active socket. The web
// client listens on the `insights` channel and uses the poke to revalidate
// its SWR cache against /v1/insights/soc.
//
// The poke is intentionally payload-free so we don't have to keep the
// realtime service in sync with the aggregator's schema; the dashboard
// pulls fresh numbers from the API.
const INSIGHTS_TICK_MS = Number.parseInt(
  process.env.INSIGHTS_TICK_MS || '30000',
  10,
);

function broadcastInsightsTick(): void {
  for (const tenantId of clients.keys()) {
    broadcastToTenant(tenantId, {
      type: 'insights_updated',
      reason: 'tick',
      timestamp: new Date().toISOString(),
    });
  }
}

// In tests we set INSIGHTS_TICK_MS=0 to suppress the timer; production keeps
// the 30s cadence the dashboard spec calls for.
if (INSIGHTS_TICK_MS > 0) {
  setInterval(broadcastInsightsTick, INSIGHTS_TICK_MS).unref?.();
}

// Rate limiters using express-rate-limit (recognised by CodeQL js/missing-rate-limiting).
const sseRateLimit = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded' },
});

const internalEventRateLimit = rateLimit({
  windowMs: 60_000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded' },
});

const internalPushRateLimit = rateLimit({
  windowMs: 60_000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded' },
});

// --- SSE endpoint ---
app.get('/sse', sseRateLimit, (req, res) => {
  // Authenticate from the short-lived ticket and derive the tenant from the
  // verified claim. Reject (401) when the ticket is missing/invalid or the
  // service is not configured to verify — SSE is no longer an open stream.
  const reqUrl = new URL(req.originalUrl, 'http://localhost');
  const tenantId = authenticateRealtime(reqUrl);
  if (tenantId === null) {
    res.status(401).json({ error: 'unauthorized' });
    return;
  }

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  // CORS headers for SSE are emitted by the `cors()` middleware on lines
  // ~118–143 above, which the `cors` npm package implements safely (CodeQL
  // recognises `cors({ origin: <function> })` as a sanitiser). SSE auth is
  // done via the short-lived `?token=` ticket verified above (Issue #239),
  // not via a session cookie, so we deliberately do not enable
  // `Access-Control-Allow-Credentials` on this endpoint — that eliminates
  // the entire "CORS misconfiguration for credentials transfer" attack
  // surface that CodeQL warns about.
  res.flushHeaders();

  const heartbeat = setInterval(() => {
    res.write('event: heartbeat\ndata: {}\n\n');
  }, 30000);

  // Register as SSE client via Redis pub/sub
  const sub = new Redis(REDIS_URL);
  sub.subscribe(`aisoc:events:${tenantId}`);
  sub.on('message', (_channel: string, message: string) => {
    res.write(`data: ${message}\n\n`);
  });

  req.on('close', () => {
    clearInterval(heartbeat);
    sub.disconnect();
  });
});

// Single shared Kafka client so we don't spin up a second TCP fan-out for
// each topic; kafkajs multiplexes consumers internally.
const kafka = new Kafka({
  clientId: 'aisoc-realtime',
  brokers: KAFKA_BROKERS,
  retry: { retries: 5 },
});

// --- Kafka consumer: bridge fused alerts to WebSocket clients ---
async function startKafkaConsumer() {
  const consumer = kafka.consumer({ groupId: 'aisoc-realtime-ws' });

  await consumer.connect();
  await consumer.subscribe({ topic: KAFKA_TOPIC_FUSED, fromBeginning: false });

  log.info({ topic: KAFKA_TOPIC_FUSED }, 'Kafka consumer connected');

  await consumer.run({
    eachMessage: async ({ message }) => {
      if (!message.value) return;
      try {
        const event = JSON.parse(message.value.toString());
        const tenantId = event?.alert?.tenant_id || event?.tenant_id || 'default';

        broadcastToTenant(tenantId, {
          type: 'alert.fused',
          payload: event,
          timestamp: new Date().toISOString(),
        });

        // Fan out P0/critical alerts to mobile responders. Lower-severity
        // alerts stay WebSocket-only so we don't pager-storm on-call.
        const severity = String(
          event?.alert?.severity ?? event?.severity ?? '',
        ).toLowerCase();
        if (
          pushManager.enabled &&
          (severity === 'critical' || severity === 'high')
        ) {
          const alertId =
            event?.alert?.id ?? event?.alert?.alert_id ?? event?.id ?? 'unknown';
          const title = `${severity === 'critical' ? 'P0' : 'P1'} alert · ${
            event?.alert?.title ?? event?.title ?? 'New alert'
          }`;
          pushManager
            .sendToTarget(
              { tenant_id: tenantId, topic: 'p0_alert' },
              {
                title,
                body:
                  event?.alert?.summary ??
                  event?.summary ??
                  'Tap to triage in the responder console',
                url: `/responder/triage/${alertId}`,
                tag: `alert-${alertId}`,
                topic: 'p0_alert',
                severity: severity as 'critical' | 'high',
                alert_id: String(alertId),
              },
            )
            .catch((err: unknown) =>
              log.warn({ err, tenantId }, 'push fan-out for fused alert failed'),
            );
        }
      } catch (err) {
        log.warn({ err }, 'Failed to parse Kafka message');
      }
    },
  });
}

// --- Kafka consumer: bridge graph mutations to WebSocket clients (T1.4) ---
// The ingest-side graph writer (services/ingest/internal/graph/writer.go)
// publishes one envelope per node/edge upsert on `security.graph_updates`.
// We fan that stream out to clients subscribed to `/ws/graph` (or `/ws/all`),
// scoped by tenant. We deliberately run this on its own consumer group so a
// graph-side stall can't backpressure the fused-alert fan-out — and vice
// versa. A failure to start (Kafka unreachable, topic missing, etc.) is
// logged and surfaced via the outer retry wrapper; it does NOT crash the
// process, because the alert fan-out path is the higher-priority surface.
async function startGraphUpdateConsumer() {
  if (!KAFKA_TOPIC_GRAPH_UPDATES) {
    log.info('Graph update consumer disabled (empty KAFKA_TOPIC_GRAPH_UPDATES)');
    return;
  }

  const consumer = kafka.consumer({ groupId: 'aisoc-realtime-graph' });

  await consumer.connect();
  await consumer.subscribe({
    topic: KAFKA_TOPIC_GRAPH_UPDATES,
    // We never want to replay the full graph history on a realtime restart —
    // a panel that connects today should see deltas from now, not from the
    // start of the topic.
    fromBeginning: false,
  });

  log.info(
    { topic: KAFKA_TOPIC_GRAPH_UPDATES, groupId: 'aisoc-realtime-graph' },
    'Graph update Kafka consumer connected',
  );

  await consumer.run({
    eachMessage: async ({ message }) => {
      if (!message.value) return;
      try {
        // The Go writer emits the camel-case-on-the-wire form documented in
        // services/ingest/internal/graph/writer.go: `entity_id`,
        // `change_type`, `ts`, `label`, `rel_type`, `from`, `to`,
        // `properties`, `schema_version`, `tenant_id`. Anything else is
        // treated as a malformed envelope and dropped.
        const update = JSON.parse(message.value.toString()) as {
          entity_id?: string;
          change_type?: string;
          ts?: string;
          label?: string;
          rel_type?: string;
          from?: string;
          to?: string;
          properties?: Record<string, unknown>;
          schema_version?: string;
          tenant_id?: string;
        };

        if (!update.entity_id || !update.change_type) {
          // Headerless or partial envelopes are almost always a producer
          // bug — log once at warn so we notice in CI but don't tear the
          // consumer down. (kafkajs auto-commits the offset either way.)
          log.warn(
            { entity_id: update.entity_id, change_type: update.change_type },
            'Dropping malformed graph update (missing entity_id or change_type)',
          );
          return;
        }

        // Per-tenant fan-out. Default to "default" so single-tenant
        // self-hosted deploys keep working without explicit tenant tagging
        // (matches the policy on the fused-alerts consumer above).
        const tenantId = update.tenant_id || 'default';

        broadcastToTenant(tenantId, {
          type: 'graph.update',
          payload: update,
          timestamp: new Date().toISOString(),
        });
      } catch (err) {
        log.warn({ err }, 'Failed to parse graph update Kafka message');
      }
    },
  });
}

// --- Web Push routes (Phase 4B mobile responder PWA) ---
// Public key is needed by the browser to subscribe; the rest are
// authenticated routes the API gateway forwards on behalf of a user.
// Rate-limit push mutation routes: 20 req / min per IP to prevent abuse.
const pushRateLimit = rateLimit({
  windowMs: 60_000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Rate limit exceeded' },
});

app.get('/v1/push/public-key', pushManager.publicKeyHandler);
app.post('/v1/push/subscribe', pushRateLimit, pushManager.subscribeHandler);
app.post('/v1/push/unsubscribe', pushRateLimit, pushManager.unsubscribeHandler);
app.post('/v1/push/test', pushRateLimit, pushManager.testNotifyHandler);

// --- Internal broadcast endpoint (called by other services) ---
// POST /internal/agent-event
// Body: { tenant_id?: string, run_id: string, kind: string, agent: string, summary: string, data?: unknown }
// The realtime service re-broadcasts to all WebSocket clients on the `agents` channel.
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || '';

function requireInternal(req: express.Request, res: express.Response): boolean {
  if (!INTERNAL_TOKEN) return true;
  const auth = req.headers['x-internal-token'];
  if (auth !== INTERNAL_TOKEN) {
    res.status(401).json({ error: 'unauthorized' });
    return false;
  }
  return true;
}

// Internal push fan-out used by the agents/api services to send a
// notification to a tenant, user list, or topic. Same auth contract as
// `internal/agent-event`.
app.post('/internal/push', internalPushRateLimit, async (req, res) => {
  if (!requireInternal(req, res)) return;

  await pushManager.internalNotifyHandler(req, res);
});

app.post('/internal/agent-event', internalEventRateLimit, (req, res) => {
  if (!requireInternal(req, res)) return;

  const { tenant_id, run_id, kind, agent, summary, data } = req.body as {
    tenant_id?: string;
    run_id: string;
    kind: string;
    agent: string;
    summary: string;
    data?: Record<string, unknown> | null;
  };

  if (!run_id || !kind || !agent) {
    res.status(400).json({ error: 'run_id, kind, and agent are required' });
    return;
  }

  const tenantId = tenant_id || 'default';
  broadcastToTenant(tenantId, {
    type: 'agent.event',
    run_id,
    kind,
    agent,
    summary,
    data: data ?? null,
    timestamp: new Date().toISOString(),
  });

  // Also publish to Redis for SSE subscribers
  const redisPub = new Redis(REDIS_URL);
  const payload = JSON.stringify({
    type: 'agent.event',
    run_id,
    kind,
    agent,
    summary,
    timestamp: new Date().toISOString(),
  });
  redisPub.publish(`aisoc:events:${tenantId}`, payload)
    .then(() => redisPub.disconnect())
    .catch((err: unknown) => log.warn({ err }, 'Redis publish failed'));

  // Approval requests page on-call directly. Anything else stays
  // websocket-only so the device doesn't buzz on every reasoning step.
  if (
    pushManager.enabled &&
    (kind === 'APPROVAL_REQUEST' || kind === 'approval_request')
  ) {
    const approvalId =
      (data && (data.approval_id as string | undefined)) ?? run_id;
    const caseId = (data?.case_id as string | undefined) ?? undefined;
    const userIds =
      data &&
      (data.notify_user_ids as string[] | undefined) instanceof Array
        ? (data.notify_user_ids as string[])
        : undefined;
    pushManager
      .sendToTarget(
        userIds && userIds.length > 0
          ? { tenant_id: tenantId, user_ids: userIds }
          : { tenant_id: tenantId, topic: 'agent_approval' },
        {
          title: 'Agent needs your approval',
          body: summary || `${agent} is waiting for a decision.`,
          url: caseId
            ? `/responder/case/${caseId}?approval=${approvalId}`
            : `/responder/approvals?focus=${approvalId}`,
          tag: `approval-${approvalId}`,
          topic: 'agent_approval',
          severity: 'high',
          approval_id: String(approvalId),
          case_id: caseId,
        },
      )
      .catch((err: unknown) =>
        log.warn({ err, tenantId }, 'push fan-out for approval failed'),
      );
  }

  res.status(202).json({ broadcast: true, tenantId });
});

// --- Health endpoint ---
// Expose both `/health` (canonical) and `/healthz` (k8s + frontend default) so
// callers don't have to guess.
const reportHealth = (_req: express.Request, res: express.Response) => {
  res.json({
    status: 'healthy',
    service: 'aisoc-realtime',
    clients: wss.clients.size,
  });
};
app.get('/health', reportHealth);
app.get('/healthz', reportHealth);

// --- Start ---
// Bind to "::" so we are reachable over Fly.io's 6PN private network (IPv6).
// Node defaults to "::" when IPv6 is available, but be explicit to match the
// other services and avoid surprises if a future Node release changes the
// default or the container is launched with IPv6 disabled.
server.listen(PORT, '::', async () => {
  log.info({ port: PORT, host: '::' }, 'AiSOC Real-time service started');

  // Start the two Kafka consumers concurrently. Each is wrapped in its own
  // try/catch so a failure on the graph topic (e.g. it doesn't exist yet on
  // a brand-new cluster) does NOT block the higher-priority fused-alerts
  // fan-out. We deliberately fire them in parallel rather than awaiting
  // sequentially so the HTTP/WS listener is fully up before either Kafka
  // round-trip completes.
  void (async () => {
    try {
      await startKafkaConsumer();
    } catch (err) {
      log.warn({ err }, 'Kafka consumer failed to start (will retry)');
    }
  })();

  void (async () => {
    try {
      await startGraphUpdateConsumer();
    } catch (err) {
      // T1.4 fan-out is best-effort: if the graph topic isn't available the
      // alerts/cases/agents/insights channels still work, the graph panel
      // just won't light up in real time.
      log.warn({ err }, 'Graph update consumer failed to start (will retry)');
    }
  })();
});
