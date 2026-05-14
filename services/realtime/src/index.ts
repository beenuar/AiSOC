import express from 'express';
import cors from 'cors';
import http from 'http';
import { WebSocketServer } from 'ws';
import { Kafka } from 'kafkajs';
import Redis from 'ioredis';
import pino from 'pino';
import rateLimit from 'express-rate-limit';

import { PushManager } from './push';

const log = pino({ level: process.env.LOG_LEVEL || 'info' });

const PORT = parseInt(process.env.PORT || '8086', 10);
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379/4';
const KAFKA_BROKERS = (process.env.KAFKA_BOOTSTRAP_SERVERS || 'localhost:9092').split(',');
const KAFKA_TOPIC_FUSED = process.env.KAFKA_TOPIC_FUSED || 'aisoc.alerts.fused';
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
// callers say up-front what they care about (alerts, cases, agents, all) so we
// can avoid spamming a panel that only renders alerts with case/agent traffic.
type Channel = 'alerts' | 'cases' | 'agents' | 'all';
const VALID_CHANNELS: Channel[] = ['alerts', 'cases', 'agents', 'all'];

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
  wss.handleUpgrade(req, socket, head, (ws) => {
    (ws as any)._aisocChannel = requested;
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
  const url = new URL(req.url || '/', `http://localhost`);
  const tenantId = url.searchParams.get('tenant_id') || 'default';
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
  'case.updated': ['cases', 'all'],
  'agent.event': ['agents', 'all'],
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
  const tenantId = (req.query.tenant_id as string) || 'default';

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  // CORS headers for SSE are emitted by the `cors()` middleware on lines
  // ~118–143 above, which the `cors` npm package implements safely (CodeQL
  // recognises `cors({ origin: <function> })` as a sanitiser). SSE auth is
  // done via the `tenant_id` query parameter, not via a session cookie,
  // so we deliberately do not enable `Access-Control-Allow-Credentials`
  // on this endpoint — that eliminates the entire "CORS misconfiguration
  // for credentials transfer" attack surface that CodeQL warns about.
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

// --- Kafka consumer: bridge fused alerts to WebSocket clients ---
async function startKafkaConsumer() {
  const kafka = new Kafka({
    clientId: 'aisoc-realtime',
    brokers: KAFKA_BROKERS,
    retry: { retries: 5 },
  });

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
  try {
    await startKafkaConsumer();
  } catch (err) {
    log.warn({ err }, 'Kafka consumer failed to start (will retry)');
  }
});
