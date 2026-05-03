import express from 'express';
import cors from 'cors';
import http from 'http';
import { WebSocketServer } from 'ws';
import { Kafka } from 'kafkajs';
import Redis from 'ioredis';
import pino from 'pino';

const log = pino({ level: process.env.LOG_LEVEL || 'info' });

const PORT = parseInt(process.env.PORT || '8086', 10);
const REDIS_URL = process.env.REDIS_URL || 'redis://localhost:6379/4';
const KAFKA_BROKERS = (process.env.KAFKA_BOOTSTRAP_SERVERS || 'localhost:9092').split(',');
const KAFKA_TOPIC_FUSED = process.env.KAFKA_TOPIC_FUSED || 'aisoc.alerts.fused';

// --- Express setup ---
const app = express();
app.use(cors());
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

wss.on('connection', (ws, req) => {
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

// --- SSE endpoint ---
app.get('/sse', (req, res) => {
  const tenantId = (req.query.tenant_id as string) || 'default';

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
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
      } catch (err) {
        log.warn({ err }, 'Failed to parse Kafka message');
      }
    },
  });
}

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
server.listen(PORT, async () => {
  log.info({ port: PORT }, 'AiSOC Real-time service started');
  try {
    await startKafkaConsumer();
  } catch (err) {
    log.warn({ err }, 'Kafka consumer failed to start (will retry)');
  }
});
