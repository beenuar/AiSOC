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
const wss = new WebSocketServer({ server, path: '/ws' });

// Client registry: tenantId -> Set of WebSocket clients
const clients = new Map<string, Set<any>>();

wss.on('connection', (ws, req) => {
  const url = new URL(req.url || '/', `http://localhost`);
  const tenantId = url.searchParams.get('tenant_id') || 'default';

  if (!clients.has(tenantId)) {
    clients.set(tenantId, new Set());
  }
  clients.get(tenantId)!.add(ws);
  log.info({ tenantId, totalClients: clients.get(tenantId)!.size }, 'WebSocket client connected');

  ws.on('close', () => {
    clients.get(tenantId)?.delete(ws);
    log.info({ tenantId }, 'WebSocket client disconnected');
  });

  ws.send(JSON.stringify({ type: 'connected', tenantId }));
});

function broadcastToTenant(tenantId: string, message: object) {
  const tenantClients = clients.get(tenantId);
  if (!tenantClients) return;

  const payload = JSON.stringify(message);
  for (const client of tenantClients) {
    if (client.readyState === 1 /* OPEN */) {
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
app.get('/health', (_req, res) => {
  res.json({ status: 'healthy', service: 'aisoc-realtime', clients: wss.clients.size });
});

// --- Start ---
server.listen(PORT, async () => {
  log.info({ port: PORT }, 'AiSOC Real-time service started');
  try {
    await startKafkaConsumer();
  } catch (err) {
    log.warn({ err }, 'Kafka consumer failed to start (will retry)');
  }
});
