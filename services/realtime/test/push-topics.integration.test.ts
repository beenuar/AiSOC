/**
 * Exercise the subscription HTTP handler and actual Redis records/indexes.
 * Set REALTIME_TEST_REDIS_URL to a test Redis instance; CI provides one.
 * The handler receives the headers stamped by the API gateway. No push is sent.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import express from 'express';
import Redis from 'ioredis';
import pino from 'pino';
import * as webpush from 'web-push';
import { PushManager } from '../src/push';

const redisUrl = process.env.REALTIME_TEST_REDIS_URL;
const defaultTopics = ['p0_alert', 'agent_approval', 'oncall_handoff'];

test('HTTP subscription renewal preserves omitted topics and updates Redis indexes', {
  skip: !redisUrl && 'Set REALTIME_TEST_REDIS_URL to run the real Redis regression',
  timeout: 15_000,
}, async (t) => {
  const namespace = `push-topics-test:${randomUUID()}:`;
  const redis = new Redis(redisUrl!, {
    keyPrefix: namespace,
    lazyConnect: true,
    connectTimeout: 2_000,
    maxRetriesPerRequest: 1,
    retryStrategy: () => null,
  });
  const tenantId = 'test-tenant';
  const userId = 'test-responder';
  const keys = [
    `aisoc:push:tenant:${tenantId}`,
    `aisoc:push:user:${tenantId}:${userId}`,
    ...defaultTopics.map((topic) => `aisoc:push:topic:${tenantId}:${topic}`),
  ];
  t.after(async () => {
    try {
      if (redis.status === 'ready') await redis.del(...keys);
    } finally {
      redis.disconnect();
    }
  });
  await redis.connect();

  const vapid = webpush.generateVAPIDKeys();
  const manager = new PushManager({
    redis,
    logger: pino({ level: 'silent' }),
    vapidPublicKey: vapid.publicKey,
    vapidPrivateKey: vapid.privateKey,
    vapidSubject: 'mailto:push-tests@example.test',
  });
  const app = express();
  app.use(express.json());
  app.post('/v1/push/subscribe', manager.subscribeHandler);
  const server = app.listen(0, '127.0.0.1');
  t.after(() => new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  }));
  await once(server, 'listening');
  const address = server.address() as AddressInfo;
  const subscription = {
    endpoint: `https://push.example/${randomUUID()}`,
    keys: { p256dh: 'test-key', auth: 'test-auth' },
  };

  async function subscribe(topics?: string[]) {
    const response = await fetch(`http://127.0.0.1:${address.port}/v1/push/subscribe`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-tenant-id': tenantId,
        'x-user-id': userId,
      },
      body: JSON.stringify({ subscription, ...(topics === undefined ? {} : { topics }) }),
    });
    assert.equal(response.status, 201);
    return await response.json() as { id: string; topics: string[] };
  }

  const first = await subscribe();
  keys.push(`aisoc:push:sub:${first.id}`);
  assert.deepEqual(first.topics, defaultTopics, 'new devices receive default topics');

  async function assertStoredTopics(expected: string[]) {
    const stored = await manager.getSubscription(first.id);
    assert.deepEqual(stored?.topics, expected, 'the Redis record matches the response');
    for (const topic of defaultTopics) {
      assert.deepEqual(
        await manager.listIdsForTopic(tenantId, topic),
        expected.includes(topic) ? [first.id] : [],
        `${topic} index reflects the selected topics`,
      );
    }
    assert.deepEqual(await manager.listIdsForUser(tenantId, userId), [first.id]);
    assert.deepEqual(await manager.listIdsForTenant(tenantId), [first.id]);
  }

  assert.deepEqual((await subscribe(['p0_alert'])).topics, ['p0_alert']);
  await assertStoredTopics(['p0_alert']);
  assert.deepEqual((await subscribe()).topics, ['p0_alert'], 'omission preserves a custom selection');
  await assertStoredTopics(['p0_alert']);

  assert.deepEqual((await subscribe([])).topics, [], 'an explicit empty array disables all topics');
  await assertStoredTopics([]);
  assert.deepEqual((await subscribe()).topics, [], 'omission also preserves an empty selection');
  await assertStoredTopics([]);

  assert.deepEqual((await subscribe(['agent_approval', 'oncall_handoff'])).topics,
    ['agent_approval', 'oncall_handoff']);
  await assertStoredTopics(['agent_approval', 'oncall_handoff']);
});
