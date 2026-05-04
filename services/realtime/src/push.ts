/**
 * Web Push registration + delivery for the AiSOC mobile responder PWA.
 *
 * Phase 4B. Subscriptions are stored in Redis keyed by tenant + user, and
 * delivered via the standard `web-push` VAPID flow. The push module is
 * intentionally framework-light so it can be mounted onto either the
 * realtime gateway (for low-latency Kafka fan-out) or a standalone worker
 * later if we shard.
 *
 * Storage layout (Redis):
 *
 *   aisoc:push:sub:<id>                 → JSON SubscriptionRecord
 *   aisoc:push:tenant:<tenant_id>       → SET of subscription ids
 *   aisoc:push:user:<tenant>:<user_id>  → SET of subscription ids
 *   aisoc:push:topic:<tenant>:<topic>   → SET of subscription ids
 *
 * That layout lets us:
 *   - fan out to a whole tenant on a P0 alert,
 *   - target a specific on-call user for an approval request, or
 *   - target everyone subscribed to a topic (`p0_alert`, `oncall_handoff`, …).
 */

import type Redis from 'ioredis';
import type { Logger } from 'pino';
import type { Request, Response } from 'express';
import webpush from 'web-push';
import crypto from 'crypto';

export interface SubscriptionPayload {
  endpoint: string;
  keys: {
    p256dh: string;
    auth: string;
  };
  expirationTime?: number | null;
}

export interface SubscribeRequestBody {
  subscription: SubscriptionPayload;
  user_agent?: string;
  user_id?: string | null;
  topics?: string[];
}

export interface SubscriptionRecord {
  id: string;
  tenant_id: string;
  user_id: string | null;
  endpoint: string;
  keys: { p256dh: string; auth: string };
  user_agent: string | null;
  topics: string[];
  created_at: string;
  last_seen_at: string;
}

export interface PushNotification {
  title: string;
  body: string;
  /** Where the SW should navigate when the user taps the notification. */
  url?: string;
  /** Notification tag to coalesce duplicates (e.g. alert ID). */
  tag?: string;
  /** Logical channel — `p0_alert`, `agent_approval`, `oncall_handoff`, … */
  topic?: string;
  /** Severity helps the SW choose the right icon/vibration pattern. */
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  /** Optional ID surfaced as `data.alert_id` / `data.case_id`. */
  alert_id?: string;
  case_id?: string;
  approval_id?: string;
  /** Custom data passthrough — anything JSON-serializable. */
  data?: Record<string, unknown>;
}

export interface PushDeliveryStats {
  attempted: number;
  delivered: number;
  removed: number;
  errors: number;
}

const SUB_TTL_DAYS = 90;
const SUB_TTL_SECONDS = SUB_TTL_DAYS * 24 * 60 * 60;

const DEFAULT_TOPICS = ['p0_alert', 'agent_approval', 'oncall_handoff'];

function key(...parts: string[]): string {
  return ['aisoc', 'push', ...parts].join(':');
}

function tenantOf(req: Request): string {
  const hdr = req.headers['x-tenant-id'];
  if (typeof hdr === 'string' && hdr.length > 0) return hdr;
  if (Array.isArray(hdr) && hdr[0]) return hdr[0];
  const q = req.query.tenant_id;
  if (typeof q === 'string' && q.length > 0) return q;
  return 'default';
}

function userOf(req: Request, body: SubscribeRequestBody): string | null {
  // Prefer the body field for now; the API gateway is expected to validate
  // it against the bearer token before traffic reaches the realtime
  // service in production.
  if (body.user_id) return body.user_id;
  const hdr = req.headers['x-user-id'];
  if (typeof hdr === 'string' && hdr.length > 0) return hdr;
  if (Array.isArray(hdr) && hdr[0]) return hdr[0];
  return null;
}

function hashEndpoint(endpoint: string): string {
  return crypto.createHash('sha256').update(endpoint).digest('hex').slice(0, 24);
}

export interface PushManagerOptions {
  redis: Redis;
  logger: Logger;
  /** VAPID public key (URL-safe base64). Empty string disables push. */
  vapidPublicKey: string;
  vapidPrivateKey: string;
  vapidSubject: string;
  /** Optional override for testing. */
  now?: () => Date;
}

export class PushManager {
  private readonly redis: Redis;
  private readonly log: Logger;
  private readonly publicKey: string;
  private readonly privateKey: string;
  private readonly subject: string;
  private readonly now: () => Date;
  readonly enabled: boolean;

  constructor(opts: PushManagerOptions) {
    this.redis = opts.redis;
    this.log = opts.logger.child({ component: 'push' });
    this.publicKey = opts.vapidPublicKey;
    this.privateKey = opts.vapidPrivateKey;
    this.subject = opts.vapidSubject;
    this.now = opts.now ?? (() => new Date());
    this.enabled = Boolean(this.publicKey && this.privateKey && this.subject);

    if (this.enabled) {
      try {
        webpush.setVapidDetails(this.subject, this.publicKey, this.privateKey);
      } catch (err) {
        this.log.error({ err }, 'invalid VAPID configuration; push disabled');
        this.enabled = false as unknown as boolean;
      }
    } else {
      this.log.info(
        'push disabled: set VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY, VAPID_SUBJECT to enable',
      );
    }
  }

  // ─── Subscription CRUD ────────────────────────────────────────────────

  async upsertSubscription(
    tenantId: string,
    userId: string | null,
    body: SubscribeRequestBody,
  ): Promise<SubscriptionRecord> {
    const sub = body.subscription;
    if (!sub?.endpoint || !sub.keys?.p256dh || !sub.keys?.auth) {
      throw new Error('subscription endpoint and keys are required');
    }

    const id = hashEndpoint(sub.endpoint);
    const subKey = key('sub', id);
    const tenantKey = key('tenant', tenantId);
    const userKey = userId ? key('user', tenantId, userId) : null;

    const existingRaw = await this.redis.get(subKey);
    const existing: SubscriptionRecord | null = existingRaw
      ? (JSON.parse(existingRaw) as SubscriptionRecord)
      : null;

    const topics =
      body.topics && body.topics.length > 0 ? body.topics : DEFAULT_TOPICS;

    const record: SubscriptionRecord = {
      id,
      tenant_id: tenantId,
      user_id: userId,
      endpoint: sub.endpoint,
      keys: { p256dh: sub.keys.p256dh, auth: sub.keys.auth },
      user_agent: body.user_agent ?? null,
      topics,
      created_at: existing?.created_at ?? this.now().toISOString(),
      last_seen_at: this.now().toISOString(),
    };

    const pipeline = this.redis.multi();
    pipeline.set(subKey, JSON.stringify(record), 'EX', SUB_TTL_SECONDS);
    pipeline.sadd(tenantKey, id);
    pipeline.expire(tenantKey, SUB_TTL_SECONDS);
    if (userKey) {
      pipeline.sadd(userKey, id);
      pipeline.expire(userKey, SUB_TTL_SECONDS);
    }
    for (const topic of topics) {
      const topicKey = key('topic', tenantId, topic);
      pipeline.sadd(topicKey, id);
      pipeline.expire(topicKey, SUB_TTL_SECONDS);
    }
    // If topics changed, prune the subscription from old topic sets.
    if (existing) {
      for (const oldTopic of existing.topics) {
        if (!topics.includes(oldTopic)) {
          pipeline.srem(key('topic', tenantId, oldTopic), id);
        }
      }
    }
    await pipeline.exec();

    this.log.info(
      { tenantId, userId, id, topics, replaced: existing !== null },
      'push subscription upserted',
    );
    return record;
  }

  async removeSubscription(tenantId: string, endpoint: string): Promise<boolean> {
    const id = hashEndpoint(endpoint);
    return this.removeSubscriptionById(tenantId, id);
  }

  async removeSubscriptionById(tenantId: string, id: string): Promise<boolean> {
    const subKey = key('sub', id);
    const raw = await this.redis.get(subKey);
    if (!raw) return false;
    const record = JSON.parse(raw) as SubscriptionRecord;

    const pipeline = this.redis.multi();
    pipeline.del(subKey);
    pipeline.srem(key('tenant', record.tenant_id), id);
    if (record.user_id) {
      pipeline.srem(key('user', record.tenant_id, record.user_id), id);
    }
    for (const topic of record.topics) {
      pipeline.srem(key('topic', record.tenant_id, topic), id);
    }
    await pipeline.exec();
    this.log.info({ tenantId, id }, 'push subscription removed');
    return true;
  }

  async getSubscription(id: string): Promise<SubscriptionRecord | null> {
    const raw = await this.redis.get(key('sub', id));
    if (!raw) return null;
    return JSON.parse(raw) as SubscriptionRecord;
  }

  // ─── Resolution ───────────────────────────────────────────────────────

  async listIdsForTenant(tenantId: string): Promise<string[]> {
    return this.redis.smembers(key('tenant', tenantId));
  }

  async listIdsForUser(tenantId: string, userId: string): Promise<string[]> {
    return this.redis.smembers(key('user', tenantId, userId));
  }

  async listIdsForTopic(tenantId: string, topic: string): Promise<string[]> {
    return this.redis.smembers(key('topic', tenantId, topic));
  }

  async resolveSubscriptions(target: {
    tenant_id: string;
    user_ids?: string[];
    topic?: string;
  }): Promise<SubscriptionRecord[]> {
    const ids = new Set<string>();

    if (target.user_ids && target.user_ids.length > 0) {
      for (const uid of target.user_ids) {
        for (const id of await this.listIdsForUser(target.tenant_id, uid)) {
          ids.add(id);
        }
      }
    } else if (target.topic) {
      for (const id of await this.listIdsForTopic(target.tenant_id, target.topic)) {
        ids.add(id);
      }
    } else {
      for (const id of await this.listIdsForTenant(target.tenant_id)) {
        ids.add(id);
      }
    }

    const records: SubscriptionRecord[] = [];
    for (const id of ids) {
      const r = await this.getSubscription(id);
      if (r) records.push(r);
    }
    return records;
  }

  // ─── Delivery ─────────────────────────────────────────────────────────

  async sendToSubscription(
    record: SubscriptionRecord,
    notification: PushNotification,
  ): Promise<{ delivered: boolean; removed: boolean }> {
    if (!this.enabled) return { delivered: false, removed: false };

    const payload = JSON.stringify(this.buildPayload(notification));
    try {
      await webpush.sendNotification(
        {
          endpoint: record.endpoint,
          keys: record.keys,
        },
        payload,
        { TTL: 60, urgency: this.urgencyFor(notification) },
      );
      // Refresh last_seen so the entry stays fresh.
      record.last_seen_at = this.now().toISOString();
      await this.redis.set(
        key('sub', record.id),
        JSON.stringify(record),
        'EX',
        SUB_TTL_SECONDS,
      );
      return { delivered: true, removed: false };
    } catch (err) {
      const status = (err as { statusCode?: number }).statusCode ?? 0;
      // 404/410 → endpoint is dead, drop it. Anything else is transient
      // (rate-limit, transient 5xx, etc).
      if (status === 404 || status === 410) {
        await this.removeSubscriptionById(record.tenant_id, record.id);
        this.log.info({ id: record.id, status }, 'pruned dead push endpoint');
        return { delivered: false, removed: true };
      }
      this.log.warn({ err, id: record.id, status }, 'push delivery failed');
      return { delivered: false, removed: false };
    }
  }

  async sendToTarget(
    target: { tenant_id: string; user_ids?: string[]; topic?: string },
    notification: PushNotification,
  ): Promise<PushDeliveryStats> {
    const stats: PushDeliveryStats = {
      attempted: 0,
      delivered: 0,
      removed: 0,
      errors: 0,
    };
    if (!this.enabled) return stats;

    const records = await this.resolveSubscriptions(target);
    stats.attempted = records.length;

    // Fan out concurrently but cap to avoid hammering FCM/APNs in big tenants.
    const CONCURRENCY = 16;
    for (let i = 0; i < records.length; i += CONCURRENCY) {
      const batch = records.slice(i, i + CONCURRENCY);
      const results = await Promise.allSettled(
        batch.map((r) => this.sendToSubscription(r, notification)),
      );
      for (const res of results) {
        if (res.status === 'fulfilled') {
          if (res.value.delivered) stats.delivered += 1;
          if (res.value.removed) stats.removed += 1;
          if (!res.value.delivered && !res.value.removed) stats.errors += 1;
        } else {
          stats.errors += 1;
        }
      }
    }
    return stats;
  }

  private buildPayload(n: PushNotification): Record<string, unknown> {
    return {
      title: n.title,
      body: n.body,
      // Defaults handled SW-side, but pre-populate so older browsers behave.
      icon: '/icons/icon-192.svg',
      badge: '/icons/icon-192.svg',
      tag: n.tag,
      topic: n.topic ?? 'general',
      severity: n.severity ?? 'info',
      url: n.url ?? '/',
      data: {
        url: n.url ?? '/',
        topic: n.topic ?? 'general',
        severity: n.severity ?? 'info',
        alert_id: n.alert_id,
        case_id: n.case_id,
        approval_id: n.approval_id,
        ...(n.data ?? {}),
      },
    };
  }

  private urgencyFor(
    n: PushNotification,
  ): 'very-low' | 'low' | 'normal' | 'high' {
    switch (n.severity) {
      case 'critical':
      case 'high':
        return 'high';
      case 'medium':
        return 'normal';
      case 'low':
        return 'low';
      default:
        return n.topic === 'p0_alert' ? 'high' : 'normal';
    }
  }

  // ─── HTTP handlers ────────────────────────────────────────────────────

  publicKeyHandler = (_req: Request, res: Response): void => {
    res.json({
      public_key: this.publicKey,
      enabled: this.enabled,
    });
  };

  subscribeHandler = async (req: Request, res: Response): Promise<void> => {
    if (!this.enabled) {
      res.status(503).json({ error: 'push not configured' });
      return;
    }
    try {
      const tenantId = tenantOf(req);
      const body = req.body as SubscribeRequestBody;
      const userId = userOf(req, body);
      const record = await this.upsertSubscription(tenantId, userId, body);
      res.status(201).json({
        id: record.id,
        vapid_public_key: this.publicKey,
        topics: record.topics,
      });
    } catch (err) {
      this.log.warn({ err }, 'subscribe failed');
      res.status(400).json({ error: (err as Error).message });
    }
  };

  unsubscribeHandler = async (req: Request, res: Response): Promise<void> => {
    const tenantId = tenantOf(req);
    const { endpoint } = (req.body ?? {}) as { endpoint?: string };
    if (!endpoint) {
      res.status(400).json({ error: 'endpoint is required' });
      return;
    }
    const removed = await this.removeSubscription(tenantId, endpoint);
    res.json({ removed });
  };

  testNotifyHandler = async (req: Request, res: Response): Promise<void> => {
    if (!this.enabled) {
      res.status(503).json({ error: 'push not configured' });
      return;
    }
    const tenantId = tenantOf(req);
    const userIdHdr = req.headers['x-user-id'];
    const userId =
      typeof userIdHdr === 'string'
        ? userIdHdr
        : Array.isArray(userIdHdr) && userIdHdr[0]
          ? userIdHdr[0]
          : null;

    const stats = await this.sendToTarget(
      userId
        ? { tenant_id: tenantId, user_ids: [userId] }
        : { tenant_id: tenantId },
      {
        title: 'AiSOC test page',
        body: 'If you can read this, push is working on this device.',
        url: '/responder',
        topic: 'test',
        severity: 'info',
        tag: 'aisoc-test',
      },
    );
    res.json({ sent: stats.delivered, ...stats });
  };

  /**
   * Internal endpoint used by the Kafka consumer + the agents service to
   * fan out a push notification. Authenticated by the same INTERNAL_TOKEN
   * the rest of the realtime gateway uses.
   */
  internalNotifyHandler = async (req: Request, res: Response): Promise<void> => {
    if (!this.enabled) {
      res.status(503).json({ error: 'push not configured' });
      return;
    }
    const body = (req.body ?? {}) as {
      tenant_id?: string;
      user_ids?: string[];
      topic?: string;
      notification: PushNotification;
    };
    if (!body?.notification?.title || !body.notification.body) {
      res.status(400).json({ error: 'notification.title and body are required' });
      return;
    }
    const stats = await this.sendToTarget(
      {
        tenant_id: body.tenant_id ?? tenantOf(req),
        user_ids: body.user_ids,
        topic: body.topic,
      },
      body.notification,
    );
    res.json(stats);
  };
}
