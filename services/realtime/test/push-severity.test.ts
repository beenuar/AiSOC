/**
 * Device-level alert paging, using the production sendToTarget gate.
 * Approvals, hand-offs and test messages must never be muted by risk settings.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { PushManager, shouldDeliverPush, isAlertSeverity, type SubscriptionRecord } from '../src/push';

function record(
  minimum_alert_severity?: SubscriptionRecord['minimum_alert_severity'],
  alert_notifications_enabled?: boolean,
): SubscriptionRecord {
  return {
    id: 'sub-1', tenant_id: 'tenant-1', user_id: 'analyst-1',
    endpoint: 'https://push.example/1', keys: { p256dh: 'key', auth: 'auth' },
    user_agent: null, topics: ['p0_alert', 'agent_approval', 'oncall_handoff'],
    created_at: '2026-01-01T00:00:00Z', last_seen_at: '2026-01-01T00:00:00Z',
    ...(minimum_alert_severity === undefined ? {} : { minimum_alert_severity }),
    ...(alert_notifications_enabled === undefined ? {} : { alert_notifications_enabled }),
  };
}

test('inclusive threshold: Critical, High, Medium and Low', () => {
  const severities = ['critical', 'high', 'medium', 'low'] as const;
  for (const minimum of severities) {
    const threshold = severities.indexOf(minimum);
    for (const severity of severities) {
      assert.equal(
        shouldDeliverPush(record(minimum, true), { topic: 'p0_alert', severity }),
        severities.indexOf(severity) <= threshold,
        `${minimum} minimum versus ${severity}`,
      );
    }
  }
});

test('legacy devices preserve the previous High+Critical default', () => {
  assert.equal(shouldDeliverPush(record(), { topic: 'p0_alert', severity: 'critical' }), true);
  assert.equal(shouldDeliverPush(record(), { topic: 'p0_alert', severity: 'high' }), true);
  assert.equal(shouldDeliverPush(record(), { topic: 'p0_alert', severity: 'medium' }), false);
  assert.equal(shouldDeliverPush(record(), { topic: 'p0_alert', severity: 'low' }), false);
});

test('unknown or unrecognised alert severities fail closed for paging', () => {
  assert.equal(isAlertSeverity('severe'), false);
  assert.equal(shouldDeliverPush(record('low'), { topic: 'p0_alert', severity: 'info' }), false);
  assert.equal(shouldDeliverPush(record('low'), { topic: 'p0_alert' }), false);
  assert.equal(shouldDeliverPush(
    { minimum_alert_severity: 'untrusted' as never },
    { topic: 'p0_alert', severity: 'medium' },
  ), false);
});

test('disable alert pages without muting approvals, handoffs or tests', () => {
  for (const topic of ['agent_approval', 'oncall_handoff', 'test']) {
    assert.equal(
      shouldDeliverPush(record('critical', false), { topic, severity: 'low' }),
      true,
    );
  }
  assert.equal(shouldDeliverPush(record('low', false), { topic: 'p0_alert', severity: 'critical' }), false);
});

test('sendToTarget actually excludes below-threshold records before delivery', async () => {
  const mgr = new PushManager({
    redis: {} as never,
    logger: { child: () => ({ info: () => undefined }) } as never,
    vapidPublicKey: '', vapidPrivateKey: '', vapidSubject: '',
  });
  Object.defineProperty(mgr, 'enabled', { value: true });
  const subs = [record('critical'), { ...record('low'), id: 'sub-2' }, { ...record('medium'), id: 'sub-3' }];
  const sent: string[] = [];
  mgr.resolveSubscriptions = async () => subs;
  mgr.sendToSubscription = async (sub) => {
    sent.push(sub.id);
    return { delivered: true, removed: false };
  };
  const result = await mgr.sendToTarget(
    { tenant_id: 'tenant-1', topic: 'p0_alert' },
    { title: 'High detection', body: 'Triage', severity: 'high', topic: 'p0_alert' },
  );
  assert.deepEqual(sent, ['sub-2', 'sub-3']);
  assert.deepEqual(result, { attempted: 2, delivered: 2, removed: 0, errors: 0 });

  sent.length = 0;
  await mgr.sendToTarget(
    { tenant_id: 'tenant-1', topic: 'agent_approval' },
    { title: 'Approval', body: 'Decision', severity: 'low', topic: 'agent_approval' },
  );
  assert.deepEqual(sent, ['sub-1', 'sub-2', 'sub-3']);
});

test('subscription metadata defaults, validates and persists on renewal', async () => {
  const stored = new Map<string, string>();
  const redis = {
    get: async (k: string) => stored.get(k) ?? null,
    multi: () => {
      const writes: Array<() => void> = [];
      const pipeline = {
        set(k: string, v: string) { writes.push(() => stored.set(k, v)); return pipeline; },
        sadd() { return pipeline; },
        expire() { return pipeline; },
        srem() { return pipeline; },
        async exec() { writes.forEach((write) => write()); return []; },
      };
      return pipeline;
    },
  };
  const mgr = new PushManager({
    redis: redis as never,
    logger: { child: () => ({ info: () => undefined }) } as never,
    vapidPublicKey: '', vapidPrivateKey: '', vapidSubject: '',
  });
  const body = {
    subscription: { endpoint: 'https://push.example/1', keys: { p256dh: 'key', auth: 'auth' } },
    topics: ['p0_alert'],
  };
  const first = await mgr.upsertSubscription('tenant-1', 'analyst-1', body);
  assert.equal(first.minimum_alert_severity, 'high');
  assert.equal(first.alert_notifications_enabled, true);
  const changed = await mgr.upsertSubscription('tenant-1', 'analyst-1', {
    ...body, minimum_alert_severity: 'medium', alert_notifications_enabled: false,
  });
  assert.equal(changed.minimum_alert_severity, 'medium');
  assert.equal(changed.alert_notifications_enabled, false);
  const renewal = await mgr.upsertSubscription('tenant-1', 'analyst-1', body);
  assert.equal(renewal.minimum_alert_severity, 'medium');
  assert.equal(renewal.alert_notifications_enabled, false);
  await assert.rejects(
    mgr.upsertSubscription('tenant-1', 'analyst-1', { ...body, minimum_alert_severity: 'urgent' as never }),
    /minimum_alert_severity must be/,
  );
  await assert.rejects(
    mgr.upsertSubscription('tenant-1', 'analyst-1', { ...body, alert_notifications_enabled: 'yes' as never }),
    /alert_notifications_enabled must be/,
  );
});
