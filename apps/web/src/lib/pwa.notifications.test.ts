import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  isAlertPushSeverity,
  readAlertPushPreferences,
  saveAlertPushPreferences,
  subscribeToPush,
  syncPushNotificationSettings,
} from './pwa';

const gateway = vi.hoisted(() => ({ subscribe: vi.fn(), getPublicKey: vi.fn() }));
vi.mock('./api', () => ({ responderApi: gateway }));

const preferenceKey = 'aisoc:settings:preferences';
const subscription: PushSubscription = {
  endpoint: 'https://push.example/device',
  expirationTime: null,
  options: { applicationServerKey: null, userVisibleOnly: true },
  getKey: () => null,
  unsubscribe: async () => true,
  toJSON: () => ({ endpoint: 'https://push.example/device', keys: { p256dh: 'key', auth: 'auth' } }),
};

function installPushBrowser(existing: PushSubscription | null = subscription) {
  const registration = {
    pushManager: {
      getSubscription: vi.fn().mockResolvedValue(existing),
      subscribe: vi.fn().mockResolvedValue(subscription),
    },
  };
  vi.stubGlobal('navigator', {
    userAgent: 'notification-regression',
    serviceWorker: {
      ready: Promise.resolve(registration),
      getRegistration: vi.fn().mockResolvedValue(registration),
    },
  });
}

beforeEach(() => {
  window.localStorage.clear();
  gateway.subscribe.mockReset().mockResolvedValue({});
  gateway.getPublicKey.mockReset().mockResolvedValue({ public_key: 'AQID', enabled: true });
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('per-device alert push preferences', () => {
  it('defaults to High while keeping alert pages enabled for existing subscribers', () => {
    expect(readAlertPushPreferences()).toEqual({
      minimumAlertSeverity: 'high',
      desktopNotifications: true,
    });
  });

  it('retains appearance settings when the responder updates the alert risk', () => {
    window.localStorage.setItem('aisoc:settings:preferences', JSON.stringify({
      theme: 'light',
      minimumAlertSeverity: 'critical',
      desktopNotifications: true,
    }));
    expect(saveAlertPushPreferences({ minimumAlertSeverity: 'medium' })).toBe(true);
    const stored = JSON.parse(window.localStorage.getItem('aisoc:settings:preferences')!);
    expect(stored).toEqual({
      theme: 'light',
      minimumAlertSeverity: 'medium',
      desktopNotifications: true,
    });
    expect(readAlertPushPreferences().minimumAlertSeverity).toBe('medium');
  });

  it('rejects malformed or unknown risk values instead of broadening delivery', () => {
    expect(isAlertPushSeverity('unknown')).toBe(false);
    expect(isAlertPushSeverity('critical')).toBe(true);
    window.localStorage.setItem('aisoc:settings:preferences', '{"minimumAlertSeverity":"urgent","desktopNotifications":false}');
    expect(readAlertPushPreferences()).toEqual({
      minimumAlertSeverity: 'high',
      desktopNotifications: false,
    });
    window.localStorage.setItem('aisoc:settings:preferences', '{bad json');
    expect(readAlertPushPreferences().minimumAlertSeverity).toBe('high');
  });

  it('repairs malformed writable preferences instead of silently losing the update', () => {
    window.localStorage.setItem(preferenceKey, '{bad json');
    expect(saveAlertPushPreferences({ minimumAlertSeverity: 'low', desktopNotifications: false })).toBe(true);
    expect(readAlertPushPreferences()).toEqual({ minimumAlertSeverity: 'low', desktopNotifications: false });
  });

  it.each(['getItem', 'setItem'] as const)('reports a failed local save when %s throws', (method) => {
    vi.spyOn(window.localStorage, method).mockImplementation(() => { throw new Error('Storage blocked'); });
    expect(saveAlertPushPreferences({ minimumAlertSeverity: 'medium' })).toBe(false);
  });
});

describe('alert preferences sent to the push gateway', () => {
  it.each([true, false])('sends explicit preferences without readable storage (existing subscription: %s)', async (existing) => {
    installPushBrowser(existing ? subscription : null);
    vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => { throw new Error('Storage blocked'); });
    const alertPreferences = { minimumAlertSeverity: 'medium' as const, desktopNotifications: false };

    expect(await subscribeToPush({ topics: ['agent_approval'], alertPreferences })).toBe(subscription);
    expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      topics: ['agent_approval'],
      minimum_alert_severity: 'medium',
      alert_notifications_enabled: false,
    }));
  });

  it('syncs the selected values even when a write failed and stale preferences remain', async () => {
    installPushBrowser();
    window.localStorage.setItem(preferenceKey, JSON.stringify({ minimumAlertSeverity: 'high', desktopNotifications: true }));
    vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => { throw new Error('Storage full'); });
    const preferences = { minimumAlertSeverity: 'critical' as const, desktopNotifications: false };
    expect(saveAlertPushPreferences(preferences)).toBe(false);

    expect(await syncPushNotificationSettings(preferences)).toBe(true);
    expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      minimum_alert_severity: 'critical', alert_notifications_enabled: false,
    }));
  });

  it('keeps saved preferences as the default for automatic subscription renewal', async () => {
    installPushBrowser();
    saveAlertPushPreferences({ minimumAlertSeverity: 'low', desktopNotifications: false });
    await subscribeToPush();
    expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      minimum_alert_severity: 'low', alert_notifications_enabled: false,
    }));
  });

  it.each(['missing', 'malformed', 'unreadable'] as const)(
    'omits unavailable topics during renewal instead of replacing them (%s)',
    async (storageState) => {
      installPushBrowser();
      if (storageState === 'malformed') {
        window.localStorage.setItem('aisoc.responder.push.topics', '{bad json');
      } else if (storageState === 'unreadable') {
        vi.spyOn(window.localStorage, 'getItem').mockImplementation(() => { throw new Error('Storage blocked'); });
      }

      await syncPushNotificationSettings({ minimumAlertSeverity: 'medium', desktopNotifications: false });

      expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
        minimum_alert_severity: 'medium', alert_notifications_enabled: false,
      }));
      expect(gateway.subscribe.mock.calls[0][0].topics).toBeUndefined();
    },
  );

  it('does not report a sync when the device has no subscription', async () => {
    installPushBrowser(null);
    expect(await syncPushNotificationSettings({ minimumAlertSeverity: 'medium', desktopNotifications: true })).toBe(false);
    expect(gateway.subscribe).not.toHaveBeenCalled();
  });

  it('propagates a gateway failure instead of treating the local save as a successful sync', async () => {
    installPushBrowser();
    gateway.subscribe.mockRejectedValue(new Error('Gateway unavailable'));
    await expect(syncPushNotificationSettings({ minimumAlertSeverity: 'medium', desktopNotifications: false }))
      .rejects.toThrow('Gateway unavailable');
  });
});
