import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NavigationTestProvider } from '@/test/NavigationTestProvider';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import { SettingsView } from './SettingsView';

const gateway = vi.hoisted(() => ({ subscribe: vi.fn() }));
const notices = vi.hoisted(() => ({ info: vi.fn(), success: vi.fn(), error: vi.fn() }));
vi.mock('react-hot-toast', () => ({
  default: Object.assign(notices.info, { success: notices.success, error: notices.error }),
}));
vi.mock('swr', () => ({
  default: () => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }),
}));
vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return { ...actual, responderApi: { ...actual.responderApi, subscribe: gateway.subscribe } };
});

const subscription = {
  toJSON: () => ({ endpoint: 'https://push.example/console', keys: { p256dh: 'key', auth: 'auth' } }),
};
const getSubscription = vi.fn();

function renderNotifications() {
  return render(<ThemeProvider><SettingsView /></ThemeProvider>, { wrapper: NavigationTestProvider });
}

function blockLocalSave() {
  vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => { throw new Error('Storage full'); });
}

beforeEach(() => {
  window.localStorage.clear();
  window.history.replaceState(null, '', '/settings?tab=notifications');
  gateway.subscribe.mockReset().mockResolvedValue({});
  Object.values(notices).forEach((notice) => notice.mockReset());
  getSubscription.mockReset().mockResolvedValue(subscription);
  const registration = { pushManager: { getSubscription } };
  vi.stubGlobal('navigator', {
    userAgent: 'console-regression',
    serviceWorker: {
      getRegistration: vi.fn().mockResolvedValue(registration),
      register: vi.fn().mockResolvedValue(registration),
      ready: Promise.resolve(registration),
    },
  });
  vi.stubGlobal('Notification', { permission: 'granted' });
  vi.stubGlobal('PushManager', class {});
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
});

describe('notification settings persistence and gateway outcomes', () => {
  it('applies the selected risk and warns when it cannot be saved locally', async () => {
    renderNotifications();
    blockLocalSave();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Minimum alert risk to notify' }), 'medium');

    await waitFor(() => expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      minimum_alert_severity: 'medium', alert_notifications_enabled: true,
    })));
    expect(notices.info).toHaveBeenCalledWith(expect.stringMatching(/applied.*could not be saved locally/i));
    expect(notices.success).not.toHaveBeenCalled();
  });

  it('sends the disabled alert preference even when the browser cannot persist it', async () => {
    renderNotifications();
    blockLocalSave();
    await userEvent.click(screen.getByRole('switch', { name: 'Desktop notifications' }));

    await waitFor(() => expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      alert_notifications_enabled: false,
    })));
    expect(notices.info).toHaveBeenCalledWith(expect.stringMatching(/could not be saved locally/i));
    expect(notices.success).not.toHaveBeenCalled();
  });

  it('does not claim a save or applied change when neither storage nor a subscription is available', async () => {
    getSubscription.mockResolvedValue(null);
    renderNotifications();
    blockLocalSave();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Minimum alert risk to notify' }), 'low');

    await waitFor(() => expect(notices.error).toHaveBeenCalledWith(expect.stringMatching(/could not save.*no.*subscription/i)));
    expect(gateway.subscribe).not.toHaveBeenCalled();
    expect(notices.success).not.toHaveBeenCalled();
    expect(notices.info).not.toHaveBeenCalled();
  });

  it.each([true, false])('distinguishes a gateway failure from local persistence (saved: %s)', async (saved) => {
    gateway.subscribe.mockRejectedValue(new Error('Gateway unavailable'));
    renderNotifications();
    if (!saved) blockLocalSave();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Minimum alert risk to notify' }), 'medium');

    await waitFor(() => expect(notices.error).toHaveBeenCalledWith(expect.stringContaining('Gateway unavailable')));
    const message = notices.error.mock.calls[0][0] as string;
    expect(message.startsWith('Saved locally')).toBe(saved);
    expect(notices.success).not.toHaveBeenCalled();
  });

  it('enrolls the explicit current preference and reports the local persistence failure', async () => {
    window.localStorage.setItem('aisoc:settings:preferences', JSON.stringify({
      minimumAlertSeverity: 'critical', desktopNotifications: false,
    }));
    renderNotifications();
    blockLocalSave();
    await userEvent.click(screen.getByRole('button', { name: 'Enable / refresh Web Push on this device' }));

    await waitFor(() => expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      minimum_alert_severity: 'critical', alert_notifications_enabled: true,
    })));
    expect(notices.info).toHaveBeenCalledWith(expect.stringMatching(/enabled.*could not be saved locally/i));
    expect(notices.success).not.toHaveBeenCalled();
  });
});
