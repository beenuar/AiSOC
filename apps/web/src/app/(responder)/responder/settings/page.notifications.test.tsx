import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import ResponderSettingsPage from './page';

const gateway = vi.hoisted(() => ({ subscribe: vi.fn(), getPublicKey: vi.fn() }));
vi.mock('next/navigation', () => ({ useRouter: () => ({ replace: vi.fn() }) }));
vi.mock('@/lib/api', () => ({
  responderApi: gateway,
  passkeyApi: { list: async () => ({ items: [] }) },
}));
vi.mock('@/lib/responder/auth', () => ({ getProfile: () => null, clearSession: vi.fn() }));

const subscription = {
  toJSON: () => ({ endpoint: 'https://push.example/responder', keys: { p256dh: 'key', auth: 'auth' } }),
};
const getSubscription = vi.fn();

beforeEach(() => {
  window.localStorage.clear();
  gateway.subscribe.mockReset().mockResolvedValue({});
  gateway.getPublicKey.mockReset().mockResolvedValue({ enabled: true, public_key: 'AQID' });
  getSubscription.mockReset().mockResolvedValue(subscription);
  const registration = {
    pushManager: { getSubscription, subscribe: vi.fn().mockResolvedValue(subscription) },
  };
  vi.stubGlobal('navigator', {
    userAgent: 'responder-regression',
    serviceWorker: {
      getRegistration: vi.fn().mockResolvedValue(registration),
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

function blockLocalSave() {
  vi.spyOn(window.localStorage, 'setItem').mockImplementation(() => { throw new Error('Storage full'); });
}

describe('responder notification persistence outcomes', () => {
  it('applies the selected risk without re-enabling alerts and reports a failed local save', async () => {
    window.localStorage.setItem('aisoc:settings:preferences', JSON.stringify({
      minimumAlertSeverity: 'high', desktopNotifications: false,
    }));
    render(<ResponderSettingsPage />);
    await screen.findByRole('button', { name: 'Disable' });
    blockLocalSave();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Minimum alert risk to notify' }), 'low');

    await waitFor(() => expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      minimum_alert_severity: 'low', alert_notifications_enabled: false,
    })));
    expect(await screen.findByRole('status')).toHaveTextContent(/applied.*could not be saved locally/i);
  });

  it('reports failure when there is no subscription and local storage is unavailable', async () => {
    getSubscription.mockResolvedValue(null);
    render(<ResponderSettingsPage />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeEnabled());
    blockLocalSave();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Minimum alert risk to notify' }), 'medium');

    expect(await screen.findByRole('status')).toHaveTextContent(/could not save.*no.*subscription/i);
    expect(gateway.subscribe).not.toHaveBeenCalled();
  });

  it('keeps an unsaved risk selection when the user enables push', async () => {
    getSubscription.mockResolvedValue(null);
    render(<ResponderSettingsPage />);
    await waitFor(() => expect(screen.getByRole('button', { name: 'Enable' })).toBeEnabled());
    blockLocalSave();
    await userEvent.selectOptions(screen.getByRole('combobox', { name: 'Minimum alert risk to notify' }), 'medium');
    await userEvent.click(screen.getByRole('button', { name: 'Enable' }));

    await waitFor(() => expect(gateway.subscribe).toHaveBeenCalledWith(expect.objectContaining({
      minimum_alert_severity: 'medium', alert_notifications_enabled: true,
    })));
    expect(await screen.findByRole('status')).toHaveTextContent(/enabled.*could not be saved locally/i);
  });
});
