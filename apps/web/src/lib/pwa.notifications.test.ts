import { beforeEach, describe, expect, it } from 'vitest';
import {
  isAlertPushSeverity,
  readAlertPushPreferences,
  saveAlertPushPreferences,
} from './pwa';

beforeEach(() => window.localStorage.clear());

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
    saveAlertPushPreferences({ minimumAlertSeverity: 'medium' });
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
});
