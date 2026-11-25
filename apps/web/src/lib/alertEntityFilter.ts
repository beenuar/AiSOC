import type { AlertEntityType } from '@/lib/api';

export const ALERT_ENTITY_LABELS: Record<AlertEntityType, string> = {
  host: 'Host',
  user: 'User',
  ip: 'IP',
  domain: 'Domain',
  asset: 'Asset',
  url: 'URL',
};

export function isAlertEntityType(value: unknown): value is AlertEntityType {
  return typeof value === 'string' && Object.hasOwn(ALERT_ENTITY_LABELS, value);
}

export function entityAlertsHref(type: AlertEntityType, value: string): string {
  const params = new URLSearchParams({
    view: 'alerts',
    page: '1',
    entity_type: type,
    entity_value: value,
  });
  return `/alerts?${params}`;
}
