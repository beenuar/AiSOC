import type { AlertFilters } from '@/lib/api';

/** Shared validation for server entry, client navigation, and history restore. */
export function readAlertDrilldown(params: { get: (name: string) => string | null | undefined }) {
  const severity = params.get('severity');
  const status = params.get('status');
  const hours = params.get('created_within_hours');
  const parsedHours = hours && /^\d{1,4}$/.test(hours) ? Number(hours) : undefined;
  const createdWithinHours =
    parsedHours !== undefined && parsedHours >= 1 && parsedHours <= 8760
      ? parsedHours
      : undefined;
  const unresolvedOnly = params.get('unresolved_only') === 'true';
  const filters: Partial<AlertFilters> = {
    ...(severity && /^(critical|high|medium|low|info)$/.test(severity) ? { severity } : {}),
    ...(status && /^[a-z_]{1,40}$/.test(status) ? { status } : {}),
    ...(unresolvedOnly ? { unresolvedOnly: true } : {}),
    ...(createdWithinHours !== undefined ? { createdWithinHours } : {}),
  };
  const viewMode = params.get('view') === 'alerts' || Object.keys(filters).length > 0
    ? 'alerts' as const
    : 'entities' as const;

  return { filters, viewMode };
}
