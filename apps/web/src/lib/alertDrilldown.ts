import type { AlertFilters } from '@/lib/api';

export type AlertDrilldown = ReturnType<typeof readAlertDrilldown>;

const DRILLDOWN_FILTER_KEYS = [
  'severity',
  'status',
  'unresolvedOnly',
  'createdWithinHours',
] as const satisfies readonly (keyof AlertFilters)[];

const QUEUE_URL_FILTER_KEYS = [
  'page',
  'pageSize',
  'search',
  'disposition',
] as const satisfies readonly (keyof AlertFilters)[];

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

  const pageRaw = params.get('page');
  const pageParsed = pageRaw && /^\d{1,5}$/.test(pageRaw) ? Number(pageRaw) : NaN;
  const page = Number.isFinite(pageParsed) && pageParsed >= 1 ? pageParsed : undefined;

  const sizeRaw = params.get('pageSize') ?? params.get('page_size');
  const sizeParsed = sizeRaw && /^\d+$/.test(sizeRaw) ? Number(sizeRaw) : NaN;
  const pageSize =
    Number.isFinite(sizeParsed) && [25, 50, 100, 200].includes(sizeParsed) ? sizeParsed : undefined;

  const searchRaw = params.get('search');
  const search =
    searchRaw && searchRaw.length > 0 && searchRaw.length <= 500 ? searchRaw : undefined;

  const dispositionRaw = params.get('disposition');
  const disposition =
    dispositionRaw && dispositionRaw !== 'any' && /^[a-z0-9_]{1,40}$/i.test(dispositionRaw)
      ? dispositionRaw
      : undefined;

  const filters: Partial<AlertFilters> = {
    ...(page !== undefined ? { page } : {}),
    ...(pageSize !== undefined ? { pageSize } : {}),
    ...(search !== undefined ? { search } : {}),
    ...(disposition !== undefined ? { disposition } : {}),
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

/** Apply URL-authoritative filters on top of local console state (history-aware). */
export function mergeAlertFiltersFromUrl(
  localFilters: AlertFilters,
  drilldown: AlertDrilldown | undefined,
): AlertFilters {
  if (!drilldown || drilldown.viewMode !== 'alerts') return localFilters;
  const next: AlertFilters = { ...localFilters };
  for (const key of DRILLDOWN_FILTER_KEYS) {
    const value = drilldown.filters[key];
    if (value === undefined) delete next[key];
    else next[key] = value as never;
  }
  for (const key of QUEUE_URL_FILTER_KEYS) {
    if (!(key in drilldown.filters)) continue;
    const value = drilldown.filters[key];
    if (value === undefined) delete next[key];
    else next[key] = value as never;
  }
  return next;
}
