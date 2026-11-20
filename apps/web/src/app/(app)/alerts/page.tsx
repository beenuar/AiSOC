import { AlertsView } from '@/components/alerts/AlertsView';
import type { AlertFilters } from '@/lib/api';

export const metadata = {
  title: 'Alerts',
};

type SearchParams = Record<string, string | string[] | undefined>;

export default async function AlertsPage({
  searchParams,
}: {
  searchParams?: Promise<SearchParams>;
}) {
  // Read the deep link on the server so the first render selects the alert
  // grid, not the default entity queue. Do not trust tenant IDs in the URL:
  // API tenant scoping comes from the authenticated principal.
  const params = (await searchParams) ?? {};
  const value = (key: string) => {
    const item = params[key];
    return Array.isArray(item) ? item[0] : item;
  };
  const severity = value('severity');
  const status = value('status');
  const hours = value('created_within_hours');
  const parsedHours = hours && /^\d{1,4}$/.test(hours) ? Number(hours) : undefined;
  const createdWithinHours =
    parsedHours !== undefined && parsedHours >= 1 && parsedHours <= 8760
      ? parsedHours
      : undefined;
  const unresolvedOnly = value('unresolved_only') === 'true';

  const initialFilters: Partial<AlertFilters> = {
    ...(severity && /^(critical|high|medium|low|info)$/.test(severity) ? { severity } : {}),
    ...(status && /^[a-z_]{1,40}$/.test(status) ? { status } : {}),
    ...(unresolvedOnly ? { unresolvedOnly: true } : {}),
    ...(createdWithinHours !== undefined ? { createdWithinHours } : {}),
  };
  const initialViewMode =
    value('view') === 'alerts' || Object.keys(initialFilters).length > 0
      ? 'alerts'
      : 'entities';

  // A new deep link must replace a previously mounted alert grid (including
  // its local pagination and filters) when navigating within the app.
  return (
    <AlertsView
      key={JSON.stringify([initialViewMode, initialFilters])}
      initialViewMode={initialViewMode}
      initialFilters={initialFilters}
    />
  );
}
