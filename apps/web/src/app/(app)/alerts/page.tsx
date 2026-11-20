import { AlertsView } from '@/components/alerts/AlertsView';
import { readAlertDrilldown } from '@/lib/alertDrilldown';

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
  const { filters: initialFilters, viewMode: initialViewMode } = readAlertDrilldown({
    get: (key) => {
      const item = params[key];
      return Array.isArray(item) ? item[0] : item;
    },
  });

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
