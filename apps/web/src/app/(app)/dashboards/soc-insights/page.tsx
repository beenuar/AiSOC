/**
 * SOC Insights dashboard (T3.1 — v8.0 parallel team plan).
 *
 * Renders 7 rolling-window tiles — MTTA, MTTR, FP rate, alerts/day,
 * cases/day, agent cost / investigation, analyst hours saved — each
 * with a current value, a previous-period delta (or em-dash when the
 * previous window was empty), and a 24-bucket inline-SVG sparkline.
 *
 * Data flow:
 *
 *   SWR(`/v1/insights/soc?window=…`) <─ user clicks 24h / 7d / 30d
 *                                    ▲
 *                                    │ revalidate()
 *               WebSocket(`insights`) — `insights_updated` poke
 *
 * The page never polls. The realtime gateway broadcasts an
 * `insights_updated` event every 30s (and on relevant case changes);
 * the WebSocket listener calls SWR's `mutate()` so the tiles re-fetch.
 * If WebSocket is unavailable, SWR's `revalidateOnFocus` still keeps
 * numbers fresh when the analyst returns to the tab.
 */

import { SOCInsightsView } from '@/components/soc-insights/SOCInsightsView';

export const metadata = {
  title: 'SOC Insights | AiSOC',
};

export default function SOCInsightsPage() {
  return <SOCInsightsView />;
}
