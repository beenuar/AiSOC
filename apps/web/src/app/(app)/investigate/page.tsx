/**
 * /investigate → /hunt redirect (T3.4).
 *
 * Track 3 collapses the standalone "Investigation" route into the new
 * /hunt natural-language hunt surface. The investigation chat + timeline
 * components live on at /hunt and are reachable via the same deep-link
 * shape — any querystring (e.g. ``?runId=<uuid>``) the legacy callers
 * relied on is preserved, so notification emails, agent runs, and
 * bookmarked URLs from before the rebrand keep working.
 *
 * Server-side redirect (Next 13+ ``redirect()``) so we never render the
 * old chat UI even for a flash; the browser sees a 307 and lands on
 * /hunt with the URL bar updated.
 */

import { permanentRedirect } from "next/navigation";

export const metadata = {
  title: "Investigate | AiSOC",
};

interface InvestigatePageProps {
  searchParams?: Record<string, string | string[] | undefined>;
}

function buildHuntUrl(
  searchParams: Record<string, string | string[] | undefined> | undefined,
): string {
  if (!searchParams) return "/hunt";
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(searchParams)) {
    if (value == null) continue;
    if (Array.isArray(value)) {
      for (const v of value) {
        if (v != null) params.append(key, v);
      }
    } else {
      params.append(key, value);
    }
  }
  const qs = params.toString();
  return qs ? `/hunt?${qs}` : "/hunt";
}

export default function InvestigateRedirect({
  searchParams,
}: InvestigatePageProps) {
  // ``permanentRedirect`` emits a 308 so analytics + browser caches treat
  // /hunt as the canonical address. Use ``redirect`` (307) instead if we
  // ever need to flip the canonical route back.
  permanentRedirect(buildHuntUrl(searchParams));
}
