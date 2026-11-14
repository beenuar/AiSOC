import type { MetadataRoute } from "next";

import { getPublicSiteUrl } from "../lib/site";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = getPublicSiteUrl();
  const now = new Date();

  const highPriority = ["/", "/benchmark", "/connectors", "/pricing"];
  const mediumPriority = [
    "/sovereign",
    "/customers",
    "/blog",
    "/about",
    "/contact",
    "/purple-team",
    "/responder",
    "/mesh",
    "/why-open-source",
    "/marketplace",
    "/compliance",
    "/hunt",
    "/explore",
    "/copilot",
    "/graph",
  ];
  // Note: AiSOC is open source and self-hosted — there is no `/signup`
  // page. We do *not* list it here (don't ask search engines to crawl a
  // route we redirect away), but we 308 `/signup` → `/dashboard` in
  // apps/web/next.config.js so the public entry point (anonymous demo
  // tenant) catches any stale external links. The hosted login at
  // `/login` is the only auth entry point we ship; the `/waitlist`
  // page is for the separate managed-instance invite-only beta.
  const lowPriority = [
    "/login",
    "/detection",
    "/threat-intel",
    "/sla",
    "/press",
    "/privacy",
    "/terms",
  ];

  // Free standalone tools (search-indexed acquisition — v8 W2). The four tool
  // hubs are medium priority; the 30 programmatic format-pair pages
  // (/tools/translate/<from>-to-<to>) are lower but each targets a distinct
  // long-tail query ("spl to kql", "sigma to esql", …).
  const toolHubs = ["/tools", "/tools/translate", "/tools/nl2sigma", "/tools/coverage", "/tools/noise"];
  const formatSlugs = ["sigma", "spl", "kql", "esql", "yaral", "udm"];
  const translatePairs: string[] = [];
  for (const from of formatSlugs) {
    for (const to of formatSlugs) {
      if (from !== to) translatePairs.push(`/tools/translate/${from}-to-${to}`);
    }
  }

  return [
    ...toolHubs.map((path) => ({
      url: `${base}${path}`,
      lastModified: now,
      changeFrequency: "weekly" as const,
      priority: 0.7,
    })),
    ...translatePairs.map((path) => ({
      url: `${base}${path}`,
      lastModified: now,
      changeFrequency: "monthly" as const,
      priority: 0.5,
    })),
    ...highPriority.map((path) => ({
      url: `${base}${path}`,
      lastModified: now,
      changeFrequency: "weekly" as const,
      priority: path === "/" ? 1 : 0.9,
    })),
    ...mediumPriority.map((path) => ({
      url: `${base}${path}`,
      lastModified: now,
      changeFrequency: "monthly" as const,
      priority: 0.7,
    })),
    ...lowPriority.map((path) => ({
      url: `${base}${path}`,
      lastModified: now,
      changeFrequency: "monthly" as const,
      priority: 0.5,
    })),
  ];
}
