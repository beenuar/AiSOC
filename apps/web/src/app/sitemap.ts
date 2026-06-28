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
    "/why-open-source",
    "/marketplace",
    "/compliance",
    "/hunt",
    "/copilot",
    "/graph",
  ];
  // Note: AiSOC is open source and self-hosted — there is no `/signup` route.
  // Anonymous demo lands directly via `/` and the in-app demo button. The
  // hosted login at `/login` is the only auth entry point we ship.
  const lowPriority = [
    "/login",
    "/detection",
    "/threat-intel",
    "/sla",
    "/press",
    "/privacy",
    "/terms",
  ];

  return [
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
