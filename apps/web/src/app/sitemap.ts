import type { MetadataRoute } from "next";

import { getPublicSiteUrl } from "../lib/site";

export default function sitemap(): MetadataRoute.Sitemap {
  const base = getPublicSiteUrl();
  const now = new Date();

  const highPriority = ["/", "/benchmark"];
  const mediumPriority = ["/purple-team", "/responder", "/why-open-source"];
  const lowPriority = ["/login", "/signup", "/detection", "/threat-intel"];

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
