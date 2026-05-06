import type { MetadataRoute } from "next";

import { getPublicSiteUrl } from "../lib/site";

export default function robots(): MetadataRoute.Robots {
  const base = getPublicSiteUrl();
  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: ["/api/", "/_next/", "/dashboard/", "/cases/"],
      },
      {
        userAgent: "Googlebot",
        allow: "/",
      },
    ],
    sitemap: `${base}/sitemap.xml`,
    host: base,
  };
}
