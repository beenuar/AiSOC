import type { Metadata } from "next";

import { getPublicSiteUrl } from "../../../../lib/site";
import { CoverageTool } from "./CoverageTool";

export const metadata: Metadata = {
  title: "MITRE ATT&CK coverage grader for Sigma rules | AiSOC",
  description:
    "Paste your Sigma detection rules and get a free MITRE ATT&CK coverage grade (A–F), a per-tactic heatmap, and your top uncovered high-prevalence techniques. In-browser, open source.",
  alternates: { canonical: `${getPublicSiteUrl()}/tools/coverage` },
  openGraph: {
    title: "MITRE ATT&CK coverage grader | AiSOC",
    description: "Grade your detection coverage A–F and see your top uncovered techniques. Free & open source.",
    url: `${getPublicSiteUrl()}/tools/coverage`,
  },
};

const JSON_LD = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "AiSOC ATT&CK Coverage Grader",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Web",
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  url: `${getPublicSiteUrl()}/tools/coverage`,
};

export default function CoveragePage() {
  return (
    <main>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }} />
      <h1 style={{ fontSize: 30, fontWeight: 800, margin: 0 }}>ATT&CK coverage grader</h1>
      <p style={{ color: "#8b93b7", fontSize: 16, marginTop: 10, maxWidth: 680 }}>
        Paste your Sigma rules (or a list of technique IDs) and get a coverage grade, a per-tactic heatmap, and the top
        highest-prevalence techniques you&apos;re missing. Download a shareable grade card.
      </p>
      <div style={{ marginTop: 24 }}>
        <CoverageTool />
      </div>
    </main>
  );
}
