import type { Metadata } from "next";

import { getPublicSiteUrl } from "../../../../lib/site";
import { Nl2SigmaTool } from "./Nl2SigmaTool";

export const metadata: Metadata = {
  title: "Natural language to Sigma rule generator | AiSOC",
  description:
    "Describe a threat in plain English and get a Sigma detection rule plus Splunk SPL, Microsoft Sentinel KQL, and Elastic ES|QL equivalents. Free, in-browser, open source.",
  alternates: { canonical: `${getPublicSiteUrl()}/tools/nl2sigma` },
  openGraph: {
    title: "Natural language to Sigma rule generator | AiSOC",
    description: "Plain English → Sigma + SPL + KQL + ES|QL. Free & open source.",
    url: `${getPublicSiteUrl()}/tools/nl2sigma`,
  },
};

const JSON_LD = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "AiSOC Natural Language to Sigma",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Web",
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  url: `${getPublicSiteUrl()}/tools/nl2sigma`,
};

export default function Nl2SigmaPage() {
  return (
    <main>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }} />
      <h1 style={{ fontSize: 30, fontWeight: 800, margin: 0 }}>Plain English → Sigma</h1>
      <p style={{ color: "#8b93b7", fontSize: 16, marginTop: 10, maxWidth: 680 }}>
        Describe the behaviour you want to detect and get a Sigma rule plus Splunk SPL, Sentinel KQL, and Elastic ES|QL. A
        deterministic scaffold generated in your browser — a starting point you refine, not a black box.
      </p>
      <div style={{ marginTop: 24 }}>
        <Nl2SigmaTool />
      </div>
    </main>
  );
}
