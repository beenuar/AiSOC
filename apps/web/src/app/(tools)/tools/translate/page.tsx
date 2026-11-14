import type { Metadata } from "next";

import { getPublicSiteUrl } from "../../../../lib/site";
import { TranslateTool } from "./TranslateTool";

export const metadata: Metadata = {
  title: "Detection rule translator — Sigma ↔ SPL ↔ KQL ↔ ES|QL ↔ YARA-L | AiSOC",
  description:
    "Free, in-browser detection-rule translator. Paste a Sigma, Splunk SPL, Microsoft Sentinel KQL, Elastic ES|QL, or Chronicle YARA-L rule and get every other dialect at once. No login, no upload, open source.",
  alternates: { canonical: `${getPublicSiteUrl()}/tools/translate` },
  openGraph: {
    title: "Detection rule translator — Sigma ↔ SPL ↔ KQL ↔ ES|QL | AiSOC",
    description: "Translate detection rules across every major SIEM dialect, in your browser. Free & open source.",
    url: `${getPublicSiteUrl()}/tools/translate`,
  },
};

const JSON_LD = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "AiSOC Detection Rule Translator",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Web",
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  description: "Translate detection rules across Sigma, Splunk SPL, Microsoft Sentinel KQL, Elastic ES|QL, and Google Chronicle YARA-L / UDM.",
  url: `${getPublicSiteUrl()}/tools/translate`,
};

export default function TranslatePage() {
  return (
    <main>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }} />
      <h1 style={{ fontSize: 30, fontWeight: 800, margin: 0 }}>Detection rule translator</h1>
      <p style={{ color: "#8b93b7", fontSize: 16, marginTop: 10, maxWidth: 680 }}>
        Paste a rule in any format and get every other dialect at once — Sigma, Splunk SPL, Microsoft Sentinel KQL, Elastic
        ES|QL, and Google Chronicle YARA-L2 / UDM. Deterministic and computed entirely in your browser.
      </p>
      <div style={{ marginTop: 24 }}>
        <TranslateTool />
      </div>
    </main>
  );
}
