import type { Metadata } from "next";

import { getPublicSiteUrl } from "../../../../lib/site";
import { NoiseTool } from "./NoiseTool";

export const metadata: Metadata = {
  title: "Alert noise & analyst-hours-saved calculator | AiSOC",
  description:
    "Estimate how many false-positive alerts you could auto-suppress and how many analyst hours you'd save, based on the AiSOC verdict engine's published suppression rate. Free, in-browser.",
  alternates: { canonical: `${getPublicSiteUrl()}/tools/noise` },
  openGraph: {
    title: "Alert noise calculator | AiSOC",
    description: "Estimate FP suppression and analyst hours saved. Free & open source.",
    url: `${getPublicSiteUrl()}/tools/noise`,
  },
};

const JSON_LD = {
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  name: "AiSOC Alert Noise Calculator",
  applicationCategory: "SecurityApplication",
  operatingSystem: "Web",
  offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
  url: `${getPublicSiteUrl()}/tools/noise`,
};

export default function NoisePage() {
  return (
    <main>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(JSON_LD) }} />
      <h1 style={{ fontSize: 30, fontWeight: 800, margin: 0 }}>Alert noise calculator</h1>
      <p style={{ color: "#8b93b7", fontSize: 16, marginTop: 10, maxWidth: 680 }}>
        Enter your alert volume to project false-positive suppression and analyst hours saved, using AiSOC&apos;s published
        verdict-engine operating point. Every number is computed in your browser with the methodology linked below.
      </p>
      <div style={{ marginTop: 24 }}>
        <NoiseTool />
      </div>
    </main>
  );
}
