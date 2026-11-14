import type { Metadata } from "next";
import Link from "next/link";

import { getPublicSiteUrl } from "../../../lib/site";

export const metadata: Metadata = {
  title: "Free SOC tools — detection translator, ATT&CK coverage grader, noise calculator | AiSOC",
  description:
    "Free, open-source tools for security analysts: translate detection rules across Sigma/SPL/KQL/ES|QL, grade your ATT&CK coverage, generate Sigma from plain English, and calculate alert-noise savings. Runs in your browser.",
  alternates: { canonical: `${getPublicSiteUrl()}/tools` },
};

const TOOLS = [
  {
    href: "/tools/translate",
    title: "Detection Translator",
    blurb: "Paste any rule, get Sigma / SPL / KQL / ES|QL / YARA-L2 / UDM simultaneously. Deterministic, in-browser.",
  },
  {
    href: "/tools/nl2sigma",
    title: "NL → Detection",
    blurb: "Describe a threat in plain English, get a Sigma rule plus the three major SIEM dialects.",
  },
  {
    href: "/tools/coverage",
    title: "ATT&CK Coverage Grader",
    blurb: "Paste your Sigma rules, get an ATT&CK heatmap, an A–F coverage grade, and your top uncovered techniques.",
  },
  {
    href: "/tools/noise",
    title: "Alert Noise Calculator",
    blurb: "Estimate false-positive suppression and analyst hours saved from your alert volume.",
  },
];

export default function ToolsIndex() {
  return (
    <main>
      <h1 style={{ fontSize: 34, fontWeight: 800, margin: 0 }}>Free tools for security analysts</h1>
      <p style={{ color: "#8b93b7", fontSize: 17, marginTop: 12, maxWidth: 640 }}>
        No login, no upload, no catch. Everything runs in your browser and is open source. Part of{" "}
        <a href="https://github.com/beenuar/AiSOC" style={{ color: "#c4cae0" }}>
          AiSOC
        </a>
        .
      </p>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, marginTop: 32 }}>
        {TOOLS.map((t) => (
          <Link
            key={t.href}
            href={t.href}
            style={{
              display: "block",
              background: "#131a33",
              border: "1px solid #232b4d",
              borderRadius: 12,
              padding: 20,
              textDecoration: "none",
              color: "#e6e9f5",
            }}
          >
            <h2 style={{ fontSize: 19, fontWeight: 700, margin: 0 }}>{t.title}</h2>
            <p style={{ color: "#8b93b7", fontSize: 14, marginTop: 8, lineHeight: 1.5 }}>{t.blurb}</p>
          </Link>
        ))}
      </div>
    </main>
  );
}
