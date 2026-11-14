import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";

import { getPublicSiteUrl } from "../../../../../lib/site";
import { FORMAT_LABELS, ALL_FORMATS, type DetectionFormat } from "../../../../../lib/tools/translate";
import { TranslateTool } from "../TranslateTool";

// URL-slug token per format (e.g. "yaral" instead of "yara_l2").
const SLUG: Record<DetectionFormat, string> = {
  sigma: "sigma",
  spl: "spl",
  kql: "kql",
  esql: "esql",
  yara_l2: "yaral",
  udm: "udm",
};
const FROM_SLUG: Record<string, DetectionFormat> = Object.fromEntries(Object.entries(SLUG).map(([k, v]) => [v, k as DetectionFormat]));

interface PageProps {
  params: Promise<{ pair: string }>;
}

/** Parse "spl-to-kql" → { from, to }. */
function parsePair(pair: string): { from: DetectionFormat; to: DetectionFormat } | null {
  const m = pair.toLowerCase().match(/^([a-z0-9]+)-to-([a-z0-9]+)$/);
  if (!m) return null;
  const from = FROM_SLUG[m[1]!];
  const to = FROM_SLUG[m[2]!];
  if (!from || !to || from === to) return null;
  return { from, to };
}

/** Emit all 30 source→target permutations for static generation. */
export function generateStaticParams(): { pair: string }[] {
  const params: { pair: string }[] = [];
  for (const from of ALL_FORMATS) {
    for (const to of ALL_FORMATS) {
      if (from !== to) params.push({ pair: `${SLUG[from]}-to-${SLUG[to]}` });
    }
  }
  return params;
}

export async function generateMetadata({ params }: PageProps): Promise<Metadata> {
  const { pair } = await params;
  const parsed = parsePair(pair);
  if (!parsed) return { title: "Detection translator | AiSOC" };
  const fromL = FORMAT_LABELS[parsed.from];
  const toL = FORMAT_LABELS[parsed.to];
  const title = `${fromL} to ${toL} — free detection rule converter | AiSOC`;
  const description = `Convert ${fromL} detection rules to ${toL} instantly and for free, in your browser. Open source, no login. Part of AiSOC.`;
  const url = `${getPublicSiteUrl()}/tools/translate/${pair}`;
  return { title, description, alternates: { canonical: url }, openGraph: { title, description, url } };
}

export default async function PairPage({ params }: PageProps) {
  const { pair } = await params;
  const parsed = parsePair(pair);
  if (!parsed) notFound();
  const fromL = FORMAT_LABELS[parsed.from];
  const toL = FORMAT_LABELS[parsed.to];

  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "HowTo",
    name: `Convert ${fromL} to ${toL}`,
    description: `Convert a ${fromL} detection rule to ${toL}.`,
    step: [
      { "@type": "HowToStep", text: `Paste your ${fromL} rule into the editor.` },
      { "@type": "HowToStep", text: `Copy the generated ${toL} equivalent.` },
    ],
  };

  return (
    <main>
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }} />
      <nav style={{ fontSize: 13, color: "#6b7394" }}>
        <Link href="/tools/translate" style={{ color: "#8b93b7" }}>
          ← All formats
        </Link>
      </nav>
      <h1 style={{ fontSize: 30, fontWeight: 800, margin: "12px 0 0" }}>
        Convert {fromL} to {toL}
      </h1>
      <p style={{ color: "#8b93b7", fontSize: 16, marginTop: 10, maxWidth: 680 }}>
        Free, in-browser {fromL} → {toL} detection-rule converter. Paste your {fromL} rule below; the {toL} equivalent (and every
        other dialect) is generated instantly. Deterministic, open source, no upload.
      </p>
      <div style={{ marginTop: 24 }}>
        <TranslateTool initialFormat={parsed.from} />
      </div>
    </main>
  );
}
