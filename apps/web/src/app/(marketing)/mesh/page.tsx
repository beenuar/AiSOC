import type { Metadata } from "next";
import Link from "next/link";

import { getPublicSiteUrl } from "../../../lib/site";

export const metadata: Metadata = {
  title: "Threat Intel Mesh — the network that makes every AiSOC smarter",
  description:
    "AiSOC's opt-in, privacy-preserving Federated Threat Intel Mesh: self-hosted instances share hashed IOC sightings and aggregate verdict signatures. Live network stats.",
  alternates: { canonical: `${getPublicSiteUrl()}/mesh` },
};

interface MeshStats {
  instances_connected: number;
  ioc_hashes_visible: number;
  verdict_signatures_visible: number;
  k_anonymity_threshold: number;
  artifacts_received: number;
}

async function fetchStats(): Promise<MeshStats | null> {
  const base = (process.env.MESH_HUB_URL || "https://mesh.tryaisoc.com").replace(/\/$/, "");
  try {
    const res = await fetch(`${base}/v1/stats`, { next: { revalidate: 300 } });
    if (!res.ok) return null;
    return (await res.json()) as MeshStats;
  } catch {
    return null;
  }
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div style={{ background: "#131a33", border: "1px solid #232b4d", borderRadius: 12, padding: 24, textAlign: "center" }}>
      <div style={{ fontSize: 44, fontWeight: 800, color: "#7b2bbe" }}>{value}</div>
      <div style={{ color: "#8b93b7", fontSize: 14, marginTop: 6 }}>{label}</div>
    </div>
  );
}

export default async function MeshPage() {
  const stats = await fetchStats();
  const live = stats !== null;

  return (
    <main style={{ maxWidth: 960, margin: "0 auto", padding: "56px 24px" }}>
      <h1 style={{ fontSize: 38, fontWeight: 800, margin: 0 }}>The Threat Intel Mesh</h1>
      <p style={{ color: "#8b93b7", fontSize: 18, marginTop: 12, maxWidth: 680 }}>
        Every AiSOC install can make every other install smarter — without revealing its data. Instances opt in to gossip{" "}
        <strong>hashed</strong> IOC sightings and <strong>aggregate</strong> verdict signatures through a lightweight,
        open-source hub. No raw indicators, no entities, no tenant data ever leave your perimeter.
      </p>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 16, marginTop: 36 }}>
        <Stat value={live ? String(stats!.instances_connected) : "—"} label="instances connected" />
        <Stat value={live ? stats!.ioc_hashes_visible.toLocaleString() : "—"} label="IOC signatures shared" />
        <Stat value={live ? stats!.verdict_signatures_visible.toLocaleString() : "—"} label="verdict signatures shared" />
        <Stat value={live ? `k=${stats!.k_anonymity_threshold}` : "k=5"} label="k-anonymity threshold" />
      </div>

      {!live ? (
        <p style={{ color: "#fbbf24", fontSize: 14, marginTop: 20 }}>
          The community hub isn&apos;t reporting stats yet — be one of the first instances to join. Run your own hub from{" "}
          <code>services/mesh</code>.
        </p>
      ) : null}

      <section style={{ marginTop: 48 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700 }}>Community FP-suppression lift</h2>
        <p style={{ color: "#8b93b7", fontSize: 15, marginTop: 8, maxWidth: 680 }}>
          The mesh adds a bounded (±0.10) community-consensus signal to the verdict engine. We will publish the{" "}
          <em>measured</em> false-positive-suppression lift (mesh enabled vs. disabled) on the{" "}
          <Link href="/benchmark" style={{ color: "#c4cae0" }}>
            benchmark page
          </Link>{" "}
          once it&apos;s run on real multi-instance data. Until then any lift figure shown is explicitly labelled{" "}
          <strong>simulated</strong> — we never present a synthetic number as measured production performance.
        </p>
      </section>

      <section style={{ marginTop: 40 }}>
        <h2 style={{ fontSize: 22, fontWeight: 700 }}>Trust the code, not a promise</h2>
        <p style={{ color: "#8b93b7", fontSize: 15, marginTop: 8, maxWidth: 680 }}>
          The mesh is opt-in, the hub is open source, and <code>mesh preview</code> shows exactly what would leave your
          instance before you enable it. Read the{" "}
          <a href="https://github.com/beenuar/AiSOC/blob/main/docs/architecture/mesh.md" style={{ color: "#c4cae0" }}>
            threat model
          </a>
          .
        </p>
      </section>
    </main>
  );
}
