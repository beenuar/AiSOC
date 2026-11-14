import { ImageResponse } from "next/og";

import { fetchPublicReplay } from "../../../lib/replay";

// Dynamic OG image for public replay unfurls on X / LinkedIn / Slack.
export const runtime = "nodejs";
export const alt = "AiSOC investigation replay";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

function verdictColor(verdict: string): string {
  const v = verdict.toLowerCase();
  if (/true|confirmed|incident|positive/.test(v)) return "#f87171";
  if (/review|needs/.test(v)) return "#fbbf24";
  return "#22c55e";
}

export default async function Image({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const result = await fetchPublicReplay(slug);
  const replay = result.kind === "ok" ? result.replay : null;
  const s = replay?.snapshot;
  const verdict = s?.verdict ?? "unknown";
  const title = replay?.title ?? "Investigation replay";
  const elapsed = s ? `${(s.elapsedMs / 1000).toFixed(0)}s` : "—";
  const techniques = (s?.techniques ?? []).slice(0, 6).join("  ·  ");

  return new ImageResponse(
    (
      <div
        style={{
          width: "100%",
          height: "100%",
          display: "flex",
          flexDirection: "column",
          background: "linear-gradient(135deg, #0b1020, #131a33)",
          color: "#e6e9f5",
          fontFamily: "sans-serif",
          padding: 64,
        }}
      >
        <div style={{ display: "flex", height: 8, width: "100%", background: "#7b2bbe", position: "absolute", top: 0, left: 0 }} />
        <div style={{ fontSize: 32, fontWeight: 700 }}>AiSOC · investigation replay</div>
        <div style={{ fontSize: 26, color: "#8b93b7", marginTop: 12 }}>{title.slice(0, 64)}</div>
        <div style={{ fontSize: 84, fontWeight: 800, color: verdictColor(verdict), marginTop: 40, textTransform: "uppercase" }}>
          {verdict.replace(/_/g, " ")}
        </div>
        <div style={{ fontSize: 26, color: "#8b93b7", marginTop: 12 }}>{techniques || "no techniques"}</div>
        <div style={{ display: "flex", gap: 56, marginTop: "auto" }}>
          <Stat value={elapsed} label="to verdict" />
          <Stat value={String(s?.stepCount ?? 0)} label="steps" />
          <Stat value={String(s?.toolCallCount ?? 0)} label="tool calls" />
          <Stat value={String(s?.evidenceSourceCount ?? 0)} label="evidence" />
        </div>
        <div style={{ fontSize: 22, color: "#6b7394", marginTop: 24 }}>tryaisoc.com · github.com/beenuar/AiSOC</div>
      </div>
    ),
    size,
  );
}

function Stat({ value, label }: { value: string; label: string }) {
  return (
    <div style={{ display: "flex", flexDirection: "column" }}>
      <div style={{ fontSize: 40, fontWeight: 700 }}>{value}</div>
      <div style={{ fontSize: 22, color: "#8b93b7" }}>{label}</div>
    </div>
  );
}
