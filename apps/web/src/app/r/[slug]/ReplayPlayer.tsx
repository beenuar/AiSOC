"use client";

import { useEffect, useMemo, useState } from "react";
import type { ReplaySnapshot } from "../../../lib/replay";

/**
 * Read-only animated playback of a redacted investigation replay.
 *
 * Timeline scrubber over the ledger traversal: evidence cards appear per step,
 * the attack graph grows, and a verdict stamp lands at the end with the elapsed
 * time. Dependency-free (hand-rolled SVG) so the public page stays lightweight
 * and CDN-cacheable.
 */

const KIND_COLOR: Record<string, string> = {
  recon: "#38bdf8",
  forensic: "#a78bfa",
  tool_call: "#22c55e",
  llm_call: "#f59e0b",
  llm_response: "#f59e0b",
  evidence_cited: "#ec4899",
  responder: "#f87171",
  report: "#e6e9f5",
  reporter: "#e6e9f5",
  decision_reason: "#94a3b8",
  debate: "#8b5cf6",
};

function verdictTone(verdict: string): { label: string; color: string } {
  const v = verdict.toLowerCase();
  if (/true|confirmed|incident|positive/.test(v)) return { label: verdict.replace(/_/g, " "), color: "#f87171" };
  if (/review|needs/.test(v)) return { label: verdict.replace(/_/g, " "), color: "#fbbf24" };
  return { label: verdict.replace(/_/g, " "), color: "#22c55e" };
}

export function ReplayPlayer({ snapshot }: { snapshot: ReplaySnapshot }) {
  const total = snapshot.steps.length;
  const [cursor, setCursor] = useState(total); // start fully revealed
  const [playing, setPlaying] = useState(false);

  useEffect(() => {
    if (!playing) return;
    if (cursor >= total) {
      setPlaying(false);
      return;
    }
    const t = setTimeout(() => setCursor((c) => Math.min(c + 1, total)), 700);
    return () => clearTimeout(t);
  }, [playing, cursor, total]);

  const visibleSteps = snapshot.steps.slice(0, cursor);
  const revealedTechniques = useMemo(() => {
    // Techniques aren't per-step in the redacted snapshot, so reveal them
    // proportionally to scrubber progress for the "graph growing" effect.
    const shown = Math.ceil((cursor / Math.max(total, 1)) * snapshot.techniques.length);
    return snapshot.techniques.slice(0, shown);
  }, [cursor, total, snapshot.techniques]);

  const tone = verdictTone(snapshot.verdict);
  const elapsedSec = (snapshot.elapsedMs / 1000).toFixed(0);
  const graphVisibleNodes = Math.ceil((cursor / Math.max(total, 1)) * snapshot.attackGraph.nodes.length);

  const play = () => {
    if (cursor >= total) setCursor(0);
    setPlaying(true);
  };

  return (
    <div style={{ display: "grid", gap: 24 }}>
      {/* Controls */}
      <div style={{ display: "flex", alignItems: "center", gap: 16, flexWrap: "wrap" }}>
        <button
          onClick={() => (playing ? setPlaying(false) : play())}
          style={{
            background: "#7b2bbe",
            color: "white",
            border: "none",
            borderRadius: 8,
            padding: "8px 18px",
            fontWeight: 700,
            cursor: "pointer",
          }}
        >
          {playing ? "❚❚ Pause" : cursor >= total ? "↻ Replay" : "▶ Play"}
        </button>
        <input
          type="range"
          min={0}
          max={total}
          value={cursor}
          onChange={(e) => {
            setPlaying(false);
            setCursor(Number(e.target.value));
          }}
          style={{ flex: 1, minWidth: 200 }}
          aria-label="Investigation timeline scrubber"
        />
        <span style={{ color: "#8b93b7", fontVariantNumeric: "tabular-nums", minWidth: 90, textAlign: "right" }}>
          step {Math.min(cursor, total)} / {total}
        </span>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 24 }}>
        {/* Timeline */}
        <section style={{ minWidth: 0 }}>
          <h2 style={{ fontSize: 14, textTransform: "uppercase", letterSpacing: 1, color: "#8b93b7", margin: "0 0 12px" }}>
            Ledger traversal
          </h2>
          <ol style={{ listStyle: "none", padding: 0, margin: 0, display: "grid", gap: 8 }}>
            {visibleSteps.map((s) => (
              <li
                key={s.seq}
                style={{
                  background: "#131a33",
                  border: "1px solid #232b4d",
                  borderLeft: `3px solid ${KIND_COLOR[s.kind] ?? "#475569"}`,
                  borderRadius: 8,
                  padding: "10px 12px",
                  animation: "aisoc-fade 0.4s ease",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", gap: 8 }}>
                  <strong style={{ color: "#e6e9f5", fontSize: 13 }}>{s.agent}</strong>
                  <code style={{ color: KIND_COLOR[s.kind] ?? "#94a3b8", fontSize: 12 }}>{s.kind}</code>
                </div>
                <p style={{ margin: "4px 0 0", color: "#c4cae0", fontSize: 13, lineHeight: 1.4 }}>{s.summary}</p>
                {s.decision?.reason ? (
                  <p style={{ margin: "6px 0 0", color: "#8b93b7", fontSize: 12, fontStyle: "italic" }}>
                    ↳ {s.decision.reason}
                    {typeof s.decision.confidence === "number" ? ` (conf ${(s.decision.confidence * 100).toFixed(0)}%)` : ""}
                  </p>
                ) : null}
              </li>
            ))}
          </ol>
        </section>

        {/* Right column: attack graph + evidence + verdict */}
        <section style={{ display: "grid", gap: 20, alignContent: "start" }}>
          <div>
            <h2 style={{ fontSize: 14, textTransform: "uppercase", letterSpacing: 1, color: "#8b93b7", margin: "0 0 12px" }}>
              Attack graph
            </h2>
            <AttackGraph
              nodes={snapshot.attackGraph.nodes.slice(0, graphVisibleNodes)}
              edges={snapshot.attackGraph.edges}
            />
          </div>

          <div>
            <h2 style={{ fontSize: 14, textTransform: "uppercase", letterSpacing: 1, color: "#8b93b7", margin: "0 0 12px" }}>
              Techniques
            </h2>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
              {revealedTechniques.length === 0 ? (
                <span style={{ color: "#64748b", fontSize: 13 }}>—</span>
              ) : (
                revealedTechniques.map((t) => (
                  <span key={t} style={{ background: "#232b4d", color: "#c4cae0", borderRadius: 6, padding: "3px 8px", fontSize: 12 }}>
                    {t}
                  </span>
                ))
              )}
            </div>
          </div>

          {cursor >= total ? (
            <div
              style={{
                border: `2px solid ${tone.color}`,
                borderRadius: 12,
                padding: "16px 20px",
                animation: "aisoc-stamp 0.5s ease",
              }}
            >
              <div style={{ color: "#8b93b7", fontSize: 12, textTransform: "uppercase", letterSpacing: 1 }}>Verdict</div>
              <div style={{ color: tone.color, fontSize: 28, fontWeight: 800, textTransform: "uppercase" }}>{tone.label}</div>
              <div style={{ color: "#8b93b7", fontSize: 13, marginTop: 6 }}>
                Investigated in {elapsedSec}s · {snapshot.stepCount} steps · {snapshot.toolCallCount} tool calls ·{" "}
                {snapshot.evidenceSourceCount} evidence sources
              </div>
            </div>
          ) : null}
        </section>
      </div>

      <style>{`
        @keyframes aisoc-fade { from { opacity: 0; transform: translateY(6px);} to { opacity: 1; transform: none; } }
        @keyframes aisoc-stamp { from { opacity: 0; transform: scale(0.9);} to { opacity: 1; transform: none; } }
      `}</style>
    </div>
  );
}

function AttackGraph({
  nodes,
  edges,
}: {
  nodes: ReplaySnapshot["attackGraph"]["nodes"];
  edges: ReplaySnapshot["attackGraph"]["edges"];
}) {
  const width = 520;
  const rowH = 54;
  const height = Math.max(120, nodes.length * rowH + 20);
  const pos = new Map(nodes.map((n, i) => [n.id, { x: 90 + (i % 2) * 240, y: 30 + i * rowH }]));

  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} style={{ background: "#0b1020", border: "1px solid #232b4d", borderRadius: 8 }}>
      {edges.map((e, i) => {
        const a = pos.get(e.source);
        const b = pos.get(e.target);
        if (!a || !b) return null;
        return <line key={i} x1={a.x} y1={a.y} x2={b.x} y2={b.y} stroke="#334155" strokeWidth={1.5} />;
      })}
      {nodes.map((n) => {
        const p = pos.get(n.id)!;
        const isAlert = n.kind === "alert";
        return (
          <g key={n.id} style={{ animation: "aisoc-fade 0.4s ease" }}>
            <circle cx={p.x} cy={p.y} r={isAlert ? 16 : 12} fill={isAlert ? "#f87171" : "#7b2bbe"} />
            <text x={p.x + 22} y={p.y + 4} fill="#c4cae0" fontSize={13} fontFamily="ui-sans-serif,system-ui">
              {n.label}
            </text>
          </g>
        );
      })}
    </svg>
  );
}
