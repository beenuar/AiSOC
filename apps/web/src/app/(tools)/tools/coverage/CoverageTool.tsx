"use client";

import { useMemo, useState } from "react";
import { renderCardSvg } from "@aisoc/report-card";

import { gradeCoverage } from "../../../../lib/tools/coverage";

const SAMPLE = `# Paste your Sigma rules (or a list of technique IDs).
tags:
  - attack.t1566
  - attack.t1059.001
  - attack.t1486
  - attack.t1078`;

const GRADE_COLOR: Record<string, string> = { A: "#22c55e", B: "#22c55e", C: "#fbbf24", D: "#fbbf24", F: "#f87171" };

export function CoverageTool() {
  const [text, setText] = useState(SAMPLE);
  const report = useMemo(() => gradeCoverage(text), [text]);

  const downloadCard = () => {
    const svg = renderCardSvg({
      kind: "coverage",
      grade: report.grade,
      covered: report.covered,
      total: report.total,
      percent: report.percent,
      topUncovered: report.topUncovered.map((t) => t.id),
    });
    const blob = new Blob([svg], { type: "image/svg+xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `aisoc-coverage-grade-${report.grade}.svg`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const gradeColor = GRADE_COLOR[report.grade] ?? "#f87171";

  return (
    <div style={{ display: "grid", gap: 20 }}>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={8}
        spellCheck={false}
        style={{
          width: "100%",
          background: "#0b1020",
          color: "#c4cae0",
          border: "1px solid #232b4d",
          borderRadius: 10,
          padding: 14,
          fontFamily: "ui-monospace,SFMono-Regular,Menlo,monospace",
          fontSize: 13,
          resize: "vertical",
        }}
      />

      <div style={{ display: "flex", gap: 24, alignItems: "center", flexWrap: "wrap" }}>
        <div style={{ fontSize: 96, fontWeight: 800, color: gradeColor, lineHeight: 1 }}>{report.grade}</div>
        <div>
          <div style={{ fontSize: 28, fontWeight: 700 }}>{report.percent}% coverage</div>
          <div style={{ color: "#8b93b7" }}>
            {report.covered} / {report.total} high-prevalence techniques covered
          </div>
        </div>
        <button onClick={downloadCard} style={{ marginLeft: "auto", ...btn, padding: "10px 16px", fontWeight: 700 }}>
          ↓ Download grade card
        </button>
      </div>

      <div>
        <h2 style={hdr}>Coverage by tactic</h2>
        <div style={{ display: "grid", gap: 8 }}>
          {report.byTactic.map((t) => {
            const pct = t.total ? Math.round((t.covered / t.total) * 100) : 0;
            return (
              <div key={t.tactic} style={{ display: "grid", gridTemplateColumns: "180px 1fr 60px", gap: 10, alignItems: "center" }}>
                <span style={{ color: "#c4cae0", fontSize: 13 }}>{t.tactic}</span>
                <div style={{ background: "#232b4d", borderRadius: 6, height: 16, overflow: "hidden" }}>
                  <div style={{ width: `${pct}%`, height: "100%", background: pct >= 60 ? "#22c55e" : pct >= 30 ? "#fbbf24" : "#f87171" }} />
                </div>
                <span style={{ color: "#8b93b7", fontSize: 12, textAlign: "right" }}>
                  {t.covered}/{t.total}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      <div>
        <h2 style={hdr}>Top 10 highest-prevalence uncovered techniques</h2>
        {report.topUncovered.length === 0 ? (
          <p style={{ color: "#22c55e" }}>Nice — every catalog technique is covered.</p>
        ) : (
          <ol style={{ margin: 0, paddingLeft: 20, color: "#c4cae0", display: "grid", gap: 4 }}>
            {report.topUncovered.map((t) => (
              <li key={t.id} style={{ fontSize: 14 }}>
                <code style={{ color: "#f87171" }}>{t.id}</code> {t.name} <span style={{ color: "#6b7394" }}>· {t.tactic}</span>
              </li>
            ))}
          </ol>
        )}
      </div>

      <p style={{ color: "#6b7394", fontSize: 12, margin: 0 }}>
        Graded against a curated 40-technique high-prevalence catalog (a quick self-check, not an authoritative audit). Runs
        entirely in your browser.
      </p>
    </div>
  );
}

const btn: React.CSSProperties = { background: "#232b4d", color: "#e6e9f5", border: "none", borderRadius: 6, padding: "6px 12px", fontSize: 13, cursor: "pointer" };
const hdr: React.CSSProperties = { fontSize: 14, textTransform: "uppercase", letterSpacing: 1, color: "#8b93b7", margin: "0 0 12px" };
