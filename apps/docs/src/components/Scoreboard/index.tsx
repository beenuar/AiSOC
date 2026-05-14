import React from "react";
import scoreboardData from "@site/static/data/scoreboard.json";
import styles from "./styles.module.css";

type ScoreboardRow = {
  date: string;
  agent_version: string;
  commit_sha: string;
  substrate: boolean;
  eval_mode: string;
  mitre_accuracy: number;
  mitre_accuracy_per_template?: number | null;
  alert_reduction?: number | null;
  investigation_completeness?: number | null;
  response_quality?: number | null;
  playbook_completion_rate?: number | null;
  mtc_p50_seconds?: number | null;
  mtc_p95_seconds?: number | null;
  tokens_total?: number | null;
  usd_total?: number | null;
  tokens_mean_per_investigation?: number | null;
  usd_mean_per_investigation?: number | null;
  rate_card_model?: string | null;
  rate_card_dated?: string | null;
  notes?: string | null;
};

type ScoreboardJson = {
  rows: ScoreboardRow[];
};

const data = scoreboardData as ScoreboardJson;

function pct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return `${(value * 100).toFixed(digits)}%`;
}

function num(value: number | null | undefined, digits = 0): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString("en-US", {
    minimumFractionDigits: digits,
    maximumFractionDigits: digits,
  });
}

function usd(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  if (value >= 1) return `$${value.toFixed(2)}`;
  return `$${value.toFixed(4)}`;
}

function seconds(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  if (value < 60) return `${value.toFixed(1)}s`;
  const m = Math.floor(value / 60);
  const s = Math.round(value - m * 60);
  return `${m}m${String(s).padStart(2, "0")}s`;
}

function classifySubstrate(row: ScoreboardRow) {
  return row.substrate
    ? { label: "substrate", title: "Deterministic substrate run — no LLM, no money. Do not quote as live agent performance." }
    : { label: "wet eval", title: "Live LangGraph agent against real LLM. Includes real latency and real cost." };
}

function rowsAsc(rows: ScoreboardRow[]): ScoreboardRow[] {
  return [...rows].sort((a, b) => a.date.localeCompare(b.date));
}

function MitreSparkline({ rows }: { rows: ScoreboardRow[] }) {
  const ascending = rowsAsc(rows);
  const points = ascending
    .map((r, i) => ({ x: i, y: r.mitre_accuracy, row: r }))
    .filter((p) => typeof p.y === "number");

  if (points.length === 0) {
    return (
      <p className={styles.empty}>
        No MITRE accuracy data points yet. Trend chart fills in once the T5.5
        weekly job appends rows.
      </p>
    );
  }

  // Chart geometry — small, dense, render server-side, no client JS needed.
  const W = 560;
  const H = 160;
  const PAD_L = 44;
  const PAD_R = 16;
  const PAD_T = 16;
  const PAD_B = 28;
  const innerW = W - PAD_L - PAD_R;
  const innerH = H - PAD_T - PAD_B;

  // Y axis: lock to a SOC-meaningful range so a small wobble doesn't look like
  // a regression. Substrate MITRE on a healthy harness sits in [0.85, 1.0].
  const yMin = 0.85;
  const yMax = 1.0;
  const yToPx = (y: number) =>
    PAD_T + innerH - ((y - yMin) / (yMax - yMin)) * innerH;

  const lastIdx = Math.max(points.length - 1, 1);
  const xToPx = (x: number) => PAD_L + (x / lastIdx) * innerW;

  const path = points
    .map((p, i) => `${i === 0 ? "M" : "L"} ${xToPx(p.x).toFixed(1)} ${yToPx(p.y).toFixed(1)}`)
    .join(" ");

  // Grid lines at 0.85 / 0.90 / 0.95 / 1.00.
  const yGrid = [0.85, 0.9, 0.95, 1.0];

  return (
    <figure className={styles.chartFigure}>
      <svg
        role="img"
        aria-label="MITRE accuracy trend over time across the AiSOC public eval scoreboard"
        viewBox={`0 0 ${W} ${H}`}
        className={styles.chart}
      >
        <rect x={0} y={0} width={W} height={H} className={styles.chartBg} />
        {yGrid.map((g) => (
          <g key={g}>
            <line
              x1={PAD_L}
              x2={W - PAD_R}
              y1={yToPx(g)}
              y2={yToPx(g)}
              className={styles.gridLine}
            />
            <text
              x={PAD_L - 6}
              y={yToPx(g) + 3}
              className={styles.axisLabel}
              textAnchor="end"
            >
              {(g * 100).toFixed(0)}%
            </text>
          </g>
        ))}
        {points.length > 1 && <path d={path} className={styles.line} />}
        {points.map((p) => (
          <g key={`${p.row.date}-${p.row.commit_sha}`}>
            <circle
              cx={xToPx(p.x)}
              cy={yToPx(p.y)}
              r={3.5}
              className={p.row.substrate ? styles.dotSubstrate : styles.dotWet}
            >
              <title>
                {p.row.date} • {p.row.agent_version} • MITRE {pct(p.y)} •{" "}
                {p.row.substrate ? "substrate" : "wet eval"}
              </title>
            </circle>
          </g>
        ))}
        {points.map((p, i) => (
          <text
            key={`xlabel-${i}`}
            x={xToPx(p.x)}
            y={H - 8}
            className={styles.axisLabel}
            textAnchor="middle"
          >
            {p.row.date.slice(5)}
          </text>
        ))}
      </svg>
      <figcaption className={styles.chartCaption}>
        MITRE accuracy over time, y-axis 85–100%. Hover a dot for the exact
        run. <span className={styles.swatchSubstrate}>●</span> substrate (CI
        gate, no LLM); <span className={styles.swatchWet}>●</span> wet eval
        (T5.5 weekly). One data point renders as a single dot — the line
        appears once two or more rows exist.
      </figcaption>
    </figure>
  );
}

export function ScoreboardTable({ rows }: { rows: ScoreboardRow[] }) {
  if (rows.length === 0) {
    return (
      <p className={styles.empty}>
        Scoreboard is empty. Seed rows from <code>scripts/run_evals.py</code>{" "}
        and the T5.5 weekly job land here.
      </p>
    );
  }

  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <caption className={styles.srOnly}>
          AiSOC public benchmark scoreboard — weekly eval results, newest
          first. Substrate rows are deterministic CI gates (no LLM); wet-eval
          rows are real LangGraph agent runs.
        </caption>
        <thead>
          <tr>
            <th scope="col">Date</th>
            <th scope="col">Agent</th>
            <th scope="col">Commit</th>
            <th scope="col">Mode</th>
            <th scope="col" className={styles.numCol}>MITRE acc.</th>
            <th scope="col" className={styles.numCol}>MTC p50</th>
            <th scope="col" className={styles.numCol}>MTC p95</th>
            <th scope="col" className={styles.numCol}>USD total</th>
            <th scope="col" className={styles.numCol}>Tokens total</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const klass = classifySubstrate(row);
            return (
              <tr
                key={`${row.date}-${row.commit_sha}`}
                className={row.substrate ? styles.rowSubstrate : styles.rowWet}
              >
                <td>{row.date}</td>
                <td>
                  <code>{row.agent_version}</code>
                </td>
                <td>
                  <code>{row.commit_sha.slice(0, 7)}</code>
                </td>
                <td>
                  <span
                    className={
                      row.substrate ? styles.badgeSubstrate : styles.badgeWet
                    }
                    title={klass.title}
                  >
                    {klass.label}
                  </span>
                </td>
                <td className={styles.numCol}>{pct(row.mitre_accuracy)}</td>
                <td className={styles.numCol}>
                  {row.substrate ? (
                    <span className={styles.naSubstrate} title={klass.title}>
                      n/a
                    </span>
                  ) : (
                    seconds(row.mtc_p50_seconds)
                  )}
                </td>
                <td className={styles.numCol}>
                  {row.substrate ? (
                    <span className={styles.naSubstrate} title={klass.title}>
                      n/a
                    </span>
                  ) : (
                    seconds(row.mtc_p95_seconds)
                  )}
                </td>
                <td className={styles.numCol}>
                  {usd(row.usd_total)}
                  {row.substrate && row.usd_total != null ? (
                    <span className={styles.budgetTag} title="Substrate budget projection — not a real bill.">
                      {" "}budget
                    </span>
                  ) : null}
                </td>
                <td className={styles.numCol}>{num(row.tokens_total)}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export function ScoreboardChart() {
  return <MitreSparkline rows={data.rows} />;
}

export default function Scoreboard() {
  const rows = [...data.rows].sort((a, b) => b.date.localeCompare(a.date));
  return (
    <div className={styles.scoreboard}>
      <ScoreboardChart />
      <ScoreboardTable rows={rows} />
    </div>
  );
}
