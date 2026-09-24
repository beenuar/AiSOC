/**
 * @aisoc/report-card — dependency-free share-card renderer.
 *
 * One visual language for every shareable AiSOC artifact:
 *   - `triage`   — the `aisoc triage --share` card and the noise-tuning
 *                  dashboard's "share results" button.
 *   - `coverage` — an ATT&CK coverage grade (A–F) for the /tools/coverage grader.
 *   - `replay`   — an investigation-replay verdict card for `/r/<slug>` unfurls.
 *
 * Outputs a standalone 1200×630 SVG (X/LinkedIn/Slack unfurl ratio) and a
 * Markdown block. All aggregate/taxonomy data only — never customer PII.
 */

export type ReportCardData =
  | {
      kind: "triage";
      total: number;
      escalate: number;
      review: number;
      suppress: number;
      noisePercent: number;
      elapsedSeconds: number;
      deterministic: boolean;
    }
  | {
      kind: "coverage";
      grade: string;
      covered: number;
      total: number;
      percent: number;
      topUncovered?: string[];
    }
  | {
      kind: "replay";
      caseTitle: string;
      verdict: string;
      techniques: string[];
      elapsedSeconds: number;
      stepCount: number;
      toolCalls: number;
    };

const BRAND = "#7b2bbe";
const FG = "#e6e9f5";
const MUTED = "#8b93b7";
const GREEN = "#22c55e";
const RED = "#f87171";
const AMBER = "#fbbf24";

const FONT = "ui-sans-serif,system-ui,Segoe UI,Roboto,Arial";
const MONO = "ui-monospace,SFMono-Regular,Menlo,monospace";

export function esc(s: string): string {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function frame(inner: string): string {
  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630" role="img" aria-label="AiSOC report card">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#0b1020"/>
      <stop offset="1" stop-color="#131a33"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>
  <rect x="0" y="0" width="1200" height="8" fill="${BRAND}"/>
${inner}
  <text x="64" y="590" fill="#6b7394" font-family="${MONO}" font-size="22">github.com/beenuar/AiSOC</text>
</svg>
`;
}

function stat(x: number, value: string, label: string, color: string): string {
  return `    <text x="${x}" y="470" fill="${color}" font-family="${FONT}" font-size="30" font-weight="700">${esc(value)}</text>
    <text x="${x}" y="506" fill="${MUTED}" font-family="${FONT}" font-size="22">${esc(label)}</text>`;
}

function gradeColor(grade: string): string {
  const g = grade.toUpperCase()[0] ?? "F";
  if (g === "A" || g === "B") return GREEN;
  if (g === "C" || g === "D") return AMBER;
  return RED;
}

export function renderCardSvg(data: ReportCardData): string {
  switch (data.kind) {
    case "triage": {
      const inner = `  <text x="64" y="96" fill="${FG}" font-family="${FONT}" font-size="34" font-weight="700">AiSOC · alert triage</text>
  <text x="64" y="150" fill="${MUTED}" font-family="${FONT}" font-size="24">${esc(
        data.deterministic ? "deterministic verdict engine · no LLM key" : "LLM-assisted verdict engine",
      )}</text>
  <text x="64" y="300" fill="${GREEN}" font-family="${FONT}" font-size="150" font-weight="800">${data.noisePercent}%</text>
  <text x="64" y="356" fill="${MUTED}" font-family="${FONT}" font-size="28">of alert noise suppressed</text>
${stat(64, String(data.total), "triaged", FG)}
${stat(320, String(data.escalate), "escalate", RED)}
${stat(560, String(data.review), "review", AMBER)}
${stat(800, String(data.suppress), "suppressed", MUTED)}
${stat(1040, `${data.elapsedSeconds.toFixed(1)}s`, "elapsed", FG)}`;
      return frame(inner);
    }
    case "coverage": {
      const inner = `  <text x="64" y="96" fill="${FG}" font-family="${FONT}" font-size="34" font-weight="700">AiSOC · ATT&amp;CK coverage grade</text>
  <text x="64" y="290" fill="${gradeColor(data.grade)}" font-family="${FONT}" font-size="200" font-weight="800">${esc(
        data.grade,
      )}</text>
  <text x="420" y="230" fill="${FG}" font-family="${FONT}" font-size="60" font-weight="700">${data.percent}%</text>
  <text x="420" y="280" fill="${MUTED}" font-family="${FONT}" font-size="26">${data.covered} / ${data.total} techniques covered</text>
${stat(64, String(data.covered), "covered", GREEN)}
${stat(320, String(data.total - data.covered), "uncovered", RED)}
${stat(560, `${data.percent}%`, "coverage", FG)}`;
      return frame(inner);
    }
    case "replay": {
      const verdictColor = /true|confirmed|incident|positive/i.test(data.verdict) ? RED : GREEN;
      const inner = `  <text x="64" y="96" fill="${FG}" font-family="${FONT}" font-size="34" font-weight="700">AiSOC · investigation replay</text>
  <text x="64" y="170" fill="${MUTED}" font-family="${FONT}" font-size="26">${esc(data.caseTitle.slice(0, 60))}</text>
  <text x="64" y="300" fill="${verdictColor}" font-family="${FONT}" font-size="72" font-weight="800">${esc(
        data.verdict.replace(/_/g, " ").toUpperCase(),
      )}</text>
  <text x="64" y="356" fill="${MUTED}" font-family="${FONT}" font-size="24">${esc(
        data.techniques.slice(0, 6).join("  ·  ") || "no techniques",
      )}</text>
${stat(64, `${data.elapsedSeconds.toFixed(0)}s`, "to verdict", FG)}
${stat(320, String(data.stepCount), "steps", FG)}
${stat(560, String(data.toolCalls), "tool calls", FG)}`;
      return frame(inner);
    }
    default: {
      const _never: never = data;
      return _never;
    }
  }
}

export function renderCardMarkdown(data: ReportCardData): string {
  switch (data.kind) {
    case "triage":
      return [
        "## AiSOC triage report card",
        "",
        `- **${data.total}** alerts triaged`,
        `- **${data.noisePercent}%** noise suppressed`,
        `- **${data.escalate}** escalate · **${data.review}** review · **${data.suppress}** suppressed`,
        `- **${data.elapsedSeconds.toFixed(1)}s** elapsed (${data.deterministic ? "deterministic, no LLM" : "LLM-assisted"})`,
        "",
        "Reproduce: `npx aisoc triage --demo` · https://github.com/beenuar/AiSOC",
      ].join("\n");
    case "coverage":
      return [
        "## AiSOC ATT&CK coverage grade",
        "",
        `- Grade: **${data.grade}**`,
        `- Covered: **${data.covered} / ${data.total}** techniques (**${data.percent}%**)`,
        ...(data.topUncovered?.length ? [`- Top uncovered: ${data.topUncovered.slice(0, 10).join(", ")}`] : []),
        "",
        "Grade yours: open `/tools/coverage` in your AiSOC console · https://github.com/beenuar/AiSOC",
      ].join("\n");
    case "replay":
      return [
        `## AiSOC investigation replay — ${data.caseTitle}`,
        "",
        `- Verdict: **${data.verdict}**`,
        `- To verdict: **${data.elapsedSeconds.toFixed(0)}s**, ${data.stepCount} steps, ${data.toolCalls} tool calls`,
        ...(data.techniques.length ? [`- Techniques: ${data.techniques.slice(0, 12).join(", ")}`] : []),
      ].join("\n");
    default: {
      const _never: never = data;
      return _never;
    }
  }
}

/** Coverage grade helper shared by the grader tool + card. */
export function coverageGrade(percent: number): string {
  if (percent >= 90) return "A";
  if (percent >= 75) return "B";
  if (percent >= 60) return "C";
  if (percent >= 40) return "D";
  return "F";
}
