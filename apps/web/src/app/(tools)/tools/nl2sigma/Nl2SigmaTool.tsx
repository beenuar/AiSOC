"use client";

import { useMemo, useState } from "react";

import { nlToSigma } from "../../../../lib/tools/nl2sigma";
import { translateRule } from "../../../../lib/tools/translate";

const SAMPLE = "Detect powershell.exe launching with a download cradle (DownloadString or IEX), MITRE T1059.001";

export function Nl2SigmaTool() {
  const [text, setText] = useState(SAMPLE);
  const [severity, setSeverity] = useState("medium");
  const [copied, setCopied] = useState<string | null>(null);

  const result = useMemo(() => nlToSigma(text, severity), [text, severity]);
  const dialects = useMemo(() => translateRule(result.sigma, "sigma", ["spl", "kql", "esql"]), [result.sigma]);

  const copy = async (key: string, value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard blocked */
    }
  };

  return (
    <div style={{ display: "grid", gap: 18 }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <label style={{ color: "#8b93b7", fontSize: 14 }}>Severity</label>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} style={select}>
          {["informational", "low", "medium", "high", "critical"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
      </div>
      <textarea
        value={text}
        onChange={(e) => setText(e.target.value)}
        rows={4}
        placeholder="Describe the behaviour to detect, in plain English…"
        style={textarea}
      />

      <Block title="Sigma" body={result.sigma} copied={copied === "sigma"} onCopy={() => copy("sigma", result.sigma)} />
      {dialects.results.map((r) => (
        <Block key={r.format} title={r.label} body={r.rule} copied={copied === r.format} onCopy={() => copy(r.format, r.rule)} />
      ))}

      <p style={{ color: "#fbbf24", fontSize: 13, margin: 0 }}>⚠ {result.note}</p>
    </div>
  );
}

function Block({ title, body, copied, onCopy }: { title: string; body: string; copied: boolean; onCopy: () => void }) {
  return (
    <div style={{ background: "#131a33", border: "1px solid #232b4d", borderRadius: 10, overflow: "hidden" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", borderBottom: "1px solid #232b4d" }}>
        <strong style={{ color: "#7b2bbe", fontSize: 14 }}>{title}</strong>
        <button onClick={onCopy} style={btn}>
          {copied ? "Copied ✓" : "Copy"}
        </button>
      </div>
      <pre style={{ margin: 0, padding: 14, color: "#c4cae0", fontSize: 13, overflowX: "auto", whiteSpace: "pre-wrap" }}>{body}</pre>
    </div>
  );
}

const btn: React.CSSProperties = { background: "#232b4d", color: "#e6e9f5", border: "none", borderRadius: 6, padding: "6px 12px", fontSize: 13, cursor: "pointer" };
const select: React.CSSProperties = { background: "#131a33", color: "#e6e9f5", border: "1px solid #232b4d", borderRadius: 8, padding: "8px 10px" };
const textarea: React.CSSProperties = {
  width: "100%",
  background: "#0b1020",
  color: "#c4cae0",
  border: "1px solid #232b4d",
  borderRadius: 10,
  padding: 14,
  fontSize: 14,
  resize: "vertical",
};
