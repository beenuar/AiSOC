"use client";

import { useEffect, useMemo, useState } from "react";

import {
  ALL_FORMATS,
  FORMAT_LABELS,
  translateRule,
  encodePermalink,
  decodePermalink,
  type DetectionFormat,
} from "../../../../lib/tools/translate";

const SAMPLE = `title: Suspicious PowerShell download cradle
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\\\powershell.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'IEX'
  condition: selection`;

export function TranslateTool({ initialRule, initialFormat }: { initialRule?: string; initialFormat?: DetectionFormat }) {
  const [source, setSource] = useState<DetectionFormat>(initialFormat ?? "sigma");
  const [rule, setRule] = useState(initialRule ?? SAMPLE);
  const [copied, setCopied] = useState<string | null>(null);

  // Hydrate from a ?s=<permalink> on first load (client-only).
  useEffect(() => {
    if (initialRule) return;
    const params = new URLSearchParams(window.location.search);
    const s = params.get("s");
    if (s) {
      const decoded = decodePermalink(s);
      if (decoded) {
        setSource(decoded.sourceFormat);
        setRule(decoded.rule);
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const output = useMemo(() => translateRule(rule, source, ALL_FORMATS.filter((f) => f !== source)), [rule, source]);

  const permalink = useMemo(() => {
    if (typeof window === "undefined") return "";
    return `${window.location.origin}/tools/translate?s=${encodePermalink(source, rule)}`;
  }, [source, rule]);

  const copy = async (key: string, text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(key);
      setTimeout(() => setCopied(null), 1500);
    } catch {
      /* clipboard blocked; no-op */
    }
  };

  return (
    <div style={{ display: "grid", gap: 20 }}>
      <div style={{ display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
        <label style={{ color: "#8b93b7", fontSize: 14 }}>Source format</label>
        <select
          value={source}
          onChange={(e) => setSource(e.target.value as DetectionFormat)}
          style={{ background: "#131a33", color: "#e6e9f5", border: "1px solid #232b4d", borderRadius: 8, padding: "8px 10px" }}
        >
          {ALL_FORMATS.map((f) => (
            <option key={f} value={f}>
              {FORMAT_LABELS[f]}
            </option>
          ))}
        </select>
        <button onClick={() => copy("permalink", permalink)} style={btn}>
          {copied === "permalink" ? "Copied link ✓" : "Copy permalink"}
        </button>
      </div>

      <textarea
        value={rule}
        onChange={(e) => setRule(e.target.value)}
        spellCheck={false}
        rows={12}
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

      <div style={{ display: "grid", gap: 14 }}>
        {output.results.map((r) => (
          <div key={r.format} style={{ background: "#131a33", border: "1px solid #232b4d", borderRadius: 10, overflow: "hidden" }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", padding: "8px 12px", borderBottom: "1px solid #232b4d" }}>
              <strong style={{ color: "#7b2bbe", fontSize: 14 }}>{r.label}</strong>
              <button onClick={() => copy(r.format, r.rule)} style={btn}>
                {copied === r.format ? "Copied ✓" : "Copy"}
              </button>
            </div>
            <pre style={{ margin: 0, padding: 14, color: "#c4cae0", fontSize: 13, overflowX: "auto", whiteSpace: "pre-wrap" }}>{r.rule}</pre>
          </div>
        ))}
      </div>

      {output.warnings.map((w) => (
        <p key={w} style={{ color: "#fbbf24", fontSize: 13, margin: 0 }}>
          ⚠ {w}
        </p>
      ))}
    </div>
  );
}

const btn: React.CSSProperties = {
  background: "#232b4d",
  color: "#e6e9f5",
  border: "none",
  borderRadius: 6,
  padding: "6px 12px",
  fontSize: 13,
  cursor: "pointer",
};
