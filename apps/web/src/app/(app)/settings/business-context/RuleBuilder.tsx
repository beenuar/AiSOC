"use client";

/**
 * Business Context — Rule Builder side-panel.
 *
 * Helper UI for analysts who don't want to write raw YAML. Collects a
 * single rule (id, description, priority, one ``when`` predicate, one
 * ``then`` action) and emits the YAML snippet via ``onAppend`` so the
 * parent component can drop it into the Monaco editor.
 *
 * The Monaco editor stays the source of truth — this panel only ever
 * *appends*, never edits, the YAML document. Analysts who outgrow it
 * (multi-clause ``all:`` / ``any:`` predicates etc.) can keep working
 * directly in the editor.
 */
import { useState } from "react";

const FIELD_SUGGESTIONS = [
  "alert.target.tag",
  "alert.target.environment",
  "alert.severity",
  "alert.source",
  "alert.entity.user",
  "alert.entity.host",
  "alert.time.is_business_hours",
  "alert.mitre.technique",
];

const OPS: { value: string; label: string }[] = [
  { value: "eq", label: "equals" },
  { value: "neq", label: "not equals" },
  { value: "in", label: "is one of" },
  { value: "contains", label: "contains" },
  { value: "gte", label: ">=" },
  { value: "lte", label: "<=" },
];

const SEVERITIES = ["info", "low", "medium", "high", "critical"];

interface RuleBuilderProps {
  onAppend: (snippet: string) => void;
}

export function RuleBuilder({ onAppend }: RuleBuilderProps) {
  const [ruleId, setRuleId] = useState("");
  const [description, setDescription] = useState("");
  const [priority, setPriority] = useState(100);
  const [field, setField] = useState(FIELD_SUGGESTIONS[0]);
  const [op, setOp] = useState("eq");
  const [value, setValue] = useState("");
  const [setSeverity, setSetSeverity] = useState("");
  const [routeTo, setRouteTo] = useState("");
  const [tag, setTag] = useState("");
  const [suppress, setSuppress] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const canSubmit =
    ruleId.trim().length > 0 &&
    value.trim().length > 0 &&
    (setSeverity || routeTo || tag || suppress);

  const buildSnippet = (): string => {
    // Try to coerce numeric / boolean literals so the generated YAML doesn't
    // unintentionally quote them. Multi-value `in` operator splits on commas.
    let parsedValue: string;
    if (op === "in") {
      const items = value
        .split(",")
        .map((v) => v.trim())
        .filter(Boolean);
      parsedValue = `[${items.map(formatScalar).join(", ")}]`;
    } else {
      parsedValue = formatScalar(value.trim());
    }

    const indent = "  ";
    const lines = [
      `${indent}- id: ${yamlSafe(ruleId.trim())}`,
    ];
    if (description.trim()) {
      lines.push(`${indent}  description: ${yamlSafe(description.trim())}`);
    }
    lines.push(`${indent}  priority: ${priority}`);
    lines.push(`${indent}  when:`);
    lines.push(`${indent}    field: ${field}`);
    lines.push(`${indent}    op: ${op}`);
    lines.push(`${indent}    value: ${parsedValue}`);
    lines.push(`${indent}  then:`);
    if (setSeverity) {
      lines.push(`${indent}    set_severity: ${setSeverity}`);
    }
    if (routeTo.trim()) {
      lines.push(`${indent}    route_to: ${yamlSafe(routeTo.trim())}`);
    }
    if (tag.trim()) {
      lines.push(`${indent}    tag: ${yamlSafe(tag.trim())}`);
    }
    if (suppress) {
      lines.push(`${indent}    suppress: true`);
    }
    return lines.join("\n");
  };

  const handleAppend = () => {
    setError(null);
    if (!canSubmit) {
      setError(
        "Need at least an id, a value, and one action (severity / route / tag / suppress).",
      );
      return;
    }
    onAppend(buildSnippet());
    // Reset just the differentiators so the analyst can stamp out a
    // similar rule quickly without re-typing the predicate scaffold.
    setRuleId("");
    setDescription("");
    setValue("");
  };

  return (
    <div className="flex flex-col gap-3 text-sm text-slate-200">
      <Field label="Rule ID">
        <input
          type="text"
          value={ruleId}
          onChange={(e) => setRuleId(e.target.value)}
          placeholder="prod-iam-business-hours"
          className={inputCls}
        />
      </Field>
      <Field label="Description">
        <input
          type="text"
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          placeholder="Wake tier-2 for prod IAM during business hours"
          className={inputCls}
        />
      </Field>
      <Field label="Priority (lower = earlier)">
        <input
          type="number"
          value={priority}
          onChange={(e) => setPriority(Number(e.target.value) || 100)}
          min={1}
          max={1000}
          className={inputCls}
        />
      </Field>

      <fieldset className="rounded border border-slate-700 p-2">
        <legend className="px-1 text-xs uppercase tracking-wide text-slate-500">
          when
        </legend>
        <div className="flex flex-col gap-2">
          <Field label="Field">
            <input
              type="text"
              list="rule-field-suggestions"
              value={field}
              onChange={(e) => setField(e.target.value)}
              className={inputCls}
            />
            <datalist id="rule-field-suggestions">
              {FIELD_SUGGESTIONS.map((f) => (
                <option key={f} value={f} />
              ))}
            </datalist>
          </Field>
          <Field label="Operator">
            <select
              value={op}
              onChange={(e) => setOp(e.target.value)}
              className={inputCls}
            >
              {OPS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </Field>
          <Field
            label={op === "in" ? "Value (comma-separated)" : "Value"}
          >
            <input
              type="text"
              value={value}
              onChange={(e) => setValue(e.target.value)}
              placeholder={op === "in" ? "prod, staging" : "prod"}
              className={inputCls}
            />
          </Field>
        </div>
      </fieldset>

      <fieldset className="rounded border border-slate-700 p-2">
        <legend className="px-1 text-xs uppercase tracking-wide text-slate-500">
          then
        </legend>
        <div className="flex flex-col gap-2">
          <Field label="Set severity">
            <select
              value={setSeverity}
              onChange={(e) => setSetSeverity(e.target.value)}
              className={inputCls}
            >
              <option value="">— unchanged —</option>
              {SEVERITIES.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </Field>
          <Field label="Route to">
            <input
              type="text"
              value={routeTo}
              onChange={(e) => setRouteTo(e.target.value)}
              placeholder="tier2"
              className={inputCls}
            />
          </Field>
          <Field label="Tag">
            <input
              type="text"
              value={tag}
              onChange={(e) => setTag(e.target.value)}
              placeholder="business-hours-prod"
              className={inputCls}
            />
          </Field>
          <label className="flex items-center gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={suppress}
              onChange={(e) => setSuppress(e.target.checked)}
            />
            Suppress matching alerts
          </label>
        </div>
      </fieldset>

      {error ? (
        <div className="rounded border border-rose-500/40 bg-rose-950/40 p-2 text-xs text-rose-200">
          {error}
        </div>
      ) : null}

      <button
        type="button"
        onClick={handleAppend}
        disabled={!canSubmit}
        className="mt-1 rounded-md bg-indigo-600 px-3 py-2 text-sm font-medium text-white shadow-sm hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60"
      >
        Append rule to editor
      </button>
      <p className="text-xs text-slate-500">
        The snippet is appended verbatim. Use the editor to tweak it after.
      </p>
    </div>
  );
}

interface FieldProps {
  label: string;
  children: React.ReactNode;
}

function Field({ label, children }: FieldProps) {
  return (
    <label className="flex flex-col gap-1 text-xs uppercase tracking-wide text-slate-500">
      <span>{label}</span>
      {children}
    </label>
  );
}

const inputCls =
  "rounded border border-slate-700 bg-slate-900 px-2 py-1 text-sm text-slate-100 normal-case tracking-normal focus:border-indigo-500 focus:outline-none";

/**
 * Quote a YAML scalar only when needed (contains special chars or whitespace).
 * Numbers / booleans / safe identifiers are emitted bare so the YAML stays
 * idiomatic.
 */
function formatScalar(raw: string): string {
  if (raw === "true" || raw === "false" || raw === "null") return raw;
  if (/^-?\d+(\.\d+)?$/.test(raw)) return raw;
  if (/^[A-Za-z0-9_\-./]+$/.test(raw)) return raw;
  return JSON.stringify(raw);
}

function yamlSafe(raw: string): string {
  // Identifiers / paths / single words go through bare; anything else gets
  // JSON-quoted so YAML parsers see an unambiguous string.
  return formatScalar(raw);
}
