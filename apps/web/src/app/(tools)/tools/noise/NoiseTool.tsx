"use client";

import { useMemo, useState } from "react";

import { projectNoise } from "../../../../lib/tools/noise";

export function NoiseTool() {
  const [alertsPerDay, setAlertsPerDay] = useState(2000);
  const [fpRate, setFpRate] = useState(90);
  const [minutesPerAlert, setMinutesPerAlert] = useState(8);
  const [hourlyCost, setHourlyCost] = useState(75);

  const projection = useMemo(
    () =>
      projectNoise({
        alertsPerDay,
        falsePositiveRate: fpRate / 100,
        minutesPerAlert,
        analystHourlyCost: hourlyCost,
      }),
    [alertsPerDay, fpRate, minutesPerAlert, hourlyCost],
  );

  return (
    <div style={{ display: "grid", gap: 24 }}>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 16 }}>
        <Field label="Alerts per day" value={alertsPerDay} onChange={setAlertsPerDay} min={0} step={100} />
        <Field label="False-positive rate (%)" value={fpRate} onChange={setFpRate} min={0} max={100} step={1} />
        <Field label="Minutes to triage one alert" value={minutesPerAlert} onChange={setMinutesPerAlert} min={1} step={1} />
        <Field label="Analyst cost ($/hour)" value={hourlyCost} onChange={setHourlyCost} min={0} step={5} />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 16 }}>
        <Stat value={`${projection.noisePercent}%`} label="of all alerts auto-suppressed" color="#22c55e" />
        <Stat value={projection.suppressedPerMonth.toLocaleString()} label="alerts suppressed / month" color="#e6e9f5" />
        <Stat value={`${projection.hoursSavedPerMonth.toLocaleString()}h`} label="analyst hours saved / month" color="#e6e9f5" />
        {projection.costSavedPerMonth !== undefined ? (
          <Stat value={`$${projection.costSavedPerMonth.toLocaleString()}`} label="cost saved / month" color="#22c55e" />
        ) : null}
      </div>

      <p style={{ color: "#6b7394", fontSize: 12, margin: 0 }}>
        Uses the AiSOC verdict engine&apos;s published deterministic-tier suppression rate (85.5%). This is a substrate
        self-consistency figure, not a claim about live-LLM accuracy — see the{" "}
        <a href="https://github.com/beenuar/AiSOC/blob/main/apps/docs/docs/benchmark.md" style={{ color: "#8b93b7" }}>
          benchmark methodology
        </a>
        . Estimates only; your mileage varies with tuning and alert mix.
      </p>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  min,
  max,
  step,
}: {
  label: string;
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
  step?: number;
}) {
  return (
    <label style={{ display: "grid", gap: 6 }}>
      <span style={{ color: "#8b93b7", fontSize: 13 }}>{label}</span>
      <input
        type="number"
        value={value}
        min={min}
        max={max}
        step={step}
        onChange={(e) => onChange(Number(e.target.value))}
        style={{ background: "#0b1020", color: "#e6e9f5", border: "1px solid #232b4d", borderRadius: 8, padding: "10px 12px", fontSize: 15 }}
      />
    </label>
  );
}

function Stat({ value, label, color }: { value: string; label: string; color: string }) {
  return (
    <div style={{ background: "#131a33", border: "1px solid #232b4d", borderRadius: 12, padding: 20 }}>
      <div style={{ fontSize: 34, fontWeight: 800, color }}>{value}</div>
      <div style={{ color: "#8b93b7", fontSize: 13, marginTop: 4 }}>{label}</div>
    </div>
  );
}
