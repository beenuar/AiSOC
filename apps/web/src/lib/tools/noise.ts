/**
 * Alert-noise calculator for `/tools/noise`.
 *
 * Projects false-positive suppression and analyst hours saved from anonymized
 * alert-volume stats, using the AiSOC verdict-engine's published operating
 * point. The precision/recall here are the DETERMINISTIC-tier figures reported
 * on the benchmark page — documented and linked on the tool page so the maths
 * is auditable, never a fabricated marketing number.
 */

// Deterministic-tier operating point (see apps/docs/docs/benchmark.md). These
// are the substrate self-consistency figures, not a claim about live-LLM
// accuracy — the tool page states this explicitly.
export const DEFAULT_SUPPRESSION_RATE = 0.855; // share of benign noise auto-suppressed
export const DEFAULT_MINUTES_PER_ALERT = 8; // industry-typical manual triage time

export interface NoiseInput {
  alertsPerDay: number;
  /** Fraction of alerts that are false positives (0–1). Default 0.9. */
  falsePositiveRate?: number;
  minutesPerAlert?: number;
  /** Fully-loaded analyst hourly cost, USD. Optional. */
  analystHourlyCost?: number;
  suppressionRate?: number;
}

export interface NoiseProjection {
  alertsPerDay: number;
  falsePositives: number;
  suppressedPerDay: number;
  suppressedPerMonth: number;
  hoursSavedPerDay: number;
  hoursSavedPerMonth: number;
  costSavedPerMonth?: number;
  noisePercent: number;
}

function clampFraction(v: number, fallback: number): number {
  if (!Number.isFinite(v) || v < 0 || v > 1) return fallback;
  return v;
}

export function projectNoise(input: NoiseInput): NoiseProjection {
  const alertsPerDay = Math.max(0, Math.floor(input.alertsPerDay || 0));
  const fpRate = clampFraction(input.falsePositiveRate ?? 0.9, 0.9);
  const suppressionRate = clampFraction(input.suppressionRate ?? DEFAULT_SUPPRESSION_RATE, DEFAULT_SUPPRESSION_RATE);
  const minutesPerAlert = input.minutesPerAlert && input.minutesPerAlert > 0 ? input.minutesPerAlert : DEFAULT_MINUTES_PER_ALERT;

  const falsePositives = alertsPerDay * fpRate;
  const suppressedPerDay = falsePositives * suppressionRate;
  const suppressedPerMonth = suppressedPerDay * 30;
  const hoursSavedPerDay = (suppressedPerDay * minutesPerAlert) / 60;
  const hoursSavedPerMonth = hoursSavedPerDay * 30;
  const noisePercent = alertsPerDay > 0 ? Number(((suppressedPerDay / alertsPerDay) * 100).toFixed(1)) : 0;

  const projection: NoiseProjection = {
    alertsPerDay,
    falsePositives: Math.round(falsePositives),
    suppressedPerDay: Math.round(suppressedPerDay),
    suppressedPerMonth: Math.round(suppressedPerMonth),
    hoursSavedPerDay: Number(hoursSavedPerDay.toFixed(1)),
    hoursSavedPerMonth: Number(hoursSavedPerMonth.toFixed(0)),
    noisePercent,
  };
  if (input.analystHourlyCost && input.analystHourlyCost > 0) {
    projection.costSavedPerMonth = Math.round(hoursSavedPerMonth * input.analystHourlyCost);
  }
  return projection;
}
