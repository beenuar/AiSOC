/**
 * Fetch the repository's own security signals and normalize them into the
 * `aisoc` verdict engine's `Alert` shape.
 *
 * Handles Dependabot, code scanning (CodeQL), and secret scanning. Each source
 * degrades gracefully: if the feature is disabled or the token lacks the scope
 * (403/404), we skip it with a note instead of failing the whole run.
 */

import type { Alert, Severity } from "./_vendor/verdict/index.js";

// Minimal client surface we depend on (paginate over a REST path).
export interface OctokitLike {
  paginate: (path: string) => Promise<unknown[]>;
}

export interface FetchResult {
  alerts: Alert[];
  notes: string[];
  /**
   * Which declared sources were actually read, and which were not.
   *
   * `safe()` turns a 403/404 into a note and an empty array, which makes a
   * source nobody could read indistinguishable from a source that was read
   * and found clean — and downstream, zero findings grades as A/100. Callers
   * need the two apart to avoid publishing an all-clear they did not earn, so
   * the split is part of the result rather than something a reader has to
   * recover by pattern-matching the prose in `notes`.
   */
  scanned: string[];
  skipped: string[];
}

function sev(value: string | undefined): Severity {
  switch ((value ?? "").toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
    case "error":
      return "high";
    case "medium":
    case "moderate":
    case "warning":
      return "medium";
    case "low":
    case "note":
      return "low";
    default:
      return "info";
  }
}

function risk(severity: Severity): number {
  return { critical: 0.95, high: 0.8, medium: 0.5, low: 0.25, info: 0.1 }[severity];
}

/** Dependabot alert → Alert. Runtime-scope + patched-version-exists raises priority. */
export function mapDependabot(a: Record<string, any>): Alert {
  const adv = a.security_advisory ?? {};
  const vuln = a.security_vulnerability ?? {};
  const severity = sev(adv.severity ?? vuln.severity);
  const scope = a.dependency?.scope ?? "runtime";
  const pkg = vuln.package?.name ?? a.dependency?.package?.name ?? "dependency";
  const runtime = scope === "runtime";
  // Runtime-scope vulns are reachable in production — bump risk so they escalate.
  const riskScore = Math.min(risk(severity) + (runtime ? 0.05 : -0.15), 0.99);
  const cves: string[] = (adv.identifiers ?? []).map((i: any) => i.value).filter(Boolean);
  return {
    id: `dependabot-${a.number}`,
    title: `${adv.summary ?? "Dependency vulnerability"} (${pkg})`,
    source: "dependabot",
    severity,
    riskScore,
    raw: `${adv.description ?? ""} scope=${scope} ${cves.join(" ")} ${runtime ? "exploitable in the dependency graph" : ""}`.slice(0, 800),
    timestamp: a.created_at,
  };
}

/** Code scanning (CodeQL) alert → Alert. */
export function mapCodeScanning(a: Record<string, any>): Alert {
  const rule = a.rule ?? {};
  const severity = sev(rule.security_severity_level ?? rule.severity);
  return {
    id: `code-scanning-${a.number}`,
    title: rule.description ?? rule.name ?? "Code scanning finding",
    source: "code-scanning",
    severity,
    riskScore: risk(severity),
    raw: `${a.most_recent_instance?.message?.text ?? rule.full_description ?? ""} ${(rule.tags ?? []).join(" ")}`.slice(0, 800),
    timestamp: a.created_at,
  };
}

/** Secret scanning alert → Alert. Leaked secrets are high-severity by nature. */
export function mapSecretScanning(a: Record<string, any>): Alert {
  const severity: Severity = "high";
  return {
    id: `secret-scanning-${a.number}`,
    title: `Leaked secret: ${a.secret_type_display_name ?? a.secret_type ?? "unknown"}`,
    source: "secret-scanning",
    severity,
    riskScore: 0.85,
    raw: `secret_type=${a.secret_type} validity=${a.validity ?? "unknown"} credential exposure`,
    timestamp: a.created_at,
  };
}

async function safe(
  fetchFn: () => Promise<unknown[]>,
  label: string,
  notes: string[],
  scanned: string[],
  skipped: string[],
): Promise<unknown[]> {
  try {
    const rows = await fetchFn();
    scanned.push(label);
    return rows;
  } catch (err: any) {
    const status = err?.status ?? err?.response?.status;
    if (status === 403) notes.push(`${label}: skipped (token lacks permission or the feature is not enabled).`);
    else if (status === 404) notes.push(`${label}: skipped (not enabled for this repository).`);
    else notes.push(`${label}: skipped (${err?.message ?? "error"}).`);
    skipped.push(label);
    return [];
  }
}

export async function fetchAlerts(
  client: OctokitLike,
  owner: string,
  repo: string,
  sources: string[],
): Promise<FetchResult> {
  const alerts: Alert[] = [];
  const notes: string[] = [];
  const scanned: string[] = [];
  const skipped: string[] = [];
  const q = "?state=open";

  if (sources.includes("dependabot")) {
    const rows = await safe(
      () => client.paginate(`/repos/${owner}/${repo}/dependabot/alerts${q}`),
      "Dependabot",
      notes,
      scanned,
      skipped,
    );
    alerts.push(...rows.map((r) => mapDependabot(r as Record<string, any>)));
  }
  if (sources.includes("code-scanning")) {
    const rows = await safe(
      () => client.paginate(`/repos/${owner}/${repo}/code-scanning/alerts${q}`),
      "Code scanning",
      notes,
      scanned,
      skipped,
    );
    alerts.push(...rows.map((r) => mapCodeScanning(r as Record<string, any>)));
  }
  if (sources.includes("secret-scanning")) {
    const rows = await safe(
      () => client.paginate(`/repos/${owner}/${repo}/secret-scanning/alerts${q}`),
      "Secret scanning",
      notes,
      scanned,
      skipped,
    );
    alerts.push(...rows.map((r) => mapSecretScanning(r as Record<string, any>)));
  }
  return { alerts, notes, scanned, skipped };
}
