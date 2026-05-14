/**
 * Business Context settings — typed fetch client.
 *
 * Mirrors the wire types exposed by
 * `services/api/app/api/v1/endpoints/business_context.py`. We talk to the
 * API directly via ``fetch`` (rather than going through the global typed
 * client in ``apps/web/src/lib/api.ts``) so this whole feature stays
 * self-contained in one directory and can be reasoned about without
 * crossing the rest of the bundle.
 */

const TENANT_ID =
  process.env.NEXT_PUBLIC_TENANT_ID ||
  "00000000-0000-0000-0000-000000000001";

/**
 * Same-origin by default so Next.js rewrites can proxy to the API gateway.
 * Honour ``NEXT_PUBLIC_API_URL`` if set so this works in local debugging
 * configurations that bypass the proxy.
 */
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "";

// ---------------------------------------------------------------------------
// Wire types — kept in sync with the FastAPI response_model classes.
// ---------------------------------------------------------------------------

export interface RuleConditionWire {
  field?: string | null;
  op?: string | null;
  value?: unknown;
  logical?: string | null;
  children?: RuleConditionWire[];
}

export interface RuleActionWire {
  set_severity?: string | null;
  route_to?: string | null;
  tag?: string | null;
  suppress?: boolean;
}

export interface RuleWire {
  id: string;
  description: string;
  enabled: boolean;
  priority: number;
  when: RuleConditionWire;
  then: RuleActionWire;
}

export interface RulesEnvelope {
  tenant_id: string;
  version: number;
  yaml: string;
  rules: RuleWire[];
  enabled: boolean;
  updated_at: string;
}

export interface PreviewRow {
  alert_id: string;
  matched_rule_ids: string[];
  before: Record<string, unknown>;
  after: Record<string, unknown>;
  suppressed: boolean;
  changed: boolean;
}

export interface PreviewResponse {
  sample_size: number;
  changed_count: number;
  suppressed_count: number;
  elapsed_ms: number;
  rows: PreviewRow[];
}

// ---------------------------------------------------------------------------
// Fetch helpers
// ---------------------------------------------------------------------------

function authHeaders(): HeadersInit {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Tenant-Id": TENANT_ID,
  };
  // Passkey/Bearer for the mobile responder bundle. Same pattern as
  // apps/web/src/lib/api.ts — additive only; the desktop console relies
  // on cookies set by the API gateway.
  if (typeof window !== "undefined") {
    try {
      const token = window.localStorage.getItem(
        "aisoc.responder.accessToken",
      );
      if (token) headers.Authorization = `Bearer ${token}`;
    } catch {
      // localStorage may be unavailable (private mode); fall through.
    }
  }
  return headers;
}

async function asJson<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new Error(
      `HTTP ${resp.status} ${resp.statusText}${body ? ` — ${body}` : ""}`,
    );
  }
  return (await resp.json()) as T;
}

/** ``GET /api/v1/business-context/rules`` — load the saved rule set. */
export async function loadRules(): Promise<RulesEnvelope> {
  const resp = await fetch(`${API_BASE}/api/v1/business-context/rules`, {
    method: "GET",
    headers: authHeaders(),
    credentials: "include",
  });
  return asJson<RulesEnvelope>(resp);
}

/** ``POST /api/v1/business-context/rules`` — replace the whole rule set. */
export async function saveRules(yaml: string): Promise<RulesEnvelope> {
  const resp = await fetch(`${API_BASE}/api/v1/business-context/rules`, {
    method: "POST",
    headers: authHeaders(),
    credentials: "include",
    body: JSON.stringify({ yaml }),
  });
  return asJson<RulesEnvelope>(resp);
}

/** ``POST /api/v1/business-context/rules/preview`` — dry-run the YAML. */
export async function previewRules(
  yaml: string,
  alerts: Record<string, unknown>[] = [],
): Promise<PreviewResponse> {
  const resp = await fetch(
    `${API_BASE}/api/v1/business-context/rules/preview`,
    {
      method: "POST",
      headers: authHeaders(),
      credentials: "include",
      body: JSON.stringify({ yaml, alerts }),
    },
  );
  return asJson<PreviewResponse>(resp);
}
