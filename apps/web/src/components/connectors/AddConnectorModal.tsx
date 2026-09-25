'use client';

/**
 * Click-and-connect wizard for adding a new connector instance.
 *
 * Two-step flow:
 *
 * 1. **Catalog picker** — fetches ``GET /api/v1/connectors/catalog`` and
 *    renders one card per registered connector class, grouped by category.
 *    The catalog is the source of truth for which connectors this build
 *    supports; we never ship a hardcoded list in the frontend.
 *
 * 2. **Schema-driven config form** — each catalog entry declares its own
 *    ``fields[]`` (see ``BaseConnector.schema()``), so this component
 *    builds the form dynamically from the selected entry. Field types map
 *    to controls:
 *      - ``string`` / ``number`` → text/number input
 *      - ``secret`` → masked password input
 *      - ``textarea`` → multi-line input (used for pasted JSON keys)
 *      - ``select`` → native ``<select>`` with provided options
 *      - ``boolean`` → checkbox
 *
 * Test-before-save lives on the second screen: it POSTs the cleartext
 * credentials to ``/api/v1/connectors/test`` (which forwards to the
 * stateless connectors microservice) without persisting anything. Only on
 * "Save" does the API encrypt the credentials in the vault and write a
 * row to Postgres.
 *
 * The modal is intentionally a single component file because the wizard
 * state machine is small (catalog → config → done) and splitting it would
 * fragment the form/state coupling for no real reuse benefit.
 */

import { Fragment, useEffect, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { clsx } from 'clsx';
import toast from 'react-hot-toast';
import {
  connectorsApi,
  oauthApi,
  ApiError,
  type Connector,
  type ConnectorCatalogEntry,
  type ConnectorLastEvent,
  type ConnectorSchemaField,
  type ConnectorTestResult,
  type OAuthAppView,
  type TroubleshootResponse,
} from '@/lib/api';

/**
 * Turn a thrown request error into something an operator can act on.
 *
 * `ApiError.message` is the status line — `API 502 Bad Gateway — /api/v1/…`.
 * Everything that identifies the fault lives in `body`, which FastAPI sends as
 * `{"detail": "…"}`. This matters most for the failure that is not the
 * customer's: when the API cannot authenticate to AiSOC's own connectors
 * service, the detail names the status, the service and the variable to set,
 * and the status line alone names none of them.
 */
function describeApiError(err: unknown, fallback: string): string {
  if (err instanceof ApiError) {
    if (err.body) {
      try {
        const parsed = JSON.parse(err.body) as { detail?: unknown };
        if (typeof parsed.detail === 'string' && parsed.detail.trim()) {
          return parsed.detail;
        }
      } catch {
        // Not JSON — a proxy error page or a truncated body. Fall through to
        // the status line, which at least names the status.
      }
    }
    return err.message;
  }
  return err instanceof Error ? err.message : fallback;
}

// ─── Field rendering helpers ────────────────────────────────────────────────

/**
 * Compute the initial form values for a catalog entry.
 *
 * Defaults from the schema flow into ``connector_config`` so the operator
 * sees them already populated. Secrets always start empty — never seed a
 * default secret, even if the schema were to declare one.
 */
function buildInitialValues(
  fields: ConnectorSchemaField[],
): Record<string, string | number | boolean> {
  const values: Record<string, string | number | boolean> = {};
  for (const f of fields) {
    if (f.type === 'secret') {
      values[f.name] = '';
      continue;
    }
    if (f.default !== undefined && f.default !== null) {
      values[f.name] = f.default as string | number | boolean;
      continue;
    }
    if (f.type === 'boolean') {
      values[f.name] = false;
      continue;
    }
    if (f.type === 'number') {
      values[f.name] = 0;
      continue;
    }
    values[f.name] = '';
  }
  return values;
}

/**
 * Split a flat values dict into ``auth_config`` (secrets) and
 * ``connector_config`` (everything else).
 *
 * The backend expects this split because secrets get encrypted and
 * non-secrets stay plaintext for poll-config readability in the UI.
 */
function partitionFormValues(
  fields: ConnectorSchemaField[],
  values: Record<string, string | number | boolean>,
): { auth_config: Record<string, unknown>; connector_config: Record<string, unknown> } {
  const auth_config: Record<string, unknown> = {};
  const connector_config: Record<string, unknown> = {};
  for (const f of fields) {
    const v = values[f.name];
    // Empty optional fields are omitted entirely so the backend doesn't
    // need to disambiguate between "operator typed empty string" and
    // "operator did not provide".
    const isEmpty = v === '' || v === null || v === undefined;
    if (isEmpty && !f.required) continue;
    if (f.type === 'secret') {
      auth_config[f.name] = v;
    } else {
      connector_config[f.name] = v;
    }
  }
  return { auth_config, connector_config };
}

interface FieldInputProps {
  field: ConnectorSchemaField;
  value: string | number | boolean;
  onChange: (next: string | number | boolean) => void;
}

function FieldInput({ field, value, onChange }: FieldInputProps) {
  const baseClass =
    'w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30 transition-colors';

  switch (field.type) {
    case 'secret':
      return (
        <input
          type="password"
          autoComplete="new-password"
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder ?? '••••••••'}
          className={clsx(baseClass, 'font-mono')}
          required={field.required}
        />
      );
    case 'textarea':
      return (
        <textarea
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          rows={6}
          className={clsx(baseClass, 'font-mono text-xs resize-y min-h-[120px]')}
          required={field.required}
        />
      );
    case 'select':
      return (
        <select
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          className={baseClass}
          required={field.required}
        >
          {!field.required && <option value="">— none —</option>}
          {(field.options ?? []).map((opt) => (
            <option key={opt.value} value={opt.value}>
              {opt.label}
            </option>
          ))}
        </select>
      );
    case 'boolean':
      return (
        <label className="flex items-center gap-2 cursor-pointer select-none">
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={(e) => onChange(e.target.checked)}
            className="h-4 w-4 rounded border-gray-700 bg-gray-900 text-blue-500 focus:ring-blue-500/30"
          />
          <span className="text-sm text-gray-300">{field.placeholder ?? 'Enabled'}</span>
        </label>
      );
    case 'number':
      return (
        <input
          type="number"
          value={typeof value === 'number' ? value : Number(value ?? 0)}
          onChange={(e) => {
            const parsed = e.target.value === '' ? 0 : Number(e.target.value);
            onChange(Number.isNaN(parsed) ? 0 : parsed);
          }}
          placeholder={field.placeholder}
          className={baseClass}
          required={field.required}
        />
      );
    case 'string':
    default:
      return (
        <input
          type="text"
          value={String(value ?? '')}
          onChange={(e) => onChange(e.target.value)}
          placeholder={field.placeholder}
          className={baseClass}
          required={field.required}
        />
      );
  }
}

// ─── Catalog grid ────────────────────────────────────────────────────────────

// Exported because the `/onboarding` landing reuses these to render its own
// hero-level category pills and "most teams pick" row outside the modal,
// and we want both surfaces to stay in lockstep.
export const CATEGORY_ORDER: string[] = [
  'edr',
  'siem',
  'cloud',
  'iam',
  'saas',
  'vcs',
  'network',
];

export const CATEGORY_LABEL: Record<string, string> = {
  edr: 'Endpoint',
  siem: 'SIEM',
  cloud: 'Cloud',
  iam: 'Identity',
  saas: 'SaaS',
  vcs: 'Source Control',
  network: 'Network',
};

/**
 * Hand-curated short-list of "most teams pick" connectors that we surface
 * at the very top of the picker. The order is intentional (highest-volume
 * pickup first) and is the same heuristic used by the /onboarding "set up
 * your first connector" CTA.
 *
 * IDs not present in the catalog are silently skipped, so dropping a
 * connector class never breaks the picker.
 */
export const MOST_TEAMS_PICK: string[] = [
  'crowdstrike',
  'sentinelone',
  'microsoft_defender',
  'okta',
  'azure_ad',
  'aws_security_hub',
  'github',
  'splunk',
  'jira',
  'servicenow',
];

function CatalogGrid({
  entries,
  onPick,
  query,
  categoryFilter,
}: {
  entries: ConnectorCatalogEntry[];
  onPick: (entry: ConnectorCatalogEntry) => void;
  query: string;
  /**
   * Optional pre-filter to a single category (e.g. "edr"). When set, only
   * entries with `e.category === categoryFilter` are shown — the curated
   * "Most teams pick" row is also suppressed because the operator has
   * already declared intent.
   */
  categoryFilter?: string | null;
}) {
  // Apply category and free-text filters in order. Category is a hard cut
  // (operator clicked "Endpoint" — they want endpoint connectors and only
  // endpoint connectors); the search is then applied on top of that.
  const filtered = useMemo(() => {
    let pool = entries;
    if (categoryFilter) {
      pool = pool.filter((e) => (e.category || 'other') === categoryFilter);
    }
    const q = query.trim().toLowerCase();
    if (!q) return pool;
    return pool.filter((e) => {
      return (
        e.connector_name.toLowerCase().includes(q) ||
        e.connector_id.toLowerCase().includes(q) ||
        (e.description ?? '').toLowerCase().includes(q) ||
        (e.category ?? '').toLowerCase().includes(q)
      );
    });
  }, [entries, query, categoryFilter]);

  const popular = useMemo(() => {
    const byId = new Map(filtered.map((e) => [e.connector_id, e]));
    return MOST_TEAMS_PICK.map((id) => byId.get(id)).filter(
      (e): e is ConnectorCatalogEntry => Boolean(e),
    );
  }, [filtered]);

  const grouped = useMemo(() => {
    const groups: Record<string, ConnectorCatalogEntry[]> = {};
    for (const e of filtered) {
      const cat = e.category || 'other';
      if (!groups[cat]) groups[cat] = [];
      groups[cat].push(e);
    }
    // Stable sort by display order, with unknown categories appended.
    const ordered = [...CATEGORY_ORDER.filter((c) => groups[c]), ...Object.keys(groups).filter((c) => !CATEGORY_ORDER.includes(c))];
    return ordered.map((c) => ({ category: c, entries: groups[c] }));
  }, [filtered]);

  if (entries.length === 0) {
    return (
      <div className="text-center text-sm text-gray-500 py-12">
        No connector types are registered in this build.
      </div>
    );
  }

  if (filtered.length === 0) {
    return (
      <div className="text-center text-sm text-gray-500 py-12">
        No connectors match <span className="text-gray-300">{query}</span>.
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Most teams pick — only when not actively searching and not
          filtered to a specific category. Suppressing the curated row
          when a category pill is active avoids duplicating cards that
          would already appear in the per-category section. */}
      {!query.trim() && !categoryFilter && popular.length > 0 && (
        <section aria-labelledby="cat-popular">
          <h3
            id="cat-popular"
            className="text-[11px] uppercase tracking-wider text-amber-300/80 font-semibold mb-2"
          >
            Most teams pick
          </h3>
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
            {popular.map((entry) => (
              <button
                key={`popular-${entry.connector_id}`}
                type="button"
                onClick={() => onPick(entry)}
                className="text-left rounded-lg border border-amber-500/20 bg-amber-500/5 hover:bg-amber-500/10 hover:border-amber-500/40 transition-colors p-4 group"
              >
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="text-sm font-medium text-gray-100 group-hover:text-white">
                    {entry.connector_name}
                  </span>
                  {entry.oauth?.supported_in_hosted && (
                    <span className="text-[10px] uppercase tracking-wider text-emerald-300/90 bg-emerald-500/10 border border-emerald-500/30 rounded px-1.5 py-0.5">
                      OAuth one-click
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-500 line-clamp-2">{entry.description}</p>
                <p className="mt-2 text-[11px] text-gray-600 font-mono">{entry.connector_id}</p>
              </button>
            ))}
          </div>
        </section>
      )}

      {grouped.map(({ category, entries: groupEntries }) => (
        <section key={category} aria-labelledby={`cat-${category}`}>
          <h3
            id={`cat-${category}`}
            className="text-[11px] uppercase tracking-wider text-gray-500 font-semibold mb-2"
          >
            {CATEGORY_LABEL[category] ?? category}
          </h3>
          <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
            {groupEntries.map((entry) => (
              <button
                key={entry.connector_id}
                type="button"
                onClick={() => onPick(entry)}
                className="text-left rounded-lg border border-gray-800/80 bg-gray-900/40 hover:bg-gray-900/80 hover:border-gray-700 transition-colors p-4 group"
              >
                <div className="flex items-start justify-between gap-2 mb-1">
                  <span className="text-sm font-medium text-gray-100 group-hover:text-white">
                    {entry.connector_name}
                  </span>
                  {entry.oauth?.supported_in_hosted && (
                    <span className="text-[10px] uppercase tracking-wider text-emerald-300/90 bg-emerald-500/10 border border-emerald-500/30 rounded px-1.5 py-0.5">
                      OAuth one-click
                    </span>
                  )}
                </div>
                <p className="text-xs text-gray-500 line-clamp-2">{entry.description}</p>
                <p className="mt-2 text-[11px] text-gray-600 font-mono">{entry.connector_id}</p>
              </button>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}

// ─── AI troubleshooter panel ─────────────────────────────────────────────────

/**
 * Inline panel rendered below the Test connection button when a test fails.
 *
 * Calls the backend ``/api/v1/connectors/troubleshoot`` LLM endpoint with
 * the connector type, the raw upstream error, and the names of the
 * auth_config keys (never the values) so the model can reason about which
 * credential is likely wrong without ever seeing a secret.
 */
function TroubleshootPanel({
  connectorId,
  testResult,
  authConfigKeys,
}: {
  connectorId: string;
  testResult: ConnectorTestResult;
  authConfigKeys: string[];
}) {
  const [loading, setLoading] = useState(false);
  const [advice, setAdvice] = useState<TroubleshootResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Reset advice whenever the upstream error text changes — a new failure
  // should not show stale suggestions from a previous run.
  const lastErrorRef = useRef<string | null>(null);
  useEffect(() => {
    const errKey = testResult.error ?? testResult.message ?? '';
    if (lastErrorRef.current !== errKey) {
      lastErrorRef.current = errKey;
      setAdvice(null);
      setError(null);
    }
  }, [testResult]);

  const handleAsk = async () => {
    setLoading(true);
    setError(null);
    setAdvice(null);
    try {
      const result = await connectorsApi.troubleshoot({
        connector_type: connectorId,
        error: testResult.error ?? testResult.message ?? 'Unknown error',
        auth_config_keys: authConfigKeys,
      });
      setAdvice(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to ask the troubleshooter');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4 mt-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-wider text-red-300">
            Connection failed
          </p>
          <p className="text-xs text-red-200/80 mt-1 break-words">
            {testResult.error ?? testResult.message ?? 'Unknown error'}
          </p>
        </div>
        {!advice && !loading && (
          <button
            type="button"
            onClick={handleAsk}
            className="text-xs whitespace-nowrap bg-red-500/20 hover:bg-red-500/30 text-red-100 border border-red-500/30 px-3 py-1.5 rounded-md transition-colors"
          >
            Ask AI to fix
          </button>
        )}
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-xs text-red-200">
          <span className="animate-spin w-3.5 h-3.5 border-2 border-red-300 border-t-transparent rounded-full" />
          Diagnosing failure…
        </div>
      )}

      {error && (
        <p className="text-xs text-red-200/80">
          Troubleshooter unavailable: {error}
        </p>
      )}

      {advice && (
        <div className="space-y-2">
          <div>
            <p className="text-[11px] uppercase tracking-wider text-gray-400 font-semibold mb-1">
              Likely cause
            </p>
            <p className="text-xs text-gray-200">{advice.likely_cause}</p>
          </div>
          <div>
            <p className="text-[11px] uppercase tracking-wider text-gray-400 font-semibold mb-1">
              Try this
            </p>
            <ol className="list-decimal list-inside space-y-1 text-xs text-gray-200 marker:text-gray-500">
              {advice.fix_steps.map((step, idx) => (
                <li key={idx}>{step}</li>
              ))}
            </ol>
          </div>
          {advice.doc_link && (
            <a
              href={advice.doc_link}
              target="_blank"
              rel="noreferrer"
              className="inline-block text-xs text-blue-400 hover:text-blue-300 underline-offset-2 hover:underline"
            >
              Open setup guide →
            </a>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Hosted OAuth panel ──────────────────────────────────────────────────────

/**
 * Hosted OAuth one-click panel, rendered above the manual fields whenever
 * the selected connector advertises ``oauth.supported_in_hosted=true`` in
 * its catalog entry.
 *
 * Three runtime states:
 *
 *   1. **Loading** — we're fetching ``GET /oauth/app/{type}`` to find out
 *      whether the tenant has already registered an OAuth client.
 *
 *   2. **Unregistered (404)** — the tenant has *not* registered a client
 *      yet. We render an inline form so an admin can paste their
 *      ``client_id`` + ``client_secret`` (and override authorize/token URLs
 *      and scopes if the schema's defaults aren't right). Submission hits
 *      ``PUT /oauth/app/{type}`` which encrypts the secret in the vault.
 *
 *   3. **Registered** — render a single "Connect with X (one-click)"
 *      button. Clicking it calls ``GET /oauth/start?response_mode=json``
 *      (authenticated XHR — we *can't* use a plain ``window.location``
 *      navigation because it would drop the JWT) and then bounces the
 *      browser to the resulting ``authorize_url``. The IdP redirects back
 *      to ``/api/v1/oauth/callback`` which writes the connector row and
 *      302s the operator to ``/onboarding?oauth_success=1`` —
 *      :func:`OnboardingView` reads those query params and surfaces a
 *      toast.
 *
 * We *also* keep the manual credential fields rendered (collapsed under a
 * disclosure) so an operator who can't get OAuth working still has a
 * fallback path. This is the same defense-in-depth approach the connector
 * schema uses by always listing field defaults even when OAuthHints is
 * present.
 */
function OAuthPanel({
  entry,
  instanceName,
}: {
  entry: ConnectorCatalogEntry;
  instanceName: string;
}) {
  const [appView, setAppView] = useState<OAuthAppView | null>(null);
  const [loadingApp, setLoadingApp] = useState(true);
  const [appLoadError, setAppLoadError] = useState<string | null>(null);
  // When the tenant clicks "Edit credentials" we expand a registration form
  // even if an app is already registered, so they can rotate the secret.
  const [showRegisterForm, setShowRegisterForm] = useState(false);
  const [connecting, setConnecting] = useState(false);

  // `entry.oauth` is already `ConnectorOAuthHints | undefined`; the
  // `OAuthAppRegisterForm` accepts the same type for `schemaHints`, so we
  // pass it through directly. Don't coerce to `null` — the prop's union
  // is `undefined`, not `null`.
  const hints = entry.oauth;

  // Reset state whenever the operator picks a different connector class —
  // otherwise stale "registered ✓" badges leak across connectors.
  useEffect(() => {
    let cancelled = false;
    setLoadingApp(true);
    setAppLoadError(null);
    setAppView(null);
    setShowRegisterForm(false);

    oauthApi
      .getApp(entry.connector_id)
      .then((view) => {
        if (cancelled) return;
        setAppView(view);
      })
      .catch((err) => {
        if (cancelled) return;
        // 404 is the "no OAuth app registered yet" path — that's the
        // expected first-time state, not an error worth surfacing.
        if (err instanceof ApiError && err.status === 404) {
          setAppView(null);
          // Auto-expand the register form when nothing is registered yet
          // so the operator's next action (paste credentials) is one
          // click away instead of two.
          setShowRegisterForm(true);
        } else {
          setAppLoadError(err instanceof Error ? err.message : 'Failed to load OAuth app');
        }
      })
      .finally(() => {
        if (!cancelled) setLoadingApp(false);
      });

    return () => {
      cancelled = true;
    };
  }, [entry.connector_id]);

  const handleConnect = async () => {
    if (connecting) return;
    setConnecting(true);
    try {
      // We MUST use the authenticated JSON variant — a raw 302 redirect
      // from the browser would drop the Bearer token and the start
      // endpoint would 401.
      const startResp = await oauthApi.startJson({
        connectorType: entry.connector_id,
        returnTo: '/onboarding',
        name: instanceName.trim() || entry.connector_name,
      });
      // Now navigate the *browser* to the IdP. The IdP's eventual
      // redirect will land at /api/v1/oauth/callback which is the only
      // OAuth endpoint that runs unauthenticated (state nonce is the
      // CSRF gate).
      window.location.href = startResp.authorize_url;
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to start OAuth flow';
      toast.error(msg);
      setConnecting(false);
    }
  };

  const refresh = async () => {
    try {
      const view = await oauthApi.getApp(entry.connector_id);
      setAppView(view);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        setAppView(null);
      }
    }
  };

  return (
    <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-[11px] uppercase tracking-wider text-emerald-300/90 font-semibold">
            One-click OAuth
          </p>
          <p className="text-sm text-gray-100 mt-1">
            Connect with {entry.connector_name} via OAuth
          </p>
          <p className="text-xs text-gray-400 mt-1 leading-relaxed">
            Recommended. We&apos;ll redirect you to {entry.connector_name} to grant access, then
            store the rotated tokens in the AiSOC vault. No long-lived secrets to paste.
          </p>
        </div>
        {appView && !showRegisterForm && (
          <span
            className="shrink-0 inline-flex items-center text-[10px] uppercase tracking-wider text-emerald-200 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded"
            title={`OAuth app last updated ${new Date(appView.updated_at).toLocaleString()}`}
          >
            App registered
          </span>
        )}
      </div>

      {loadingApp ? (
        <div className="flex items-center gap-2 text-xs text-gray-400">
          <span className="animate-spin w-3.5 h-3.5 border-2 border-gray-500 border-t-transparent rounded-full" />
          Checking OAuth registration…
        </div>
      ) : appLoadError ? (
        <p className="text-xs text-amber-200">
          Couldn&apos;t check OAuth registration: {appLoadError}
        </p>
      ) : appView && !showRegisterForm ? (
        // ─── Registered: render the connect button ────────────────────────
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleConnect}
              disabled={connecting}
              className="text-sm bg-emerald-500/90 hover:bg-emerald-400 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-60 flex items-center gap-2"
            >
              {connecting && (
                <span className="animate-spin w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full" />
              )}
              Connect with {entry.connector_name}
            </button>
            <button
              type="button"
              onClick={() => setShowRegisterForm(true)}
              className="text-xs text-gray-400 hover:text-gray-200 px-2 py-1 transition-colors"
            >
              Rotate client credentials
            </button>
          </div>
          <p className="text-[11px] text-gray-500 font-mono break-all">
            client_id: {appView.client_id}
          </p>
        </div>
      ) : (
        // ─── Unregistered (or rotating): render the registration form ────
        <OAuthAppRegistrationForm
          entry={entry}
          existing={appView}
          onSaved={async () => {
            await refresh();
            setShowRegisterForm(false);
          }}
          onCancel={
            appView
              ? () => setShowRegisterForm(false)
              : undefined
          }
          schemaHints={hints}
        />
      )}
    </div>
  );
}

/**
 * Inline form for registering or rotating a tenant's OAuth client.
 *
 * The schema's :class:`OAuthHints` already declares default authorize and
 * token URLs plus the scope set we recommend, so we pre-fill those — the
 * operator only *has* to provide ``client_id`` and ``client_secret``. Any
 * non-defaults they paste become per-tenant overrides on the
 * ``oauth_app_credentials`` row.
 */
function OAuthAppRegistrationForm({
  entry,
  existing,
  schemaHints,
  onSaved,
  onCancel,
}: {
  entry: ConnectorCatalogEntry;
  existing: OAuthAppView | null;
  schemaHints: ConnectorCatalogEntry['oauth'];
  onSaved: () => Promise<void> | void;
  onCancel?: () => void;
}) {
  const [clientId, setClientId] = useState(existing?.client_id ?? '');
  const [clientSecret, setClientSecret] = useState('');
  const [authorizeUrl, setAuthorizeUrl] = useState(
    existing?.authorize_url ?? schemaHints?.authorize_url ?? '',
  );
  const [tokenUrl, setTokenUrl] = useState(
    existing?.token_url ?? schemaHints?.token_url ?? '',
  );
  const [scopesText, setScopesText] = useState(
    (existing?.scopes ?? schemaHints?.scopes ?? []).join(' '),
  );
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!clientId.trim() || !clientSecret.trim()) {
      toast.error('Client ID and Client Secret are required');
      return;
    }
    setSaving(true);
    try {
      const scopes = scopesText
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      await oauthApi.upsertApp(entry.connector_id, {
        client_id: clientId.trim(),
        client_secret: clientSecret,
        authorize_url: authorizeUrl.trim() || null,
        token_url: tokenUrl.trim() || null,
        scopes: scopes.length > 0 ? scopes : null,
      });
      // Wipe the secret out of React state immediately — no reason to keep
      // it around once the vault has it. The next render of this form will
      // get a blank secret box, which is the right UX for "registered".
      setClientSecret('');
      toast.success('OAuth app registered');
      await onSaved();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to register OAuth app';
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const fieldClass =
    'w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-xs text-gray-100 placeholder-gray-600 focus:outline-none focus:border-emerald-500/60 focus:ring-1 focus:ring-emerald-500/30 transition-colors';

  return (
    <form onSubmit={handleSubmit} className="space-y-3 pt-1">
      <p className="text-xs text-gray-400 leading-relaxed">
        First time connecting? Register your OAuth app in {entry.connector_name} (using the
        redirect URI shown in the docs), then paste the client credentials below.
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-[11px] font-semibold text-gray-300 mb-1">
            Client ID <span className="text-red-400">*</span>
          </label>
          <input
            type="text"
            value={clientId}
            onChange={(e) => setClientId(e.target.value)}
            placeholder="client_xxxxxxxx"
            className={clsx(fieldClass, 'font-mono')}
            required
            autoComplete="off"
          />
        </div>
        <div>
          <label className="block text-[11px] font-semibold text-gray-300 mb-1">
            Client Secret <span className="text-red-400">*</span>
          </label>
          <input
            type="password"
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            placeholder={existing ? 'Re-enter to rotate' : '••••••••'}
            className={clsx(fieldClass, 'font-mono')}
            required
            autoComplete="new-password"
          />
        </div>
      </div>

      <details className="group">
        <summary className="cursor-pointer text-[11px] text-gray-500 hover:text-gray-300 select-none">
          Override authorize URL, token URL, or scopes
        </summary>
        <div className="mt-3 space-y-3">
          <div>
            <label className="block text-[11px] font-semibold text-gray-300 mb-1">
              Authorize URL
            </label>
            <input
              type="url"
              value={authorizeUrl}
              onChange={(e) => setAuthorizeUrl(e.target.value)}
              placeholder={schemaHints?.authorize_url ?? 'https://provider.example.com/oauth/authorize'}
              className={fieldClass}
              autoComplete="off"
            />
          </div>
          <div>
            <label className="block text-[11px] font-semibold text-gray-300 mb-1">
              Token URL
            </label>
            <input
              type="url"
              value={tokenUrl}
              onChange={(e) => setTokenUrl(e.target.value)}
              placeholder={schemaHints?.token_url ?? 'https://provider.example.com/oauth/token'}
              className={fieldClass}
              autoComplete="off"
            />
          </div>
          <div>
            <label className="block text-[11px] font-semibold text-gray-300 mb-1">
              Scopes (space- or comma-separated)
            </label>
            <input
              type="text"
              value={scopesText}
              onChange={(e) => setScopesText(e.target.value)}
              placeholder={(schemaHints?.scopes ?? []).join(' ') || 'openid profile email'}
              className={fieldClass}
              autoComplete="off"
            />
            {schemaHints?.scopes && schemaHints.scopes.length > 0 && (
              <p className="mt-1 text-[10px] text-gray-600 font-mono">
                Schema default: {schemaHints.scopes.join(' ')}
              </p>
            )}
          </div>
        </div>
      </details>

      <div className="flex items-center gap-2">
        <button
          type="submit"
          disabled={saving}
          className="text-xs bg-emerald-600 hover:bg-emerald-500 text-white px-3 py-2 rounded-lg transition-colors disabled:opacity-60 flex items-center gap-2"
        >
          {saving && (
            <span className="animate-spin w-3 h-3 border-2 border-white border-t-transparent rounded-full" />
          )}
          {existing ? 'Update OAuth app' : 'Register OAuth app'}
        </button>
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            disabled={saving}
            className="text-xs text-gray-400 hover:text-gray-200 px-2 py-2 transition-colors disabled:opacity-50"
          >
            Cancel
          </button>
        )}
      </div>
    </form>
  );
}

// ─── Config step ─────────────────────────────────────────────────────────────

interface ConfigStepProps {
  entry: ConnectorCatalogEntry;
  values: Record<string, string | number | boolean>;
  setValues: (next: Record<string, string | number | boolean>) => void;
  instanceName: string;
  setInstanceName: (next: string) => void;
  /** Last test result, so we can render the AI troubleshooter inline. */
  testResult: ConnectorTestResult | null;
}

function ConfigStep({
  entry,
  values,
  setValues,
  instanceName,
  setInstanceName,
  testResult,
}: ConfigStepProps) {
  const updateField = (name: string, next: string | number | boolean) => {
    setValues({ ...values, [name]: next });
  };

  // Names of secret-typed fields, passed to the troubleshooter so the LLM
  // can reason about credential shape without ever seeing the values.
  const authConfigKeys = useMemo(
    () => entry.fields.filter((f) => f.type === 'secret').map((f) => f.name),
    [entry.fields],
  );

  // True when the schema advertises hosted OAuth — drives whether we render
  // the OAuth panel and whether the manual fields collapse under a
  // disclosure (recommended path: OAuth; fallback: paste secrets).
  const supportsHostedOAuth = Boolean(entry.oauth?.supported_in_hosted);

  return (
    <div className="space-y-5">
      {/* Friendly label for this instance — separate from the catalog name
          so an operator can have e.g. two CrowdStrike tenants distinguished
          by "Falcon — production" / "Falcon — staging". */}
      <div>
        <label className="block text-xs font-semibold text-gray-300 mb-1">
          Instance name
          <span className="text-red-400 ml-0.5">*</span>
        </label>
        <input
          type="text"
          value={instanceName}
          onChange={(e) => setInstanceName(e.target.value)}
          placeholder={`${entry.connector_name} — production`}
          className="w-full bg-gray-950/60 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30"
          required
        />
        <p className="mt-1 text-xs text-gray-500">
          Shown in the connectors list and on alerts ingested through this connector.
        </p>
      </div>

      {/* OAuth one-click panel — only renders for connectors that opted in
          via OAuthHints.supported_in_hosted=true. The panel handles its own
          state (registered vs unregistered, rotating credentials) and
          triggers a browser-level redirect on success. */}
      {supportsHostedOAuth && (
        <OAuthPanel entry={entry} instanceName={instanceName} />
      )}

      {/* Manual fields. For hosted-OAuth connectors we collapse these under
          a disclosure since OAuth is the recommended path; for everyone
          else they're rendered inline as before. */}
      {supportsHostedOAuth ? (
        <details className="group rounded-lg border border-gray-800/80 bg-gray-900/30">
          <summary className="cursor-pointer select-none px-4 py-3 text-xs font-semibold text-gray-400 hover:text-gray-200 transition-colors">
            Or use static credentials instead
          </summary>
          <div className="px-4 pb-4 pt-1 space-y-5">
            {entry.fields.map((f) => (
              <div key={f.name}>
                <label className="block text-xs font-semibold text-gray-300 mb-1">
                  {f.label}
                  {f.required && <span className="text-red-400 ml-0.5">*</span>}
                </label>
                <FieldInput
                  field={f}
                  value={values[f.name]}
                  onChange={(v) => updateField(f.name, v)}
                />
                {f.help_text && (
                  <p className="mt-1 text-xs text-gray-500 leading-relaxed">{f.help_text}</p>
                )}
              </div>
            ))}
          </div>
        </details>
      ) : (
        entry.fields.map((f) => (
          <div key={f.name}>
            <label className="block text-xs font-semibold text-gray-300 mb-1">
              {f.label}
              {f.required && <span className="text-red-400 ml-0.5">*</span>}
            </label>
            <FieldInput field={f} value={values[f.name]} onChange={(v) => updateField(f.name, v)} />
            {f.help_text && (
              <p className="mt-1 text-xs text-gray-500 leading-relaxed">{f.help_text}</p>
            )}
          </div>
        ))
      )}

      {entry.docs_url && (
        <p className="text-xs text-gray-500">
          Need help?{' '}
          <a
            href={entry.docs_url}
            target="_blank"
            rel="noreferrer"
            className="text-blue-400 hover:text-blue-300 underline-offset-2 hover:underline"
          >
            View setup guide
          </a>
        </p>
      )}

      {/* AI troubleshooter — only renders when the last test failed. We
          keep this inside ConfigStep (not the modal footer) so the panel
          scrolls with the form fields the operator probably needs to fix. */}
      {testResult && !testResult.success && (
        <TroubleshootPanel
          connectorId={entry.connector_id}
          testResult={testResult}
          authConfigKeys={authConfigKeys}
        />
      )}
    </div>
  );
}

// ─── Verify-data-flowing step ────────────────────────────────────────────────

/**
 * Final wizard screen — operator just saved a connector, now we wait for
 * the first event to land.
 *
 * Polls ``GET /api/v1/connectors/{id}/last_event_at`` every 5s for up to
 * five minutes. The poll is naturally bounded by the modal closing, so we
 * also stop polling once an event arrives.
 *
 * For first-time operators this screen is the moment of truth — it's the
 * difference between "I configured something" and "data is actually
 * flowing into AiSOC". Without it the wizard ends ambiguously and folks
 * tend to wander off to read docs instead of waiting.
 */
function VerifyStep({
  connector,
  onDone,
}: {
  connector: Connector;
  onDone: () => void;
}) {
  const [lastEvent, setLastEvent] = useState<ConnectorLastEvent | null>(null);
  const [pollError, setPollError] = useState<string | null>(null);
  const [elapsed, setElapsed] = useState(0);
  // Hard cap on polling — five minutes is generous enough for batch-poll
  // connectors (5min default cadence) but stops us hammering the API
  // forever if the connector never fires.
  const MAX_ELAPSED_SEC = 5 * 60;

  useEffect(() => {
    let cancelled = false;
    let tickTimer: ReturnType<typeof setInterval> | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const poll = async () => {
      try {
        const res = await connectorsApi.lastEvent(connector.id);
        if (cancelled) return;
        setPollError(null);
        if (res.last_event_at) {
          setLastEvent(res);
          // Stop both timers — we're done. The user can dismiss whenever
          // they're ready.
          if (pollTimer) clearInterval(pollTimer);
          if (tickTimer) clearInterval(tickTimer);
        }
      } catch (err) {
        if (cancelled) return;
        setPollError(err instanceof Error ? err.message : 'Polling failed');
      }
    };

    void poll();
    pollTimer = setInterval(poll, 5000);
    tickTimer = setInterval(() => {
      setElapsed((e) => {
        const next = e + 1;
        if (next >= MAX_ELAPSED_SEC) {
          if (pollTimer) clearInterval(pollTimer);
          if (tickTimer) clearInterval(tickTimer);
        }
        return next;
      });
    }, 1000);

    return () => {
      cancelled = true;
      if (pollTimer) clearInterval(pollTimer);
      if (tickTimer) clearInterval(tickTimer);
    };
  }, [connector.id]);

  const arrived = Boolean(lastEvent?.last_event_at);
  const timedOut = !arrived && elapsed >= MAX_ELAPSED_SEC;

  return (
    <div className="space-y-5">
      <div className="rounded-lg border border-gray-800/80 bg-gray-900/40 p-5">
        <div className="flex items-start gap-4">
          {arrived ? (
            <div className="flex-shrink-0 w-10 h-10 rounded-full bg-green-500/15 border border-green-500/30 flex items-center justify-center">
              <svg className="w-5 h-5 text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            </div>
          ) : timedOut ? (
            <div className="flex-shrink-0 w-10 h-10 rounded-full bg-amber-500/15 border border-amber-500/30 flex items-center justify-center">
              <svg className="w-5 h-5 text-amber-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
            </div>
          ) : (
            <div className="flex-shrink-0 w-10 h-10 rounded-full bg-blue-500/15 border border-blue-500/30 flex items-center justify-center">
              <span className="animate-spin w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full" />
            </div>
          )}
          <div className="min-w-0 flex-1">
            <h3 className="text-sm font-semibold text-gray-100">
              {arrived
                ? 'Data is flowing'
                : timedOut
                  ? 'No data yet'
                  : 'Waiting for first event…'}
            </h3>
            <p className="text-xs text-gray-400 mt-1 leading-relaxed">
              {arrived ? (
                <>
                  AiSOC received the first event from{' '}
                  <span className="text-gray-200">{connector.name}</span>. The connector is
                  healthy and on its normal poll cadence.
                </>
              ) : timedOut ? (
                <>
                  We didn&apos;t see any events from{' '}
                  <span className="text-gray-200">{connector.name}</span> in five minutes.
                  This is normal for low-volume sources, but if you expect activity, check the
                  connector&apos;s Health tab for poll errors.
                </>
              ) : (
                <>
                  AiSOC is polling <span className="text-gray-200">{connector.name}</span> on
                  its configured cadence. The first batch usually lands within a minute or two.
                </>
              )}
            </p>

            {arrived && lastEvent?.last_event_at && (
              <dl className="mt-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
                <dt className="text-gray-500">First event</dt>
                <dd className="text-gray-200 font-mono">
                  {new Date(lastEvent.last_event_at).toLocaleString()}
                </dd>
                {lastEvent.last_event_kind && (
                  <>
                    <dt className="text-gray-500">Kind</dt>
                    <dd className="text-gray-200 font-mono">{lastEvent.last_event_kind}</dd>
                  </>
                )}
              </dl>
            )}

            {!arrived && !timedOut && (
              <p className="mt-3 text-xs text-gray-600 font-mono">
                {Math.floor(elapsed / 60)}:{String(elapsed % 60).padStart(2, '0')} elapsed
              </p>
            )}

            {pollError && (
              <p className="mt-2 text-xs text-red-400">Polling error: {pollError}</p>
            )}
          </div>
        </div>
      </div>

      <div className="text-xs text-gray-500 leading-relaxed">
        You can close this dialog at any time — verification keeps running in the background.
        Health and freshness for this connector live on its detail page.
      </div>

      <div className="flex justify-end">
        <button
          type="button"
          onClick={onDone}
          className={clsx(
            'text-sm px-4 py-2 rounded-lg transition-colors',
            arrived
              ? 'bg-blue-600 hover:bg-blue-500 text-white'
              : 'bg-gray-800 hover:bg-gray-700 text-gray-200',
          )}
        >
          {arrived ? 'Done' : 'Close — keep waiting in background'}
        </button>
      </div>
    </div>
  );
}

// ─── Main modal ──────────────────────────────────────────────────────────────

interface AddConnectorModalProps {
  open: boolean;
  onClose: () => void;
  /** Called after a connector is created so the parent can refresh its list. */
  onCreated?: (connector: Connector) => void;
  /**
   * If set, the picker will auto-advance to the configure step for this
   * connector class once the catalog finishes loading. The /onboarding
   * "Most teams pick" tiles use this to drop the operator straight onto
   * the configure form for the vendor they clicked.
   */
  primedConnectorId?: string | null;
  /**
   * If set, the picker pre-filters the catalog grid to a single category
   * (e.g. "edr"). Used by /onboarding category pills so an operator who
   * clicked "Endpoint" only sees endpoint connectors.
   */
  activeCategory?: string | null;
}

type WizardStep = 'pick' | 'configure' | 'verify';

export function AddConnectorModal({
  open,
  onClose,
  onCreated,
  primedConnectorId,
  activeCategory,
}: AddConnectorModalProps) {
  const [step, setStep] = useState<WizardStep>('pick');
  const [catalog, setCatalog] = useState<ConnectorCatalogEntry[] | null>(null);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  // Free-text filter for the catalog grid.
  const [query, setQuery] = useState<string>('');
  // Sticky category filter — initialized from the activeCategory prop and
  // tweakable via a "clear" affordance once the modal is open.
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);

  const [selected, setSelected] = useState<ConnectorCatalogEntry | null>(null);
  const [values, setValues] = useState<Record<string, string | number | boolean>>({});
  const [instanceName, setInstanceName] = useState<string>('');

  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<ConnectorTestResult | null>(null);
  const [saving, setSaving] = useState(false);
  // Connector instance returned by the create call — used by the verify
  // step to poll for the first event.
  const [createdConnector, setCreatedConnector] = useState<Connector | null>(null);

  // Load catalog whenever the modal opens. We don't keep stale data around
  // between opens because the operator may have added a new connector class
  // and redeployed.
  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setCatalog(null);
    setCatalogError(null);
    setStep('pick');
    setSelected(null);
    setValues({});
    setInstanceName('');
    setTestResult(null);
    setQuery('');
    // Snapshot the category prop at open time. Subsequent prop changes
    // shouldn't yank the operator's filter out from under them mid-flow.
    setCategoryFilter(activeCategory ?? null);
    setCreatedConnector(null);

    connectorsApi
      .catalog()
      .then((res) => {
        if (cancelled) return;
        setCatalog(res.connectors);

        // Auto-advance to configure for the primed connector, if any. We
        // do this here (after catalog loads) rather than in render so that
        // the catalog state, selected entry, and form values all settle
        // in the right order. If the primed id isn't in the catalog (e.g.
        // a stale curated list pointed at a connector we removed), we
        // silently fall back to the picker.
        if (primedConnectorId) {
          const entry = res.connectors.find((e) => e.connector_id === primedConnectorId);
          if (entry) {
            setSelected(entry);
            setValues(buildInitialValues(entry.fields));
            setInstanceName(entry.connector_name);
            setStep('configure');
          }
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        const msg = err instanceof Error ? err.message : 'Failed to load connector catalog';
        setCatalogError(msg);
      });

    return () => {
      cancelled = true;
    };
    // We intentionally only re-run when the modal toggles open. The primed
    // id and category props are read at open-time; changing them mid-flow
    // would discard the operator's typed credentials.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  // Close on Escape — but only when we're on the picker. On the config
  // and verify screens, prefer the explicit Cancel/Done buttons so a
  // misclick doesn't lose the operator's typed credentials or interrupt
  // first-event polling.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && step === 'pick') {
        onClose();
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, step, onClose]);

  const handlePick = (entry: ConnectorCatalogEntry) => {
    setSelected(entry);
    setValues(buildInitialValues(entry.fields));
    setInstanceName(entry.connector_name);
    setTestResult(null);
    setStep('configure');
  };

  const handleBack = () => {
    setStep('pick');
    setSelected(null);
    setTestResult(null);
  };

  const handleTest = async () => {
    if (!selected) return;
    setTesting(true);
    setTestResult(null);
    try {
      const { auth_config, connector_config } = partitionFormValues(selected.fields, values);
      const result = await connectorsApi.testInline({
        connector_type: selected.connector_id,
        auth_config,
        connector_config,
      });
      setTestResult(result);
      if (result.success) {
        toast.success('Connection test passed');
      } else {
        toast.error(result.error ?? result.message ?? 'Connection test failed');
      }
    } catch (err) {
      // `ApiError.message` is only "API 502 Bad Gateway — /api/v1/connectors/test".
      // The reason the operator can act on — which service refused, with what
      // status, and what to set — is in the response body, so a bare `.message`
      // here reproduced the dead end this panel is meant to have stopped
      // showing. Prefer the API's `detail`, fall back to the status line.
      const msg = describeApiError(err, 'Test request failed');
      setTestResult({ success: false, error: msg });
      toast.error(msg);
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!selected) return;
    if (!instanceName.trim()) {
      toast.error('Please give this connector an instance name');
      return;
    }
    setSaving(true);
    try {
      const { auth_config, connector_config } = partitionFormValues(selected.fields, values);
      const created = await connectorsApi.create({
        name: instanceName.trim(),
        connector_type: selected.connector_id,
        category: selected.category,
        auth_config,
        connector_config,
      });
      toast.success(`Connected ${created.name}`);
      // Notify parent immediately so the connectors list refreshes in the
      // background while the operator watches for the first event. We don't
      // close the modal here — the verify step is the third leg of the
      // wizard and is what gives a first-time operator confidence the
      // connector actually works end-to-end.
      onCreated?.(created);
      setCreatedConnector(created);
      setStep('verify');
    } catch (err) {
      // Same reasoning as handleTest: a save refused by the credential vault
      // answers 500 with a detail that names AISOC_CREDENTIAL_KEY, and the
      // status line names nothing.
      const msg = describeApiError(err, 'Failed to save connector');
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleDoneVerify = () => {
    // Verify step is purely informational — the actual connector is already
    // saved and the parent has been told about it. Closing is the same as
    // dismissing the dialog from the picker.
    onClose();
  };

  return (
    <AnimatePresence>
      {open && (
        <Fragment>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-40 bg-black/60 backdrop-blur-sm"
            onClick={() => {
              if (step === 'pick') onClose();
            }}
          />

          {/* Panel */}
          <motion.div
            initial={{ opacity: 0, y: 12, scale: 0.98 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8, scale: 0.98 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="fixed inset-0 z-50 flex items-center justify-center p-4 pointer-events-none"
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="add-connector-title"
              className="pointer-events-auto w-full max-w-3xl max-h-[85vh] overflow-hidden rounded-2xl border border-gray-800 bg-gray-950 shadow-2xl flex flex-col"
            >
              {/* Header */}
              <div className="flex items-start justify-between gap-4 px-6 py-4 border-b border-gray-800">
                <div className="min-w-0">
                  <h2
                    id="add-connector-title"
                    className="text-base font-semibold text-gray-100"
                  >
                    {step === 'pick'
                      ? 'Add connector'
                      : step === 'configure'
                        ? `Configure ${selected?.connector_name ?? ''}`
                        : `Verifying ${createdConnector?.name ?? ''}`}
                  </h2>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {step === 'pick'
                      ? 'Pick a security tool to connect. Credentials are encrypted with the AiSOC vault.'
                      : step === 'configure'
                        ? 'Credentials are tested against the upstream API and only saved on success.'
                        : 'Watching for the first event to land. This is normally seconds for high-volume sources.'}
                  </p>
                </div>
                <button
                  type="button"
                  onClick={onClose}
                  aria-label="Close"
                  className="text-gray-500 hover:text-gray-300 transition-colors p-1"
                >
                  <svg className="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>

              {/* Body */}
              <div className="flex-1 overflow-y-auto px-6 py-5">
                {step === 'pick' && (
                  <div className="space-y-4">
                    {/* Search field — surfaced above the grid so operators
                        with a long catalog can jump straight to e.g.
                        "crowdstrike" without scrolling past unrelated
                        categories. */}
                    <div className="relative">
                      <svg
                        className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-600"
                        fill="none"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M21 21l-4.35-4.35m0 0A7.5 7.5 0 103.5 10.5a7.5 7.5 0 0013.15 6.15z"
                        />
                      </svg>
                      <input
                        type="search"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search by name, vendor, or capability"
                        className="w-full bg-gray-950/60 border border-gray-800 rounded-lg pl-9 pr-3 py-2 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-blue-500/60 focus:ring-1 focus:ring-blue-500/30"
                        autoFocus
                      />
                    </div>

                    {/* Active category chip — shows when /onboarding handed
                        us a category to filter to. Clicking the X drops the
                        filter so the operator can browse the full catalog. */}
                    {categoryFilter && (
                      <div className="flex items-center gap-2 text-xs text-gray-400">
                        <span>Filtered to</span>
                        <button
                          type="button"
                          onClick={() => setCategoryFilter(null)}
                          className="inline-flex items-center gap-1.5 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-200 px-2.5 py-0.5 hover:bg-blue-500/20 transition-colors"
                          title="Clear category filter"
                        >
                          <span className="font-medium">
                            {CATEGORY_LABEL[categoryFilter] ?? categoryFilter}
                          </span>
                          <svg
                            className="h-3 w-3"
                            fill="none"
                            viewBox="0 0 24 24"
                            stroke="currentColor"
                          >
                            <path
                              strokeLinecap="round"
                              strokeLinejoin="round"
                              strokeWidth={2}
                              d="M6 18L18 6M6 6l12 12"
                            />
                          </svg>
                        </button>
                      </div>
                    )}

                    {catalog === null && !catalogError ? (
                      <div className="flex items-center justify-center h-32 text-gray-600">
                        <div className="animate-spin w-6 h-6 border-2 border-blue-500 border-t-transparent rounded-full" />
                      </div>
                    ) : catalogError ? (
                      <div className="text-sm text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                        Failed to load connector catalog: {catalogError}
                      </div>
                    ) : (
                      <CatalogGrid
                        entries={catalog ?? []}
                        onPick={handlePick}
                        query={query}
                        categoryFilter={categoryFilter}
                      />
                    )}
                  </div>
                )}

                {step === 'configure' && selected && (
                  <ConfigStep
                    entry={selected}
                    values={values}
                    setValues={setValues}
                    instanceName={instanceName}
                    setInstanceName={setInstanceName}
                    testResult={testResult}
                  />
                )}

                {step === 'verify' && createdConnector && (
                  <VerifyStep connector={createdConnector} onDone={handleDoneVerify} />
                )}
              </div>

              {/* Footer */}
              <div className="flex items-center justify-between gap-3 px-6 py-4 border-t border-gray-800 bg-gray-950/80">
                {step === 'pick' ? (
                  <>
                    <p className="text-xs text-gray-600">
                      {(catalog?.length ?? 0)} connector type
                      {(catalog?.length ?? 0) === 1 ? '' : 's'} available
                    </p>
                    <button
                      type="button"
                      onClick={onClose}
                      className="text-sm text-gray-400 hover:text-gray-200 px-3 py-2 rounded-lg transition-colors"
                    >
                      Cancel
                    </button>
                  </>
                ) : step === 'configure' ? (
                  <>
                    <div className="flex items-center gap-2 min-w-0">
                      <button
                        type="button"
                        onClick={handleBack}
                        disabled={saving}
                        className="text-sm text-gray-400 hover:text-gray-200 px-3 py-2 rounded-lg transition-colors disabled:opacity-50"
                      >
                        ← Back
                      </button>
                      {testResult && (
                        <span
                          className={clsx(
                            'truncate text-xs px-2 py-1 rounded-md border',
                            testResult.success
                              ? 'text-green-300 bg-green-500/10 border-green-500/20'
                              : 'text-red-300 bg-red-500/10 border-red-500/20',
                          )}
                          title={testResult.message ?? testResult.error ?? ''}
                        >
                          {testResult.success
                            ? testResult.message ?? 'Connection successful'
                            : testResult.error ?? testResult.message ?? 'Connection failed'}
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={handleTest}
                        disabled={testing || saving}
                        className="text-sm bg-gray-800 hover:bg-gray-700 text-gray-200 px-3 py-2 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
                      >
                        {testing && (
                          <span className="animate-spin w-3.5 h-3.5 border-2 border-blue-400 border-t-transparent rounded-full" />
                        )}
                        Test connection
                      </button>
                      <button
                        type="button"
                        onClick={handleSave}
                        disabled={saving || testing}
                        className="text-sm bg-blue-600 hover:bg-blue-500 text-white px-4 py-2 rounded-lg transition-colors disabled:opacity-50 flex items-center gap-2"
                      >
                        {saving && (
                          <span className="animate-spin w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full" />
                        )}
                        Save connector
                      </button>
                    </div>
                  </>
                ) : (
                  // Verify step has its own action button inside VerifyStep
                  // (the centered "Done" / "Close" CTA), so the footer just
                  // shows secondary status. Keeping a lightweight footer
                  // preserves visual rhythm with the previous two steps.
                  <p className="text-xs text-gray-600">
                    Verification continues in the background even after you close.
                  </p>
                )}
              </div>
            </div>
          </motion.div>
        </Fragment>
      )}
    </AnimatePresence>
  );
}
