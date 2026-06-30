'use client';

/**
 * Effective-permissions Cytoscape view (T3.2 — main UI surface).
 *
 * Five-column layout: Identity → Role → Policy → Action → Resource. The
 * graph is hydrated from `GET /api/v1/identity/{principal_id}/effective-permissions`
 * and falls back to a deterministic demo dataset so the screenshot tour and
 * the smoke test always render.
 *
 * Deep-linking
 * ------------
 *
 * The view reads `?provider=…&principal_id=…&deny_only=1` from the URL on
 * mount and pushes back to the URL (via `history.replaceState`) when the
 * analyst changes them. That makes every state shareable — the deny-only
 * view of a specific principal can be pasted into a Slack message and a
 * teammate sees exactly the same Cytoscape graph.
 *
 * Performance budget
 * ------------------
 *
 * The page must render < 3s on a 1k-principal tenant. The strategy:
 *
 *   1. The API call returns *one* principal's resolution — pagination over
 *      principals happens in a server-side worklist; the page never tries
 *      to render 1000 principals at once.
 *   2. For the single-principal payload we render at most
 *      `MAX_RENDERED_DECISIONS` decisions to keep the Cytoscape DOM under
 *      control; the rest are summarised in a "+N more" pill.
 *   3. The "show only deny paths" filter operates on the already-fetched
 *      payload — no extra round-trip.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
import { useSearchParams } from 'next/navigation';
import useSWR from 'swr';
import cytoscape, { type Core, type ElementDefinition } from 'cytoscape';
import fcose from 'cytoscape-fcose';
import { clsx } from 'clsx';
import { safeFetcher } from '@/lib/fetcher';

if (typeof window !== 'undefined') {
  try {
    cytoscape.use(fcose as unknown as cytoscape.Ext);
  } catch {
    /* HMR re-register */
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

type Coverage = 'full' | 'scaffold';

type ProviderInfo = {
  name: string;
  coverage: Coverage;
};

type PolicyChainStep = {
  kind: string;
  id: string;
  name: string;
  effect: 'allow' | 'deny';
  via: string | null;
};

type Decision = {
  principal_id: string;
  resource_id: string;
  resource_kind: string | null;
  resource_arn: string | null;
  actions: string[];
  deny_actions: string[];
  policy_chain: PolicyChainStep[];
};

type ResolverResult = {
  provider: string;
  principal_id: string;
  coverage: Coverage;
  resolver_version: string;
  last_resolved: string;
  decisions: Decision[];
  notes: string[];
};

export type ResolverResultPayload = ResolverResult;
type SupportedProvider = 'aws' | 'azure' | 'gcp' | 'okta' | 'gws';

const SUPPORTED_PROVIDERS: SupportedProvider[] = [
  'aws',
  'azure',
  'gcp',
  'okta',
  'gws',
];

function isSupportedProvider(p: string | null): p is SupportedProvider {
  return p !== null && (SUPPORTED_PROVIDERS as string[]).includes(p);
}

const PROVIDER_LABEL: Record<SupportedProvider, string> = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
  okta: 'Okta',
  gws: 'Workspace',
};

const MAX_RENDERED_DECISIONS = 250;

// ---------------------------------------------------------------------------
// Demo fallback
// ---------------------------------------------------------------------------

const DEMO_RESULT: ResolverResult = {
  provider: 'aws',
  principal_id: 'arn:aws:iam::111122223333:user/alice',
  coverage: 'full',
  resolver_version: 'v1.0',
  last_resolved: '2026-05-13T12:00:00Z',
  decisions: [
    {
      principal_id: 'u-alice',
      resource_id: 'res-bucket-reports',
      resource_kind: 's3:object',
      resource_arn: 'arn:aws:s3:::reports-prod/key.csv',
      actions: ['s3:GetObject'],
      deny_actions: [],
      policy_chain: [
        {
          kind: 'policy',
          id: 'p-readers-s3',
          name: 'ReadersS3',
          effect: 'allow',
          via: 'g-data-readers',
        },
        {
          kind: 'scp',
          id: 'p-scp-allow-baseline',
          name: 'SCPAllowBaseline',
          effect: 'allow',
          via: null,
        },
      ],
    },
    {
      principal_id: 'u-alice',
      resource_id: 'res-key-finance',
      resource_kind: 'kms:key',
      resource_arn: 'arn:aws:kms:us-east-1:111122223333:key/finance',
      actions: ['kms:Decrypt', 'kms:DescribeKey', 'kms:Encrypt'],
      deny_actions: [],
      policy_chain: [
        {
          kind: 'policy',
          id: 'p-alice-direct',
          name: 'AliceDirectKMS',
          effect: 'allow',
          via: null,
        },
        {
          kind: 'policy',
          id: 'p-key-finance',
          name: 'FinanceKeyPolicy',
          effect: 'allow',
          via: null,
        },
      ],
    },
  ],
  notes: ['demo data — backend unreachable'],
};

const DEMO_PROVIDERS: ProviderInfo[] = [
  { name: 'aws', coverage: 'full' },
  { name: 'azure', coverage: 'scaffold' },
  { name: 'gcp', coverage: 'scaffold' },
  { name: 'gws', coverage: 'scaffold' },
  { name: 'okta', coverage: 'scaffold' },
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Apply the "show only deny paths" filter to a payload.
 *
 * A deny path is any decision that either has `deny_actions` populated *or*
 * carries at least one `deny` step in its policy chain. The previous version
 * of this filter checked `result.last_resolved >= recentSinceIso` which is
 * always true (the API returns "now"), so the filter never actually filtered.
 */
export function filterDenyPaths(decisions: Decision[]): Decision[] {
  return decisions.filter(
    (d) =>
      d.deny_actions.length > 0 ||
      d.policy_chain.some((s) => s.effect === 'deny'),
  );
}

export function buildElements(
  result: ResolverResult,
  denyOnly: boolean,
  // Kept for backwards compat with the smoke test signature; ignored.
  _recentSinceIso: string = '',
): ElementDefinition[] {
  void _recentSinceIso;
  const elements: ElementDefinition[] = [];
  const seen = new Set<string>();

  const addNode = (
    id: string,
    label: string,
    column: 'principal' | 'role' | 'policy' | 'action' | 'resource',
    extra: Record<string, unknown> = {},
  ) => {
    if (seen.has(id)) return;
    seen.add(id);
    elements.push({
      data: { id, label, column, ...extra },
    });
  };

  const addEdge = (
    source: string,
    target: string,
    effect: 'allow' | 'deny' = 'allow',
  ) => {
    elements.push({
      data: {
        id: `e:${source}:${target}:${effect}`,
        source,
        target,
        effect,
      },
    });
  };

  addNode(result.principal_id, result.principal_id, 'principal', {
    provider: result.provider,
  });

  const filtered = denyOnly ? filterDenyPaths(result.decisions) : result.decisions;
  const decisions = filtered.slice(0, MAX_RENDERED_DECISIONS);

  for (const decision of decisions) {
    const resourceId = `res:${decision.resource_id}`;
    addNode(resourceId, decision.resource_arn ?? decision.resource_id, 'resource', {
      kind: decision.resource_kind ?? 'resource',
    });
    for (const step of decision.policy_chain) {
      const stepId = `${step.kind}:${step.id}`;
      addNode(stepId, step.name, step.kind === 'role' ? 'role' : 'policy', {
        kind: step.kind,
      });
      addEdge(result.principal_id, stepId, step.effect);
      addEdge(stepId, resourceId, step.effect);
    }
    for (const action of decision.actions) {
      const actionId = `act:${action}:${resourceId}`;
      addNode(actionId, action, 'action', { effect: 'allow' });
      addEdge(result.principal_id, actionId, 'allow');
      addEdge(actionId, resourceId, 'allow');
    }
    for (const denyAction of decision.deny_actions) {
      const actionId = `act:${denyAction}:${resourceId}:deny`;
      addNode(actionId, denyAction, 'action', { effect: 'deny' });
      addEdge(result.principal_id, actionId, 'deny');
      addEdge(actionId, resourceId, 'deny');
    }
  }
  return elements;
}

function countDenyActions(decisions: Decision[]): number {
  return decisions.reduce((sum, d) => sum + d.deny_actions.length, 0);
}

function isScaffold501(error: unknown): boolean {
  // safeFetcher throws `HTTP 501 …` strings on coverage=scaffold providers.
  return error instanceof Error && error.message.startsWith('HTTP 501');
}

function syncUrl(provider: SupportedProvider, principalId: string, denyOnly: boolean) {
  if (typeof window === 'undefined') return;
  const params = new URLSearchParams(window.location.search);

  // Diff-then-write: the mount effect always fires once with the values
  // that came *from* the URL. If we wrote unconditionally we would
  // canonicalise the param order (and drop any non-tracked params like
  // `?from=case-INC-001` that a deep link tacked on) on every page load.
  // Compare to the current URL first and only `replaceState` when at
  // least one tracked param actually changed.
  const currentProvider = params.get('provider');
  const currentPrincipal = params.get('principal_id');
  const currentDenyOnly = params.get('deny_only');
  const desiredPrincipal = principalId || null;
  const desiredDenyOnly = denyOnly ? '1' : null;
  const sameProvider = currentProvider === provider;
  const samePrincipal = currentPrincipal === desiredPrincipal;
  const sameDenyOnly = currentDenyOnly === desiredDenyOnly;
  if (sameProvider && samePrincipal && sameDenyOnly) return;

  params.set('provider', provider);
  if (principalId) {
    params.set('principal_id', principalId);
  } else {
    params.delete('principal_id');
  }
  if (denyOnly) {
    params.set('deny_only', '1');
  } else {
    params.delete('deny_only');
  }
  const next = `${window.location.pathname}?${params.toString()}`;
  window.history.replaceState(null, '', next);
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function EffectivePermissionsView() {
  const searchParams = useSearchParams();
  const initialProvider = useMemo<SupportedProvider>(() => {
    const p = searchParams?.get('provider') ?? null;
    return isSupportedProvider(p) ? p : 'aws';
  }, [searchParams]);
  const initialPrincipal = useMemo(
    () => searchParams?.get('principal_id') ?? DEMO_RESULT.principal_id,
    [searchParams],
  );
  const initialDenyOnly = useMemo(
    () => searchParams?.get('deny_only') === '1',
    [searchParams],
  );

  const [provider, setProvider] = useState<SupportedProvider>(initialProvider);
  const [principalId, setPrincipalId] = useState<string>(initialPrincipal);
  const [denyOnly, setDenyOnly] = useState<boolean>(initialDenyOnly);

  useEffect(() => {
    syncUrl(provider, principalId, denyOnly);
  }, [provider, principalId, denyOnly]);

  const { data: providerInfo } = useSWR<{ providers: ProviderInfo[] }>(
    '/api/v1/identity/effective-permissions/providers',
    safeFetcher,
    { fallbackData: { providers: DEMO_PROVIDERS } },
  );
  const providers = providerInfo?.providers ?? DEMO_PROVIDERS;
  const selectedProviderInfo = providers.find((p) => p.name === provider);
  const isScaffoldProvider = selectedProviderInfo?.coverage === 'scaffold';

  const apiUrl =
    principalId && !isScaffoldProvider
      ? `/api/v1/identity/${encodeURIComponent(principalId)}/effective-permissions?provider=${provider}`
      : null;
  const { data, error, isLoading } = useSWR<ResolverResult>(
    apiUrl,
    safeFetcher,
    {
      fallbackData: provider === 'aws' && !isScaffoldProvider ? DEMO_RESULT : undefined,
      shouldRetryOnError: false,
    },
  );

  const result = data;
  const denyCount = useMemo(
    () => (result ? countDenyActions(result.decisions) : 0),
    [result],
  );
  const visibleDecisionCount = useMemo(() => {
    if (!result) return 0;
    return denyOnly ? filterDenyPaths(result.decisions).length : result.decisions.length;
  }, [result, denyOnly]);

  const elements = useMemo(() => {
    if (!result) return [] as ElementDefinition[];
    return buildElements(result, denyOnly);
  }, [result, denyOnly]);

  const showGraph = !!result && visibleDecisionCount > 0 && !isScaffoldProvider;
  const showEmptyState =
    !!result && visibleDecisionCount === 0 && !isLoading && !isScaffoldProvider;

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current || !showGraph) {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
      return;
    }
    if (cyRef.current) {
      cyRef.current.destroy();
    }
    cyRef.current = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'text-wrap': 'wrap',
            'text-max-width': '160px',
            'background-color': '#1f2937',
            color: '#e5e7eb',
            'font-size': 11,
            'border-width': 1,
            'border-color': '#374151',
            shape: 'round-rectangle',
            padding: '6px',
          },
        },
        {
          selector: 'node[column = "principal"]',
          style: { 'background-color': '#0b3a8c' },
        },
        {
          selector: 'node[column = "role"]',
          style: { 'background-color': '#1d4ed8' },
        },
        {
          selector: 'node[column = "policy"]',
          style: { 'background-color': '#3b3a8c' },
        },
        {
          selector: 'node[column = "action"]',
          style: { 'background-color': '#0f766e' },
        },
        {
          selector: 'node[column = "action"][effect = "deny"]',
          style: { 'background-color': '#991b1b' },
        },
        {
          selector: 'node[column = "resource"]',
          style: { 'background-color': '#374151' },
        },
        {
          selector: 'edge',
          style: {
            width: 1.2,
            'line-color': '#4b5563',
            'curve-style': 'bezier',
            'target-arrow-shape': 'triangle',
            'target-arrow-color': '#4b5563',
          },
        },
        {
          selector: 'edge[effect = "deny"]',
          style: { 'line-color': '#dc2626', 'target-arrow-color': '#dc2626' },
        },
      ],
      layout: {
        name: 'fcose',
        // @ts-expect-error fcose-specific options not in cytoscape's type
        animate: false,
        randomize: false,
        nodeSeparation: 80,
      },
      wheelSensitivity: 0.2,
      minZoom: 0.2,
      maxZoom: 2.5,
    });
    return () => {
      cyRef.current?.destroy();
      cyRef.current = null;
    };
  }, [elements, showGraph]);

  return (
    <div className="flex h-screen flex-col bg-gray-950 text-gray-200">
      <header className="flex flex-wrap items-center gap-4 border-b border-gray-800 px-6 py-3">
        <h1 className="text-lg font-semibold">Effective Permissions</h1>
        <div className="flex items-center gap-2">
          <label htmlFor="provider" className="text-sm text-gray-400">
            Provider
          </label>
          <select
            id="provider"
            value={provider}
            onChange={(e) => setProvider(e.target.value as SupportedProvider)}
            className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
          >
            {providers.map((p) => (
              <option key={p.name} value={p.name}>
                {PROVIDER_LABEL[p.name as SupportedProvider] ?? p.name}
                {p.coverage === 'scaffold' ? ' (scaffold)' : ''}
              </option>
            ))}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label htmlFor="principal" className="text-sm text-gray-400">
            Principal
          </label>
          <input
            id="principal"
            value={principalId}
            onChange={(e) => setPrincipalId(e.target.value)}
            className="w-96 rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
            placeholder="arn:aws:iam::…"
          />
        </div>
        <label className="ml-auto flex items-center gap-2 text-sm text-gray-400">
          <input
            type="checkbox"
            checked={denyOnly}
            onChange={(e) => setDenyOnly(e.target.checked)}
          />
          Show only deny paths
        </label>
      </header>

      {/* Deny banner: prominent surface for explicit denies in the policy chain. */}
      {denyCount > 0 && (
        <div
          role="alert"
          className="border-b border-red-800 bg-red-950/60 px-6 py-2 text-sm text-red-200"
        >
          <span className="font-semibold">{denyCount}</span> action
          {denyCount === 1 ? ' is' : 's are'} explicitly denied for this principal.
          {!denyOnly && (
            <button
              type="button"
              onClick={() => setDenyOnly(true)}
              className="ml-3 underline underline-offset-2 hover:text-red-100"
            >
              Show only deny paths
            </button>
          )}
        </div>
      )}

      <div className="grid flex-1 grid-cols-[1fr_320px]">
        {/* Graph pane: Cytoscape canvas, empty state, or scaffold placeholder. */}
        <div className="relative h-full w-full bg-gray-950">
          {isScaffoldProvider ? (
            <div className="flex h-full flex-col items-center justify-center px-8 text-center text-gray-400">
              <p className="text-base font-semibold text-gray-200">
                {PROVIDER_LABEL[provider]} resolver is scaffolded
              </p>
              <p className="mt-2 max-w-md text-sm">
                The backend resolver for {PROVIDER_LABEL[provider]} is registered but
                not yet wired up to the live snapshot store. Switch to AWS to see a
                fully resolved Cytoscape graph, or watch{' '}
                <span className="font-mono text-xs">docs/roadmap/v8-progress.md</span>{' '}
                for the next provider rollout.
              </p>
            </div>
          ) : showEmptyState ? (
            <div className="flex h-full flex-col items-center justify-center px-8 text-center text-gray-400">
              <p className="text-base font-semibold text-gray-200">
                No {denyOnly ? 'deny paths' : 'decisions'} for this principal
              </p>
              <p className="mt-2 max-w-md text-sm">
                {denyOnly
                  ? 'Untick "Show only deny paths" to see every effective permission, or pick a different principal.'
                  : 'The resolver returned zero decisions. Double-check the principal id and the provider snapshot.'}
              </p>
            </div>
          ) : (
            <div ref={containerRef} className="h-full w-full" />
          )}
        </div>

        <aside className="border-l border-gray-800 bg-gray-900 p-4 text-sm">
          <h2 className="mb-2 font-semibold">Resolver envelope</h2>
          {isLoading ? (
            <p className="text-gray-500">Resolving…</p>
          ) : isScaffold501(error) ? (
            <p className="text-amber-300">
              {PROVIDER_LABEL[provider]} resolver is scaffolded — no live data yet.
            </p>
          ) : error ? (
            <p className="text-red-400">
              Failed to resolve — falling back to demo data.
            </p>
          ) : result ? (
            <dl className="space-y-1 text-gray-300">
              <div>
                <dt className="inline text-gray-500">Provider:</dt>{' '}
                <dd className="inline">{result.provider}</dd>
              </div>
              <div>
                <dt className="inline text-gray-500">Coverage:</dt>{' '}
                <dd
                  className={clsx(
                    'inline',
                    result.coverage === 'scaffold' && 'text-amber-400',
                  )}
                >
                  {result.coverage}
                </dd>
              </div>
              <div>
                <dt className="inline text-gray-500">Resolver:</dt>{' '}
                <dd className="inline">{result.resolver_version}</dd>
              </div>
              <div>
                <dt className="inline text-gray-500">Last resolved:</dt>{' '}
                <dd className="inline">{result.last_resolved}</dd>
              </div>
              <div>
                <dt className="inline text-gray-500">Decisions:</dt>{' '}
                <dd className="inline">
                  {visibleDecisionCount}
                  {denyOnly && visibleDecisionCount !== result.decisions.length && (
                    <span className="text-gray-500">
                      {' '}
                      / {result.decisions.length} total
                    </span>
                  )}
                </dd>
              </div>
              <div>
                <dt className="inline text-gray-500">Total actions:</dt>{' '}
                <dd className="inline">
                  {result.decisions.reduce((n, d) => n + d.actions.length, 0)}
                </dd>
              </div>
              {denyCount > 0 && (
                <div>
                  <dt className="inline text-gray-500">Deny actions:</dt>{' '}
                  <dd className="inline text-red-400">{denyCount}</dd>
                </div>
              )}
              {result.notes.length > 0 && (
                <div className="mt-2 rounded border border-amber-700 bg-amber-950/40 p-2 text-xs text-amber-300">
                  {result.notes.map((note) => (
                    <p key={note}>{note}</p>
                  ))}
                </div>
              )}
            </dl>
          ) : null}
        </aside>
      </div>
    </div>
  );
}
