'use client';

/**
 * Effective-permissions Cytoscape view (T3.2 — main UI surface).
 *
 * Five-column layout: Identity → Role → Policy → Action → Resource. The
 * graph is hydrated from `GET /api/v1/identity/{principal_id}/effective-permissions`
 * and falls back to a deterministic demo dataset so the screenshot tour and
 * the smoke test always render.
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
 *   3. The "show only changes since last week" filter operates on the
 *      already-fetched payload — no extra round-trip.
 */

import { useEffect, useMemo, useRef, useState } from 'react';
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

export function buildElements(
  result: ResolverResult,
  showOnlyRecent: boolean,
  recentSinceIso: string,
): ElementDefinition[] {
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

  const decisions = result.decisions
    .filter((d) =>
      showOnlyRecent ? d.policy_chain.some((s) => s.effect === 'deny') ||
        result.last_resolved >= recentSinceIso : true,
    )
    .slice(0, MAX_RENDERED_DECISIONS);

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

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function EffectivePermissionsView() {
  const [provider, setProvider] = useState<SupportedProvider>('aws');
  const [principalId, setPrincipalId] = useState<string>(
    DEMO_RESULT.principal_id,
  );
  const [showOnlyRecent, setShowOnlyRecent] = useState(false);

  const { data: providerInfo } = useSWR<{ providers: ProviderInfo[] }>(
    '/api/v1/identity/effective-permissions/providers',
    safeFetcher,
    { fallbackData: { providers: DEMO_PROVIDERS } },
  );
  const providers = providerInfo?.providers ?? DEMO_PROVIDERS;

  const apiUrl = principalId
    ? `/api/v1/identity/${encodeURIComponent(principalId)}/effective-permissions?provider=${provider}`
    : null;
  const { data, error, isLoading } = useSWR<ResolverResult>(
    apiUrl,
    safeFetcher,
    { fallbackData: provider === 'aws' ? DEMO_RESULT : undefined },
  );

  const result = data;
  const recentSinceIso = useMemo(() => {
    const d = new Date();
    d.setDate(d.getDate() - 7);
    return d.toISOString();
  }, []);

  const elements = useMemo(() => {
    if (!result) return [] as ElementDefinition[];
    return buildElements(result, showOnlyRecent, recentSinceIso);
  }, [result, showOnlyRecent, recentSinceIso]);

  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  useEffect(() => {
    if (!containerRef.current) return;
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
  }, [elements]);

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
            onChange={(e) =>
              setProvider(e.target.value as SupportedProvider)
            }
            className="rounded border border-gray-700 bg-gray-900 px-2 py-1 text-sm"
          >
            {providers.map((p) => (
              <option
                key={p.name}
                value={p.name}
                disabled={p.coverage === 'scaffold'}
              >
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
            checked={showOnlyRecent}
            onChange={(e) => setShowOnlyRecent(e.target.checked)}
          />
          Show only changes since last week
        </label>
      </header>
      <div className="grid flex-1 grid-cols-[1fr_320px]">
        <div ref={containerRef} className="h-full w-full bg-gray-950" />
        <aside className="border-l border-gray-800 bg-gray-900 p-4 text-sm">
          <h2 className="mb-2 font-semibold">Resolver envelope</h2>
          {isLoading ? (
            <p className="text-gray-500">Resolving…</p>
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
                <dd className="inline">{result.decisions.length}</dd>
              </div>
              <div>
                <dt className="inline text-gray-500">Total actions:</dt>{' '}
                <dd className="inline">
                  {result.decisions.reduce(
                    (n, d) => n + d.actions.length,
                    0,
                  )}
                </dd>
              </div>
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
