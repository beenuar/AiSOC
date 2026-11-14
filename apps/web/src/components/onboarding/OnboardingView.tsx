'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import { useRouter, useSearchParams } from 'next/navigation';
import { motion } from 'framer-motion';
import toast from 'react-hot-toast';
import useSWR from 'swr';

import {
  AddConnectorModal,
  CATEGORY_LABEL,
  CATEGORY_ORDER,
  MOST_TEAMS_PICK,
} from '@/components/connectors/AddConnectorModal';
import { connectorsApi, type ConnectorCatalogEntry } from '@/lib/api';
import { clsx } from 'clsx';

/**
 * Dedicated /onboarding surface for first-time tenants.
 *
 * The plan calls this out as a separate route from /connectors because the
 * goals are different: /connectors is an inventory dashboard, while
 * /onboarding is a getting-started funnel that has to do four things in
 * order:
 *
 *   1. Tell a brand-new operator what they're about to do.
 *   2. Show them the highest-leverage 8–10 connectors first ("Most teams pick"),
 *      so they don't have to read a 50-row catalog before clicking anything.
 *   3. Let them pick a category if their tool isn't in the curated row.
 *   4. Hand them off to the same {@link AddConnectorModal} the rest of the
 *      app uses, including its three-step wizard (pick → configure →
 *      verify-data-flowing) and the AI troubleshooter on test failure.
 *
 * Once the tenant already has a connected, healthy connector we collapse
 * the funnel into a "you're done" state with a link into the main app —
 * showing the same big picker again would be misleading.
 */
export function OnboardingView() {
  // Catalog drives the hero pills and curated row. Re-using the same SWR
  // key as the modal lets a single network round-trip serve both surfaces.
  // `connectorsApi.catalog()` returns a `{ connectors: [...] }` envelope, so
  // we unwrap to a flat array here for the rest of this component.
  const { data: catalogData, error: catalogError } = useSWR(
    'connectors-catalog',
    () => connectorsApi.catalog(),
    { revalidateOnFocus: false },
  );
  const catalog: ConnectorCatalogEntry[] | undefined = catalogData?.connectors;

  // Live list of the tenant's existing connector instances. We poll lightly
  // so once verify-data-flowing flips a connector to "healthy" the
  // onboarding screen reflects it without a full reload.
  const { data: existingData, mutate: mutateExisting } = useSWR(
    'connectors-list',
    () => connectorsApi.list(),
    { refreshInterval: 5000, revalidateOnFocus: false },
  );
  const existing = existingData?.connectors;

  const [modalOpen, setModalOpen] = useState(false);
  // The picker can be primed with a specific connector class so clicking a
  // "Most teams pick" tile drops the operator straight onto the configure
  // step for that vendor instead of forcing them to scroll the picker again.
  const [primedConnectorId, setPrimedConnectorId] = useState<string | null>(null);
  const [activeCategory, setActiveCategory] = useState<string | null>(null);

  // Reset transient picker state every time the modal closes, so a second
  // open never starts with a stale connector primed or category pre-selected.
  // We do this on the falling edge so the modal still sees the correct
  // primedConnectorId / activeCategory while it's open.
  useEffect(() => {
    if (!modalOpen) {
      setPrimedConnectorId(null);
      setActiveCategory(null);
    }
  }, [modalOpen]);

  // ── OAuth callback landing handler ──────────────────────────────────────
  //
  // The hosted OAuth flow (Workstream 2) bounces the operator to
  // /api/v1/oauth/start → IdP → /api/v1/oauth/callback → here, with one of
  // two query strings appended to ``return_to``:
  //
  //   * Success: ``?oauth_success=1&connector_id=…&connector_type=…``
  //   * Error:   ``?oauth_error=<code>&oauth_message=<short message>``
  //
  // We surface the result as a toast, force-refresh the connector list so
  // the right-rail counts and "Connected" badges flip immediately, and
  // strip the query params from the URL so a refresh doesn't re-fire the
  // toast. We deliberately don't auto-open the modal at the verify step
  // here — by the time the operator lands back on /onboarding the
  // connector row already exists and the poller is the source of truth
  // for whether data is flowing. The Stats row + the next time they open
  // the picker will both reflect the new connector.
  const router = useRouter();
  const searchParams = useSearchParams();
  useEffect(() => {
    const success = searchParams.get('oauth_success');
    const errorCode = searchParams.get('oauth_error');
    const errorMessage = searchParams.get('oauth_message');
    const connectorType = searchParams.get('connector_type');
    if (!success && !errorCode) return;

    if (success === '1') {
      toast.success(
        connectorType
          ? `Connected ${connectorType}. Watching for live events…`
          : 'Connector OAuth complete.',
      );
      void mutateExisting();
    } else if (errorCode) {
      toast.error(
        errorMessage
          ? `OAuth failed: ${errorMessage}`
          : `OAuth failed (${errorCode}). Check the connector logs.`,
        { duration: 8000 },
      );
    }
    // Strip the params so a hard refresh doesn't re-toast and so the URL
    // looks clean in the address bar. router.replace() preserves
    // scroll position, which is what we want here.
    router.replace('/onboarding');
    // We intentionally re-run only when the search params change.
    // mutateExisting is stable across renders.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [searchParams]);

  const popular = useMemo(() => {
    if (!catalog) return [];
    const byId = new Map(catalog.map((e) => [e.connector_id, e]));
    return MOST_TEAMS_PICK.map((id) => byId.get(id)).filter(
      (e): e is ConnectorCatalogEntry => Boolean(e),
    );
  }, [catalog]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const e of catalog ?? []) {
      const c = e.category || 'other';
      counts[c] = (counts[c] ?? 0) + 1;
    }
    return counts;
  }, [catalog]);

  const totalConnectorTypes = catalog?.length ?? 0;
  const connectedCount = existing?.length ?? 0;
  // `active` is the frontend ConnectorStatus that maps from backend
  // `health_status === 'healthy' && is_enabled === true`. That's exactly
  // what "the connector is sending data we trust" means here.
  const healthyCount = useMemo(
    () => (existing ?? []).filter((c) => c.status === 'active').length,
    [existing],
  );

  // Treat the tenant as "done with onboarding" once at least one connector
  // has actually flipped to healthy. A connector in the catalog but stuck
  // in `pending` doesn't count — they haven't seen data yet, so the funnel
  // is still relevant.
  const onboardingComplete = healthyCount > 0;

  const openPicker = (connectorId?: string, category?: string) => {
    if (connectorId) setPrimedConnectorId(connectorId);
    if (category) setActiveCategory(category);
    setModalOpen(true);
  };

  return (
    <div className="max-w-5xl mx-auto px-6 py-10">
      {/* Hero */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: 'easeOut' }}
        className="mb-10"
      >
        <p className="text-xs uppercase tracking-wider text-blue-400/80 mb-2">
          Getting started
        </p>
        <h1 className="text-3xl font-semibold text-gray-100 mb-3">
          Connect your first security tool
        </h1>
        <p className="text-gray-400 max-w-2xl leading-relaxed">
          AiSOC pulls signals from the tools you already run and stitches them into a single
          investigation timeline. Most teams start with their endpoint or identity provider —
          you can wire up the rest later.
        </p>

        {/* Snapshot row — gives the operator a sense of progress without
            looking like a real dashboard. We only show it once we have a
            catalog so it never flickers in with zeros. */}
        {totalConnectorTypes > 0 && (
          <div className="mt-6 grid grid-cols-3 gap-3 max-w-xl">
            <Stat label="Available" value={totalConnectorTypes} />
            <Stat label="Connected" value={connectedCount} />
            <Stat
              label="Sending data"
              value={healthyCount}
              tone={healthyCount > 0 ? 'good' : 'neutral'}
            />
          </div>
        )}
      </motion.div>

      {/* Done state */}
      {onboardingComplete && (
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
          className="mb-10 rounded-2xl border border-green-500/20 bg-green-500/5 p-6"
        >
          <div className="flex items-start justify-between gap-4">
            <div>
              <h2 className="text-lg font-medium text-green-200 mb-1">
                You&rsquo;re live — events are flowing
              </h2>
              <p className="text-sm text-green-200/70">
                {healthyCount} connector{healthyCount === 1 ? '' : 's'} sending data. Detections,
                cases, and the assistant are all reading from your live signal now.
              </p>
            </div>
            <Link
              href="/cases"
              className="shrink-0 text-sm bg-green-600/90 hover:bg-green-500 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Open cases →
            </Link>
          </div>
        </motion.div>
      )}

      {/* Catalog error */}
      {catalogError && (
        <div className="mb-8 text-sm text-red-300 bg-red-500/10 border border-red-500/20 rounded-lg p-4">
          Failed to load connector catalog. Refresh the page to try again — your existing
          connectors are unaffected.
        </div>
      )}

      {/* Most teams pick */}
      {popular.length > 0 && (
        <section className="mb-10">
          <div className="flex items-baseline justify-between mb-3">
            <h2 className="text-sm font-medium text-gray-300 uppercase tracking-wider">
              Most teams pick
            </h2>
            <button
              type="button"
              onClick={() => openPicker()}
              className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
            >
              Browse all {totalConnectorTypes} connectors →
            </button>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
            {popular.map((entry) => (
              <PopularTile
                key={entry.connector_id}
                entry={entry}
                onClick={() => openPicker(entry.connector_id)}
                        connected={
                          (existing ?? []).some((c) => c.type === entry.connector_id)
                        }
              />
            ))}
          </div>
        </section>
      )}

      {/* Category pills */}
      {totalConnectorTypes > 0 && (
        <section className="mb-12">
          <h2 className="text-sm font-medium text-gray-300 uppercase tracking-wider mb-3">
            Or browse by category
          </h2>
          <div className="flex flex-wrap gap-2">
            {CATEGORY_ORDER.filter((c) => (categoryCounts[c] ?? 0) > 0).map((c) => (
              <button
                key={c}
                type="button"
                onClick={() => openPicker(undefined, c)}
                className={clsx(
                  'px-3 py-2 rounded-lg text-sm border transition-colors',
                  'border-gray-800 bg-gray-900 text-gray-200 hover:border-blue-500/40 hover:bg-gray-900/80',
                  activeCategory === c && 'border-blue-500/60 bg-blue-500/10',
                )}
              >
                {CATEGORY_LABEL[c] ?? c}
                <span className="ml-2 text-xs text-gray-500">{categoryCounts[c]}</span>
              </button>
            ))}
          </div>
        </section>
      )}

      {/* Footnote: where to go next once connected.
       *
       * The push-ingest docs live on the Docusaurus site (separate origin from
       * the Next.js app), so we link out to GH Pages rather than to a path
       * under tryaisoc.com that would 404. The detections route is singular
       * (/detection) — earlier copy here said /detections and 404'd. */}
      <section className="mt-12 grid sm:grid-cols-2 gap-4">
        <NextStepCard
          title="Bring your own data"
          body="No connector for your tool? Push raw events into AiSOC over a tenant-scoped HTTPS endpoint."
          href="https://beenuar.github.io/AiSOC/docs/operations/credentials/"
          cta="Push-ingest docs"
        />
        <NextStepCard
          title="Run a detection"
          body="Already connected? Validate the pipeline end-to-end with a synthetic detection."
          href="/detection"
          cta="Open detections"
        />
      </section>

      {/* Modal — same wizard the /connectors page uses, primed with the
          tile the operator clicked so the picker step is essentially
          skipped for the curated path. */}
      <AddConnectorModal
        open={modalOpen}
        onClose={() => setModalOpen(false)}
        primedConnectorId={primedConnectorId}
        activeCategory={activeCategory}
        onCreated={() => {
          // Refresh the right-rail counts immediately. The verify step
          // inside the modal handles its own polling for the green check.
          void mutateExisting();
        }}
      />
    </div>
  );
}

// ─── Pieces ──────────────────────────────────────────────────────────────────

function Stat({
  label,
  value,
  tone = 'neutral',
}: {
  label: string;
  value: number;
  tone?: 'neutral' | 'good';
}) {
  return (
    <div
      className={clsx(
        'rounded-xl border px-4 py-3',
        tone === 'good'
          ? 'border-green-500/20 bg-green-500/5'
          : 'border-gray-800 bg-gray-900/60',
      )}
    >
      <div className="text-xs text-gray-500 uppercase tracking-wider">{label}</div>
      <div
        className={clsx(
          'text-2xl font-semibold mt-0.5',
          tone === 'good' ? 'text-green-200' : 'text-gray-100',
        )}
      >
        {value}
      </div>
    </div>
  );
}

function PopularTile({
  entry,
  onClick,
  connected,
}: {
  entry: ConnectorCatalogEntry;
  onClick: () => void;
  connected: boolean;
}) {
  // Surface "OAuth one-click" on the tile so the operator knows which curated
  // picks won't ask them to paste static credentials before they get in.
  // Mirrors the same emerald palette used inside the modal's picker step so
  // the visual signal is consistent end-to-end. We hide the badge once the
  // connector is connected (the "Connected" badge is more useful at that
  // point) to avoid stacking two badges on a small tile.
  const supportsHostedOAuth = Boolean(entry.oauth?.supported_in_hosted);
  return (
    <button
      type="button"
      onClick={onClick}
      className="group relative text-left rounded-xl border border-gray-800 bg-gray-900/60 hover:bg-gray-900 hover:border-blue-500/40 px-4 py-4 transition-colors"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="text-sm font-medium text-gray-100 truncate">
            {entry.connector_name}
          </div>
          <div className="text-xs text-gray-500 mt-0.5 capitalize">
            {CATEGORY_LABEL[entry.category] ?? entry.category}
          </div>
        </div>
        {connected ? (
          <span
            className="shrink-0 inline-flex items-center text-[10px] uppercase tracking-wider text-green-300 bg-green-500/10 border border-green-500/20 px-1.5 py-0.5 rounded"
            title="You already have an instance of this connector"
          >
            Connected
          </span>
        ) : supportsHostedOAuth ? (
          <span
            className="shrink-0 inline-flex items-center text-[10px] uppercase tracking-wider text-emerald-300 bg-emerald-500/10 border border-emerald-500/30 px-1.5 py-0.5 rounded"
            title="Click-and-connect via OAuth — no API tokens to paste"
          >
            OAuth one-click
          </span>
        ) : null}
      </div>
      {entry.description && (
        <p className="text-xs text-gray-500 mt-2 line-clamp-2">{entry.description}</p>
      )}
    </button>
  );
}

function NextStepCard({
  title,
  body,
  href,
  cta,
}: {
  title: string;
  body: string;
  href: string;
  cta: string;
}) {
  // Cross-origin links (docs site on GH Pages) need a real <a> with
  // target=_blank — next/link is for in-app routing only. Keeping the same
  // markup otherwise so the visual treatment stays identical.
  const isExternal = /^https?:\/\//i.test(href);
  const className =
    'block rounded-xl border border-gray-800 bg-gray-900/40 hover:bg-gray-900 hover:border-blue-500/40 p-5 transition-colors';
  const inner = (
    <>
      <div className="text-sm font-medium text-gray-100 mb-1">{title}</div>
      <p className="text-sm text-gray-500 mb-3 leading-relaxed">{body}</p>
      <span className="text-xs text-blue-400 group-hover:text-blue-300">{cta} →</span>
    </>
  );
  if (isExternal) {
    return (
      <a
        href={href}
        className={className}
        target="_blank"
        rel="noopener noreferrer"
      >
        {inner}
      </a>
    );
  }
  return (
    <Link href={href} className={className}>
      {inner}
    </Link>
  );
}
