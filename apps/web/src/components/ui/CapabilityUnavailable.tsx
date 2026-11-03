import { clsx } from 'clsx';

/**
 * Whether a failed read means the capability is not in this deployment.
 *
 * AiSOC ships two profiles. CORE is sixteen services; several capabilities —
 * the entity graph on Neo4j, the event lake on ClickHouse, file integrity
 * monitoring on osquery — belong to `full` and are legitimately absent from
 * a CORE install. Their routes answer **503**, which is the API saying the
 * backing store is not reachable, not that a request went wrong.
 *
 * Narrow on purpose. A 500 is a service that is present and threw, and a
 * transport failure is a request that never arrived; both are faults a
 * retry can reasonably be offered for. Treating either as "not deployed"
 * would tell an operator to stop looking at something genuinely broken.
 *
 * Read off the `status` property rather than with `instanceof ApiError`.
 * Three callers reach here with errors built in three places — `request()`,
 * the osquery client, and whatever a test substitutes — and an identity
 * check against one class quietly answers `false` for the other two. This
 * also keeps a UI primitive from importing the API module.
 */
export function isCapabilityAbsent(error: unknown): boolean {
  return httpStatusOf(error) === 503;
}

function httpStatusOf(error: unknown): number | undefined {
  if (error && typeof error === 'object' && 'status' in error) {
    const status = (error as { status?: unknown }).status;
    if (typeof status === 'number') return status;
  }
  return undefined;
}

interface CapabilityUnavailableProps {
  /** What is missing, as a sentence subject: "The entity graph". */
  capability: string;
  /** The `full`-profile component behind it: "Neo4j". */
  service: string;
  /** The failure, shown so whoever is debugging keeps the status. */
  detail?: unknown;
  className?: string;
}

/**
 * The panel for a capability that is not part of this deployment.
 *
 * Written because `/graph` rendered a generic *"Couldn't load graph — Try
 * again or check the service status. API 503"* over a condition where
 * retrying is the one action guaranteed not to work, and then promised
 * *"The graph auto-refreshes every 30s as new events arrive"* underneath
 * it. The correct diagnosis already existed one service away:
 * `services/agents/app/tools/graph.py` logs "the entity graph runs in the
 * `full` profile and is not part of this deployment".
 *
 * Three things this does that `ErrorState` deliberately does not:
 *
 * * it names the real cause and the command that fixes it;
 * * it offers **no retry**, because there is nothing to retry into;
 * * it says the screen is not a report of zero — the sentence
 *   `/purple-team` and `/honeytokens` already use, so an analyst does not
 *   read an absent capability as a clean result.
 */
export function CapabilityUnavailable({
  capability,
  service,
  detail,
  className,
}: CapabilityUnavailableProps) {
  const status = httpStatusOf(detail);

  return (
    <div
      className={clsx(
        'rounded-xl border border-amber-500/25 bg-amber-500/5 px-6 py-6 text-sm',
        className,
      )}
      role="status"
    >
      <p className="font-medium text-amber-200">{capability} is not part of this deployment</p>
      <p className="mt-2 max-w-xl text-amber-200/70">
        {capability} is backed by {service}, which runs in the{' '}
        <code className="rounded bg-amber-500/10 px-1 py-0.5 font-mono text-[12px]">`full`</code>{' '}
        profile and is not part of this deployment. This is not a report that there is nothing to
        show — nothing was read.
      </p>
      <p className="mt-2 max-w-xl text-amber-200/60">
        Bring it up with{' '}
        <code className="rounded bg-amber-500/10 px-1 py-0.5 font-mono text-[12px]">make up-full</code>
        , then reload this page.
      </p>
      {status !== undefined && (
        <p className="mt-3 font-mono text-[11px] text-amber-300/50">HTTP {status}</p>
      )}
    </div>
  );
}
