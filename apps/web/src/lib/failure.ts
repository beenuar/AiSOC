/**
 * Describing a failed console request in words that point at the right thing.
 *
 * Five banners in this console claimed to be showing data they were not
 * showing. "Connectors API unreachable — showing demo instances so you can
 * explore the interface" rendered above an empty list, because the sample data
 * behind it is gated on demo mode and the list is `data?.connectors ?? []`.
 * "RBAC API unreachable — showing demo roles" was the only thing on the page:
 * `roles` was `undefined`, which suppressed both the skeleton and the empty
 * state. A banner that misdescribes its own state is worse than no banner,
 * because the operator now has a confident diagnosis that is wrong and spends
 * the next hour on the service it named.
 *
 * Two rules come out of that, both enforced by the tests beside each view:
 *
 * **Name the upstream service only when that service is genuinely at fault.**
 * A 422 is the console sending a malformed request — the backend is healthy
 * and saying so. A 401 is an expired session. Neither is an outage, and
 * calling them one is how `EntityRiskQueue` sent somebody to debug a working
 * fusion service (see `describeQueueFailure`, which this generalises).
 *
 * **Say what is on screen.** Every message ends by stating that the thing is
 * *unknown*, not empty — an empty list and an unreadable list look identical
 * and mean opposite things.
 */

import { ApiError } from '@/lib/api';

/**
 * HTTP status behind a rejection, or `null` when it did not come from one.
 *
 * `ApiError` is the shape `lib/api.ts` throws. Several views predate it and
 * hand SWR a local fetcher that throws `new Error('HTTP 503')`, so that string
 * form is parsed too rather than being downgraded to "unrecognised" — the
 * status is the whole basis for telling a console bug from an outage.
 */
export function statusOf(error: unknown): number | null {
  if (error instanceof ApiError) return error.status;
  if (error instanceof Error) {
    const match = /\bHTTP (\d{3})\b/.exec(error.message);
    if (match) return Number(match[1]);
  }
  return null;
}

export interface FailureSubject {
  /**
   * What could not be loaded, as a lowercase noun phrase that reads correctly
   * after "read the" and before "is unknown" — e.g. `'connector list'`.
   */
  subject: string;
  /**
   * The upstream service to name on a 5xx, e.g. `'connectors service'`. Left
   * unset when this surface is served by the API itself; it is never used for
   * a 4xx, because a 4xx is not that service's fault.
   */
  service?: string;
  /**
   * What a 404 means here. Some surfaces are optional deployments, so a 404 is
   * "not installed" rather than a fault. Unset means the generic wording.
   */
  notDeployed?: string;
}

/** Sentence fragment asserting the view is showing nothing, not nothing-found. */
function unknownNotEmpty(subject: string): string {
  return `The ${subject} is unknown, not empty.`;
}

/**
 * One operator-readable sentence for a failed request, plus what is on screen.
 *
 * Deliberately conservative at the bottom: an unrecognised failure repeats the
 * underlying message and blames nothing, because a guessed subsystem is the
 * defect this function exists to prevent.
 */
export function describeApiFailure(error: unknown, subject: FailureSubject): string {
  const what = subject.subject;
  const status = statusOf(error);

  if (status !== null) {
    if (status === 0) {
      return `Cannot reach the API from this browser. ${unknownNotEmpty(what)}`;
    }
    if (status === 401) {
      return `Your session is not authenticated, so nothing was requested. ${unknownNotEmpty(what)} Sign in again.`;
    }
    if (status === 403) {
      return `Not authorised to read the ${what}. ${unknownNotEmpty(what)}`;
    }
    if (status === 404) {
      return subject.notDeployed
        ? `${subject.notDeployed} ${unknownNotEmpty(what)}`
        : `This deployment does not expose the ${what}. ${unknownNotEmpty(what)}`;
    }
    if (status === 422) {
      return `The API rejected this request as malformed, so this is a console bug rather than an outage. ${unknownNotEmpty(what)}`;
    }
    if (status === 429) {
      return `The API is rate-limiting this console. ${unknownNotEmpty(what)} Retrying shortly should succeed.`;
    }
    if (status >= 500) {
      const who = subject.service ?? 'API';
      return `The ${who} returned ${status}. ${unknownNotEmpty(what)}`;
    }
    return `The ${what} request failed with HTTP ${status}. ${unknownNotEmpty(what)}`;
  }

  const detail = error instanceof Error ? error.message : String(error ?? 'unknown error');
  return `Could not load the ${what}: ${detail}. ${unknownNotEmpty(what)}`;
}

/**
 * `fetch` wrapper that throws {@link ApiError} rather than a bare `Error`.
 *
 * The per-view fetchers this replaces threw `new Error('HTTP 404')`, which
 * carried the status in prose only. Callers therefore could not distinguish a
 * console bug from an outage without parsing a message, and none of them did —
 * they all printed "unreachable".
 */
export async function jsonFetcher<T>(url: string): Promise<T> {
  let response: Response;
  try {
    response = await fetch(url);
  } catch (err) {
    // Status 0 is the transport failing: DNS, TLS, CORS, offline. This is the
    // only case where "unreachable" is the honest word.
    throw new ApiError(err instanceof Error ? err.message : 'Network request failed', 0, '');
  }
  if (!response.ok) {
    const body = await response.text().catch(() => '');
    throw new ApiError(`HTTP ${response.status}`, response.status, body);
  }
  return (await response.json()) as T;
}
