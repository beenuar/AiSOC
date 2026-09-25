/**
 * A banner that misdescribes its own state sends the operator to debug the
 * wrong thing, which is worse than no banner.
 *
 * Five surfaces printed "<X> API unreachable — showing demo <things>" for
 * every failure. Four of them were showing nothing at all, and none of them
 * had any basis for the word "unreachable": the status was either discarded by
 * the fetcher or never consulted. These tests pin the two rules that fall out
 * of that — name the upstream service only when it is genuinely at fault, and
 * always say the data is *unknown* rather than empty.
 */

import { describe, expect, it } from 'vitest';
import { ApiError } from '@/lib/api';
import { describeApiFailure, statusOf } from '@/lib/failure';

const SUBJECT = { subject: 'connector list', service: 'connectors service' };

describe('statusOf', () => {
  it('reads the status off an ApiError', () => {
    expect(statusOf(new ApiError('boom', 503, ''))).toBe(503);
    expect(statusOf(new ApiError('offline', 0, ''))).toBe(0);
  });

  it('parses the status out of the legacy fetchers that only threw a string', () => {
    // `RBACView` and `PlaybooksView` threw `new Error('HTTP 404')`, and
    // `safeFetcher` throws `HTTP 501 Not Implemented — …`. Downgrading those
    // to "unrecognised" would lose the only signal that distinguishes a
    // console bug from an outage.
    expect(statusOf(new Error('HTTP 404'))).toBe(404);
    expect(statusOf(new Error('HTTP 501 Not Implemented — scaffolded'))).toBe(501);
  });

  it('returns null rather than guessing when there is no status', () => {
    expect(statusOf(new Error('Failed to fetch'))).toBeNull();
    expect(statusOf('something')).toBeNull();
    expect(statusOf(undefined)).toBeNull();
  });
});

describe('describeApiFailure — blames only what is actually at fault', () => {
  it('calls a 422 a console bug and does not name the service', () => {
    const message = describeApiFailure(new ApiError('API 422', 422, ''), SUBJECT);

    expect(message).toMatch(/console bug rather than an outage/i);
    expect(message).not.toMatch(/connectors service/i);
    expect(message).not.toMatch(/unreachable/i);
  });

  it('names the service only on a 5xx, which is when it really did fail', () => {
    expect(describeApiFailure(new ApiError('API 503', 503, ''), SUBJECT)).toMatch(
      /connectors service returned 503/i,
    );
  });

  it('falls back to "API" when the surface is served by the API itself', () => {
    const message = describeApiFailure(new ApiError('API 500', 500, ''), { subject: 'role list' });

    expect(message).toMatch(/API returned 500/i);
  });

  it('reports a transport failure as unreachable, which is what status 0 means', () => {
    expect(describeApiFailure(new ApiError('Network error', 0, ''), SUBJECT)).toMatch(
      /cannot reach the api/i,
    );
  });

  it('distinguishes an unauthenticated session from an authorisation refusal', () => {
    // Different fixes: sign in again, versus ask for the permission.
    expect(describeApiFailure(new ApiError('API 401', 401, ''), SUBJECT)).toMatch(/sign in again/i);
    expect(describeApiFailure(new ApiError('API 403', 403, ''), SUBJECT)).toMatch(/not authorised/i);
  });

  it('treats a 404 as "not deployed here" rather than an outage', () => {
    expect(describeApiFailure(new ApiError('API 404', 404, ''), SUBJECT)).toMatch(
      /does not expose/i,
    );
  });

  it('uses the caller supplied wording for an optional deployment', () => {
    const message = describeApiFailure(new ApiError('API 404', 404, ''), {
      subject: 'FIM event log',
      notDeployed: 'This deployment does not run the osquery service.',
    });

    expect(message).toMatch(/does not run the osquery service/i);
  });

  it('says a rate limit is temporary rather than a fault', () => {
    expect(describeApiFailure(new ApiError('API 429', 429, ''), SUBJECT)).toMatch(
      /rate-limiting/i,
    );
  });

  it('stays vague rather than guessing a subsystem for an unrecognised failure', () => {
    const message = describeApiFailure(new Error('boom'), SUBJECT);

    expect(message).toContain('boom');
    expect(message).not.toMatch(/connectors service/i);
    expect(message).not.toMatch(/unreachable/i);
  });

  it('never claims the data is empty, for any status', () => {
    // An empty list and an unreadable list look identical and mean opposite
    // things. Every message has to close that gap.
    for (const status of [0, 401, 403, 404, 422, 429, 500, 503, 418]) {
      const message = describeApiFailure(new ApiError(`API ${status}`, status, ''), SUBJECT);
      expect(
        /unknown, not empty|not authorised|does not expose|sign in again/i.test(message),
        `HTTP ${status} produced: ${message}`,
      ).toBe(true);
    }
  });

  it('never says "demo" on any path, because these run outside the demo', () => {
    const inputs: unknown[] = [
      new ApiError('API 422', 422, ''),
      new ApiError('API 500', 500, ''),
      new ApiError('Network error', 0, ''),
      new Error('boom'),
    ];
    for (const err of inputs) {
      expect(describeApiFailure(err, SUBJECT)).not.toMatch(/demo/i);
    }
  });
});
