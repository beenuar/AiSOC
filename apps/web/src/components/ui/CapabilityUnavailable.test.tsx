/**
 * A view whose backing service is not in this deployment must not offer Retry.
 *
 * `/graph` rendered *"Couldn't load graph … **Try again** or check the
 * service status. API 503 — /api/v1/graph"*, and immediately below it
 * *"The graph auto-refreshes every 30s as new events arrive"* — a promise
 * it cannot keep. The real cause is that Neo4j is a `full`-profile service
 * and the deployment is CORE. `services/agents/app/tools/graph.py` already
 * answers the identical condition in one sentence: *"the entity graph runs
 * in the `full` profile and is not part of this deployment."* `/fim` had
 * the same shape ("Could not load FIM summary").
 *
 * Retry is the one action guaranteed not to work, so the test asserts its
 * absence as well as the sentence. `/purple-team` and `/honeytokens`
 * already get this right — *"This is not a report of zero coverage"* — and
 * are the pattern.
 */
import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import { ApiError } from '@/lib/api';
import { CapabilityUnavailable, isCapabilityAbsent } from './CapabilityUnavailable';

describe('telling a missing capability from a broken one', () => {
  it('reads a 503 as the capability not being deployed', () => {
    expect(isCapabilityAbsent(new ApiError('API 503 Service Unavailable — /api/v1/graph', 503, ''))).toBe(true);
  });

  it('does not read a 500 as a missing capability', () => {
    // A service that is present and threw is a fault, and a retry is a
    // reasonable thing to offer for it.
    expect(isCapabilityAbsent(new ApiError('API 500 — /api/v1/graph', 500, ''))).toBe(false);
  });

  it('does not read a transport failure as a missing capability', () => {
    expect(isCapabilityAbsent(new TypeError('Failed to fetch'))).toBe(false);
    expect(isCapabilityAbsent(undefined)).toBe(false);
  });
});

describe('what the panel says', () => {
  it('names the profile the service runs in and the command that brings it up', () => {
    render(
      <CapabilityUnavailable
        capability="The entity graph"
        service="Neo4j"
        detail={new ApiError('API 503 — /api/v1/graph', 503, '')}
      />,
    );

    // The profile name sits in its own <code>, so the sentence around it is
    // several text nodes — match the element, not the concatenation.
    expect(screen.getByText('`full`')).toBeTruthy();
    expect(screen.getByText(/profile and is not part of this deployment/)).toBeTruthy();
    expect(screen.getByText('make up-full')).toBeTruthy();
  });

  it('offers no Retry, because retrying cannot work', () => {
    render(
      <CapabilityUnavailable
        capability="The entity graph"
        service="Neo4j"
        detail={new ApiError('API 503 — /api/v1/graph', 503, '')}
      />,
    );

    expect(screen.queryByRole('button', { name: /try again|retry/i })).toBeNull();
    expect(screen.queryByText(/try again/i)).toBeNull();
  });

  it('says this is not a report of zero, like its correct neighbours do', () => {
    render(<CapabilityUnavailable capability="File integrity monitoring" service="osquery" detail={undefined} />);

    expect(screen.getByText(/not a report that/i)).toBeTruthy();
  });

  it('keeps the underlying status visible for whoever is debugging it', () => {
    render(
      <CapabilityUnavailable
        capability="The entity graph"
        service="Neo4j"
        detail={new ApiError('API 503 Service Unavailable — /api/v1/graph', 503, '')}
      />,
    );

    expect(screen.getByText(/503/)).toBeTruthy();
  });
});
