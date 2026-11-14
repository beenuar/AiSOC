/**
 * The source-address class must render what the dataset said and nothing
 * more.
 *
 * Depth plan wave 2, item 1.6. Three of the five classes ship with no
 * records, because no source for them survived the licence check, so an
 * alert with no class is the ordinary case rather than an edge one. The
 * failure mode this file guards is the repository's oldest: rendering an
 * absent measurement as a confident value. A chip reading "not an
 * anonymizer" on an address the dataset has never seen would be exactly
 * that, and an analyst would reasonably treat it as evidence.
 *
 * SWR and next/link are mocked at the module boundary, following
 * `InvestigationRail.test.tsx`, so the rail renders from a fixed envelope
 * without a network call.
 */
import { describe, expect, it, vi, beforeEach } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/react';

const swrState = vi.hoisted(() => ({
  data: undefined as unknown,
  error: undefined as unknown,
  isLoading: false,
}));

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrState.data,
    error: swrState.error,
    isLoading: swrState.isLoading,
  }),
}));

vi.mock('next/link', () => ({
  __esModule: true,
  default: ({
    href,
    children,
    ...rest
  }: {
    href: string;
    children: React.ReactNode;
  } & React.AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a href={typeof href === 'string' ? href : '#'} {...rest}>
      {children}
    </a>
  ),
}));

import { InvestigationRail } from './InvestigationRail';
import type { Alert } from '@/lib/api';

/**
 * Render the rail and switch to the Details face.
 *
 * The rail opens on the story view; every structured section, including
 * this one, lives behind the Details tab. Asserting without the click
 * would pass only if the section were on the story face, which would be
 * the wrong place for it.
 */
function renderDetails() {
  render(<InvestigationRail alertId="ALERT-IPCLASS-1" onClose={vi.fn()} />);
  fireEvent.click(screen.getByRole('tab', { name: 'Details' }));
}

function envelope(extra: Partial<Alert>): Alert {
  return {
    id: 'ALERT-IPCLASS-1',
    tenantId: 't-1',
    title: 'Sign-in from an unfamiliar network',
    severity: 'high',
    status: 'new',
    source: 'okta',
    createdAt: '2026-11-01T00:00:00Z',
    updatedAt: '2026-11-01T00:00:00Z',
    ...extra,
  } as Alert;
}

describe('source address class on the investigation rail', () => {
  beforeEach(() => {
    swrState.error = undefined;
    swrState.isLoading = false;
  });

  it('names a Tor exit relay and the dataset version that said so', () => {
    swrState.data = envelope({
      srcIpClass: 'tor_exit',
      srcIpClassDatasetVersion: '2026.11.01',
    });
    renderDetails();
    expect(screen.getByText('Tor exit relay')).toBeInTheDocument();
    expect(screen.getByText(/dataset 2026\.11\.01/)).toBeInTheDocument();
  });

  it('renders nothing at all when the dataset had no entry', () => {
    swrState.data = envelope({});
    renderDetails();
    expect(screen.queryByText('Source address')).not.toBeInTheDocument();
    // The specific regression: an absent class must never become a
    // reassurance. Any wording telling the analyst the address is clean is
    // a claim the dataset cannot support.
    expect(screen.queryByText(/not an anonymizer/i)).not.toBeInTheDocument();
  });

  it('shows the class with no version rather than dropping the class', () => {
    // A row written before the version column existed still carries a real
    // class. Dropping the chip over a cosmetic gap would lose a true
    // finding.
    swrState.data = envelope({ srcIpClass: 'hosting_provider' });
    renderDetails();
    expect(screen.getByText('Hosting provider')).toBeInTheDocument();
    expect(screen.queryByText(/^dataset /)).not.toBeInTheDocument();
  });

  it('ignores a class the console does not know', () => {
    // An unrecognised value on a security surface reads as a finding nobody
    // can explain; `normalizeAlert` drops it, and the rail must too.
    swrState.data = envelope({ srcIpClass: 'something_new' as Alert['srcIpClass'] });
    renderDetails();
    expect(screen.queryByText('Source address')).not.toBeInTheDocument();
  });
});
