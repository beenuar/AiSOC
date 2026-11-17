import { act, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { AUTH_TOKEN_KEY, setActiveTenantId, type RelatedCase, type RelatedCasesResponse } from '@/lib/api';
import { RelatedCasesPanel } from './RelatedCasesPanel';

const fetchMock = vi.fn<typeof fetch>();

function candidate(overrides: Partial<RelatedCase> = {}): RelatedCase {
  return {
    id: 'related-case-id',
    case_number: 'INC-RELATED-002',
    title: 'Lateral movement on the same host',
    severity: 'high',
    status: 'investigating',
    created_at: '2026-11-16T10:00:00Z',
    reason: 'shared_alerts',
    shared_alert_count: 1,
    shared_alert_ids: ['shared-alert-id'],
    shared_observable_count: 1,
    shared_observables: [{ kind: 'host', value: 'finance-workstation' }],
    ...overrides,
  };
}

function response(related: RelatedCase[] = [], hasMore = false) {
  return Response.json({ related, limit: 20, has_more: hasMore } satisfies RelatedCasesResponse);
}

function renderPanel(caseId = 'case-source') {
  const cache = new Map();
  const wrapper = ({ children }: { children: React.ReactNode }) => (
    <SWRConfig value={{ provider: () => cache, dedupingInterval: 0 }}>{children}</SWRConfig>
  );
  return render(<RelatedCasesPanel caseId={caseId} />, { wrapper });
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
  window.localStorage.clear();
  window.localStorage.setItem(AUTH_TOKEN_KEY, 'related-cases-test-session');
  setActiveTenantId('tenant-one');
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('RelatedCasesPanel through the authenticated API client', () => {
  it('waits for a response before reporting that no related cases exist', () => {
    fetchMock.mockImplementation(() => new Promise(() => {}));
    renderPanel();
    expect(screen.getByRole('status')).toHaveTextContent('Finding related cases');
    expect(screen.queryByText('No related cases found')).not.toBeInTheDocument();
  });

  it('loads with credentials and shows the matching evidence and case link', async () => {
    fetchMock.mockResolvedValueOnce(response([candidate()]));
    renderPanel('INC/source?');

    const link = await screen.findByRole('link', { name: /INC-RELATED-002.*Lateral movement/ });
    expect(link).toHaveAttribute('href', '/cases/related-case-id');
    expect(screen.getByRole('link', { name: 'shared-alert-id' })).toHaveAttribute(
      'href', '/alerts/shared-alert-id',
    );
    expect(screen.getByText('1 shared alert')).toBeInTheDocument();
    expect(screen.getByText('1 shared observable')).toBeInTheDocument();
    expect(screen.getByText('finance-workstation')).toBeInTheDocument();
    expect(screen.getByText('host')).toBeInTheDocument();
    expect(screen.getByText('high')).toBeInTheDocument();
    expect(screen.getByText('investigating')).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledWith('/api/v1/cases/INC%2Fsource%3F/related', expect.objectContaining({
      headers: expect.objectContaining({
        Authorization: 'Bearer related-cases-test-session',
        'X-Tenant-Id': 'tenant-one',
      }),
    }));
  });

  it('renders an observable-only match, including informational severity and a closed case', async () => {
    fetchMock.mockResolvedValueOnce(response([candidate({
      case_number: null,
      severity: 'info',
      status: 'closed',
      reason: 'shared_observables',
      shared_alert_count: 0,
      shared_alert_ids: [],
      shared_observables: [{ kind: 'domain', value: '<script>example.test</script>' }],
    })]));
    const { container } = renderPanel();
    expect(await screen.findByText('<script>example.test</script>')).toBeInTheDocument();
    expect(screen.getByText('info')).toBeInTheDocument();
    expect(screen.getByText('closed')).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'shared-alert-id' })).not.toBeInTheDocument();
    expect(container.querySelector('script')).toBeNull();
    expect(screen.getByRole('link', { name: /related-case-id.*Lateral movement/ })).toHaveAttribute(
      'href', '/cases/related-case-id',
    );
  });

  it('reports an empty result only after a successful empty response', async () => {
    fetchMock.mockResolvedValueOnce(response());
    renderPanel();
    expect(await screen.findByText('No related cases found')).toBeInTheDocument();
    expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  });

  it('keeps a failed query distinct from an empty result and retries on request', async () => {
    fetchMock
      .mockResolvedValueOnce(Response.json({ detail: 'Service unavailable' }, { status: 503 }))
      .mockResolvedValueOnce(response([candidate()]));
    renderPanel();
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load related cases');
    expect(screen.queryByText('No related cases found')).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByRole('link', { name: /INC-RELATED-002/ })).toBeInTheDocument();
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('does not show cached matches as current after a failed refresh', async () => {
    fetchMock
      .mockResolvedValueOnce(response([candidate()]))
      .mockResolvedValueOnce(Response.json({ detail: 'Forbidden' }, { status: 403 }));
    renderPanel();
    await screen.findByRole('link', { name: /INC-RELATED-002/ });
    await waitFor(() => expect(screen.getByRole('button', { name: 'Refresh' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: 'Refresh' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Could not load related cases');
    expect(screen.queryByRole('link', { name: /INC-RELATED-002/ })).not.toBeInTheDocument();
    expect(screen.queryByText('No related cases found')).not.toBeInTheDocument();
  });

  it('labels both result and evidence truncation with the actual counts', async () => {
    fetchMock.mockResolvedValueOnce(response([candidate({
      shared_alert_count: 12,
      shared_observable_count: 15,
    })], true));
    renderPanel();
    expect(await screen.findByText(/Showing 1 match; additional related cases exist/)).toBeInTheDocument();
    expect(screen.getByText('Showing 1 of 12 shared alerts.')).toBeInTheDocument();
    expect(screen.getByText('Showing 1 of 15 shared observables.')).toBeInTheDocument();
  });

  it('clears the previous case evidence while the next case is loading', async () => {
    fetchMock
      .mockResolvedValueOnce(response([candidate()]))
      .mockImplementationOnce(() => new Promise(() => {}));
    const view = renderPanel('first-case');
    await screen.findByRole('link', { name: /INC-RELATED-002/ });
    view.rerender(<RelatedCasesPanel caseId="second-case" />);
    expect(screen.queryByRole('link', { name: /INC-RELATED-002/ })).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('Finding related cases');
    await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/cases/second-case/related', expect.anything(),
    ));
  });

  it('does not reuse another tenant cache entry for the same case identifier', async () => {
    fetchMock.mockResolvedValueOnce(response([candidate()])).mockResolvedValueOnce(response());
    const view = renderPanel();
    await screen.findByRole('link', { name: /INC-RELATED-002/ });
    await act(async () => {
      setActiveTenantId('tenant-two');
      view.rerender(<RelatedCasesPanel caseId="case-source" />);
    });
    const panel = screen.getByRole('region', { name: 'Related cases' });
    expect(await within(panel).findByText('No related cases found')).toBeInTheDocument();
    expect(within(panel).queryByRole('link', { name: /INC-RELATED-002/ })).not.toBeInTheDocument();
    expect(fetchMock).toHaveBeenLastCalledWith('/api/v1/cases/case-source/related', expect.objectContaining({
      headers: expect.objectContaining({ 'X-Tenant-Id': 'tenant-two' }),
    }));
  });
});
