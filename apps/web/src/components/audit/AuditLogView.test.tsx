import { describe, expect, it, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// WS-H3 — pin the export-button wiring on AuditLogView. The component exposes
// two affordances ("Export CSV" / "Export PDF (HTML)") that must:
//   1. forward the *currently filtered* view to auditApi.{exportCsv,exportHtml}
//   2. trigger a real browser download / new-tab open
//   3. disable themselves while a request is inflight or when 0 rows match
//
// We mock SWR (so we control the data the table sees), the auditApi exports,
// react-hot-toast (so we don't need a portal root), and the URL/window
// sinks (so the download anchor + window.open don't blow up jsdom).

const swrCalls = vi.hoisted(() => new Map<string, unknown>());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: string) => {
    const data = swrCalls.get(key);
    return {
      data,
      error: undefined,
      isLoading: false,
      mutate: vi.fn(async () => undefined),
    };
  },
}));

const exportCsvMock = vi.hoisted(() => vi.fn());
const exportHtmlMock = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({
  __esModule: true,
  // Real ApiError surface so the component's `instanceof ApiError` branches
  // continue to match.
  ApiError: class ApiError extends Error {
    status: number;
    body: string;
    constructor(message: string, status = 0, body = '') {
      super(message);
      this.name = 'ApiError';
      this.status = status;
      this.body = body;
    }
  },
  auditApi: {
    exportCsv: exportCsvMock,
    exportHtml: exportHtmlMock,
  },
  // The view's SWR fetcher. It used to be a module-local arrow that called
  // `fetch(url, { credentials: 'include' })`, i.e. no credential the API
  // reads; SWR itself is mocked below, so this only has to exist.
  authedFetcher: vi.fn(),
}));

const toastSuccess = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: toastSuccess, error: toastError },
}));

import { AuditLogView } from './AuditLogView';

// A tiny helper to register the SWR fixture for the default page-1 query.
function seedAuditPage(items: unknown[], total = items.length) {
  // Component builds `/api/v1/audit?page=1&page_size=50` when no filters set.
  swrCalls.set('/api/v1/audit?page=1&page_size=50', {
    items,
    total,
    page: 1,
    page_size: 50,
    total_pages: total === 0 ? 1 : Math.ceil(total / 50),
  });
}

const sampleEvent = {
  id: 'evt-1',
  tenant_id: 't1',
  actor_id: 'u1',
  actor_email: 'admin@acme.io',
  actor_ip: '10.0.1.12',
  action: 'cases:create',
  resource: 'case',
  resource_id: 'c-0001',
  changes: { title: 'Suspicious lateral movement' },
  created_at: new Date('2026-05-01T12:00:00Z').toISOString(),
};

beforeEach(() => {
  swrCalls.clear();
  exportCsvMock.mockReset();
  exportHtmlMock.mockReset();
  toastSuccess.mockReset();
  toastError.mockReset();

  // jsdom doesn't implement these — the component depends on them for the
  // CSV anchor click and the HTML new-tab open. Stub them as no-ops so we
  // can assert the call sequence rather than fight the environment.
  if (typeof URL.createObjectURL === 'undefined') {
    Object.defineProperty(URL, 'createObjectURL', {
      value: vi.fn(() => 'blob:mock-url'),
      writable: true,
    });
  } else {
    URL.createObjectURL = vi.fn(() => 'blob:mock-url') as unknown as typeof URL.createObjectURL;
  }
  if (typeof URL.revokeObjectURL === 'undefined') {
    Object.defineProperty(URL, 'revokeObjectURL', {
      value: vi.fn(),
      writable: true,
    });
  } else {
    URL.revokeObjectURL = vi.fn() as unknown as typeof URL.revokeObjectURL;
  }
  // window.open returns a fake window so the success branch fires.
  vi.spyOn(window, 'open').mockImplementation(() => ({}) as unknown as Window);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('AuditLogView export buttons', () => {
  it('renders the CSV and HTML export buttons next to the title', () => {
    seedAuditPage([sampleEvent]);

    render(<AuditLogView />);

    expect(screen.getByRole('heading', { level: 1, name: /audit log/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /export csv/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /export pdf \(html\)/i })).toBeInTheDocument();
  });

  it('calls auditApi.exportCsv with the empty filter set when nothing is filtered', async () => {
    seedAuditPage([sampleEvent]);
    exportCsvMock.mockResolvedValueOnce({
      body: 'id,action\nevt-1,cases:create\n',
      filename: 'aisoc-audit-20260501T120000Z.csv',
    });

    render(<AuditLogView />);

    await userEvent.click(screen.getByRole('button', { name: /export csv/i }));

    await waitFor(() => expect(exportCsvMock).toHaveBeenCalledTimes(1));
    // No filters set: builder must hand the API an empty object — not e.g.
    // an object with `search: ""` that the server might mis-interpret.
    expect(exportCsvMock).toHaveBeenCalledWith({});
    await waitFor(() =>
      expect(toastSuccess).toHaveBeenCalledWith(
        expect.stringContaining('aisoc-audit-20260501T120000Z.csv'),
      ),
    );
  });

  it('forwards search + action + resource filters into the export payload', async () => {
    seedAuditPage([sampleEvent]);
    // Pre-seed the SWR key the component will use *after* the filters land,
    // so the filtered render still has data and the buttons stay enabled.
    // (When SWR misses, the component falls back to MOCK_AUDIT anyway, so
    // the buttons remain enabled — but we still seed the final key so any
    // SWR-driven re-render is deterministic.)
    swrCalls.set(
      '/api/v1/audit?page=1&page_size=50&search=admin&action=cases%3A&resource=case',
      { items: [sampleEvent], total: 1, page: 1, page_size: 50, total_pages: 1 },
    );
    exportCsvMock.mockResolvedValueOnce({
      body: 'id,action\nevt-1,cases:create\n',
      filename: 'aisoc-audit-filtered.csv',
    });

    render(<AuditLogView />);

    // Drive the three filter knobs the way an analyst would. The action and
    // resource filters are <select>s; the search is a free-text <input>.
    // Form order is: search input, action select, resource select.
    await userEvent.type(screen.getByPlaceholderText(/search email or action/i), 'admin');
    const selects = screen.getAllByRole('combobox');
    await userEvent.selectOptions(selects[0], 'cases:');
    await userEvent.selectOptions(selects[1], 'case');

    await userEvent.click(screen.getByRole('button', { name: /export csv/i }));

    await waitFor(() => expect(exportCsvMock).toHaveBeenCalledTimes(1));
    expect(exportCsvMock).toHaveBeenCalledWith({
      search: 'admin',
      action: 'cases:',
      resource: 'case',
    });
  });

  it('opens the print-ready HTML in a new tab on Export PDF (HTML)', async () => {
    seedAuditPage([sampleEvent]);
    exportHtmlMock.mockResolvedValueOnce({
      html: '<!doctype html><html><body><h1>Audit Log Export</h1></body></html>',
      filename: 'aisoc-audit-20260501T120000Z.html',
    });

    render(<AuditLogView />);

    await userEvent.click(screen.getByRole('button', { name: /export pdf \(html\)/i }));

    await waitFor(() => expect(exportHtmlMock).toHaveBeenCalledTimes(1));
    expect(window.open).toHaveBeenCalledWith('blob:mock-url', '_blank', 'noopener,noreferrer');
    await waitFor(() =>
      expect(toastSuccess).toHaveBeenCalledWith(
        expect.stringMatching(/save as pdf/i),
      ),
    );
  });

  it('surfaces a toast when the export endpoint returns 403', async () => {
    seedAuditPage([sampleEvent]);
    const { ApiError } = await import('@/lib/api');
    exportCsvMock.mockRejectedValueOnce(
      new ApiError('forbidden', 403, '{"detail": "missing audit_log:read"}'),
    );

    render(<AuditLogView />);

    await userEvent.click(screen.getByRole('button', { name: /export csv/i }));

    await waitFor(() => expect(toastError).toHaveBeenCalledTimes(1));
    expect(toastError).toHaveBeenCalledWith(expect.stringMatching(/audit_log:read/i));
  });

  it('disables the export buttons when there are zero rows in the current view', () => {
    seedAuditPage([], 0);

    render(<AuditLogView />);

    const csv = screen.getByRole('button', { name: /export csv/i });
    const html = screen.getByRole('button', { name: /export pdf \(html\)/i });
    expect(csv).toBeDisabled();
    expect(html).toBeDisabled();
  });
});
