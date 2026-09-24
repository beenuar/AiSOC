import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { useState } from 'react';

// WS-F3 — pin the SavedViewsBar wiring. We care about four behaviors the
// downstream pages actually rely on:
//   1. Load + render existing presets, with a star on the default one.
//   2. Auto-apply the default exactly once on first render (so coming back
//      to a page restores the analyst's preferred filters), without firing
//      again on stale SWR revalidations.
//   3. Save the *current* filters when the analyst hits "Save current view"
//      with the typed name + default checkbox.
//   4. Surface 409 conflicts (duplicate names) as a friendly error toast,
//      not a stack trace.
//
// We keep the SWR + savedViewsApi + toast mocks lightweight so the test
// stays under jsdom budget; nothing here renders the actual list view, just
// the bar.

const swrCalls = vi.hoisted(() => new Map<string, unknown>());
const swrErrors = vi.hoisted(() => new Map<string, unknown>());
vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => {
    // Cache key is `['saved-views', viewType]` for the bar.
    const k = Array.isArray(key) ? key.join(':') : String(key);
    return {
      data: swrCalls.get(k),
      error: swrErrors.get(k),
      isLoading: !swrCalls.has(k) && !swrErrors.has(k),
      mutate: vi.fn(async () => undefined),
    };
  },
}));

const listMock = vi.hoisted(() => vi.fn());
const createMock = vi.hoisted(() => vi.fn());
const updateMock = vi.hoisted(() => vi.fn());
const deleteMock = vi.hoisted(() => vi.fn());
vi.mock('@/lib/api', () => ({
  __esModule: true,
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
  savedViewsApi: {
    list: listMock,
    create: createMock,
    update: updateMock,
    delete: deleteMock,
  },
}));

const toastSuccess = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: toastSuccess, error: toastError },
}));

import { SavedViewsBar } from './SavedViewsBar';
import { ApiError } from '@/lib/api';

interface TestFilters extends Record<string, unknown> {
  status?: string;
  q?: string;
}

function seedViews(viewType: string, items: unknown[]) {
  swrCalls.set(`saved-views:${viewType}`, items);
}

function makeView(overrides: Record<string, unknown> = {}) {
  return {
    id: 'v-1',
    tenant_id: 't-1',
    user_id: 'u-1',
    view_type: 'alerts',
    name: 'High severity',
    filters: { status: 'open', q: 'critical' },
    columns: null,
    is_default: false,
    created_at: '2026-05-01T10:00:00Z',
    updated_at: '2026-05-01T10:00:00Z',
    ...overrides,
  };
}

describe('SavedViewsBar', () => {
  beforeEach(() => {
    swrCalls.clear();
    swrErrors.clear();
    listMock.mockReset();
    createMock.mockReset();
    updateMock.mockReset();
    deleteMock.mockReset();
    toastSuccess.mockReset();
    toastError.mockReset();
  });

  it('renders existing views with a star on the default one', () => {
    seedViews('alerts', [
      makeView({ id: 'v-1', name: 'Open critical', is_default: true }),
      makeView({ id: 'v-2', name: 'My queue', is_default: false }),
    ]);
    const onApply = vi.fn();

    render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{ status: 'open' }}
        onApply={onApply}
      />,
    );

    // Both chips render.
    expect(screen.getByTestId('saved-view-chip-v-1')).toHaveTextContent(
      'Open critical',
    );
    expect(screen.getByTestId('saved-view-chip-v-2')).toHaveTextContent(
      'My queue',
    );
    // The default chip surfaces the ★ glyph.
    expect(
      screen.getByTestId('saved-view-chip-v-1').textContent,
    ).toContain('★');
    expect(
      screen.getByTestId('saved-view-chip-v-2').textContent,
    ).not.toContain('★');
  });

  it('auto-applies the default view exactly once on mount', async () => {
    const defaultFilters = { status: 'open', q: 'critical' };
    seedViews('alerts', [
      makeView({ id: 'v-1', name: 'Open critical', is_default: true, filters: defaultFilters }),
      makeView({ id: 'v-2', name: 'My queue' }),
    ]);
    const onApply = vi.fn();
    const onDefaultLoaded = vi.fn();

    const { rerender } = render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{}}
        onApply={onApply}
        onDefaultLoaded={onDefaultLoaded}
      />,
    );

    await waitFor(() => {
      expect(onApply).toHaveBeenCalledWith(defaultFilters);
    });
    expect(onDefaultLoaded).toHaveBeenCalledTimes(1);

    // Re-render with the same SWR data — must not re-apply, since otherwise
    // we'd clobber filters the analyst has tweaked since mount.
    rerender(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{ status: 'closed' }}
        onApply={onApply}
        onDefaultLoaded={onDefaultLoaded}
      />,
    );
    expect(onApply).toHaveBeenCalledTimes(1);
    expect(onDefaultLoaded).toHaveBeenCalledTimes(1);
  });

  it('applies the default without updating its parent mid-render', async () => {
    // The auto-apply used to run in the render body, so `onApply` — which for
    // every real caller is a setState on the *page* — fired while this
    // component was rendering. React rejects that outright and does not
    // guarantee the parent's update is processed.
    //
    // The existing "exactly once" test cannot catch it: its `onApply` is a
    // bare `vi.fn()` that sets no state, so React has nothing to complain
    // about. It takes a real parent to reproduce.
    seedViews('alerts', [
      makeView({ id: 'v-1', is_default: true, filters: { status: 'open' } }),
    ]);

    const consoleErrors: string[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
      consoleErrors.push(args.map((a) => String(a)).join(' '));
    });

    function Page() {
      const [applied, setApplied] = useState<TestFilters | null>(null);
      return (
        <>
          <SavedViewsBar<TestFilters> viewType="alerts" filters={{}} onApply={setApplied} />
          <span data-testid="applied-status">{applied?.status ?? 'none'}</span>
        </>
      );
    }

    try {
      render(<Page />);
      await waitFor(() => {
        expect(screen.getByTestId('applied-status')).toHaveTextContent('open');
      });
    } finally {
      spy.mockRestore();
    }

    const renderPhaseUpdates = consoleErrors.filter((line) =>
      /Cannot update a component/.test(line),
    );
    expect(renderPhaseUpdates).toEqual([]);
  });

  it('does not auto-apply when no default view exists', () => {
    seedViews('alerts', [makeView({ id: 'v-2', is_default: false })]);
    const onApply = vi.fn();

    render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{}}
        onApply={onApply}
      />,
    );

    expect(onApply).not.toHaveBeenCalled();
  });

  it('saves the current filters with the typed name', async () => {
    seedViews('alerts', []);
    createMock.mockResolvedValue(makeView({ id: 'v-new', name: 'My filter' }));
    const user = userEvent.setup();

    render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{ status: 'open', q: 'phish' }}
        onApply={vi.fn()}
      />,
    );

    await user.click(screen.getByTestId('save-current-view-btn'));
    const input = screen.getByLabelText('New saved view name');
    await user.type(input, 'My filter');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(createMock).toHaveBeenCalledWith({
        view_type: 'alerts',
        name: 'My filter',
        filters: { status: 'open', q: 'phish' },
        is_default: false,
      });
    });
    expect(toastSuccess).toHaveBeenCalled();
  });

  it('surfaces 409 conflicts as a friendly error toast', async () => {
    seedViews('alerts', []);
    createMock.mockRejectedValue(new ApiError('Conflict', 409, ''));
    const user = userEvent.setup();

    render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{ status: 'open' }}
        onApply={vi.fn()}
      />,
    );

    await user.click(screen.getByTestId('save-current-view-btn'));
    await user.type(screen.getByLabelText('New saved view name'), 'Dup');
    await user.click(screen.getByRole('button', { name: 'Save' }));

    await waitFor(() => {
      expect(toastError).toHaveBeenCalledWith(
        'A view named "Dup" already exists',
      );
    });
    expect(toastSuccess).not.toHaveBeenCalled();
  });

  it('emits onApply with the preset filters when a chip is clicked', async () => {
    const presetFilters = { status: 'closed', q: 'apt' };
    seedViews('alerts', [
      makeView({ id: 'v-1', name: 'My queue', filters: presetFilters }),
    ]);
    const onApply = vi.fn();
    const user = userEvent.setup();

    render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{ status: 'open' }}
        onApply={onApply}
      />,
    );

    await user.click(screen.getByTestId('saved-view-chip-v-1'));
    expect(onApply).toHaveBeenCalledWith(presetFilters);
  });

  it('hides the save affordance in read-only mode', () => {
    seedViews('alerts', [makeView()]);
    render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{}}
        onApply={vi.fn()}
        readOnly
      />,
    );
    expect(screen.queryByTestId('save-current-view-btn')).toBeNull();
  });

  it('shows an empty-state nudge when no views exist yet', () => {
    seedViews('alerts', []);
    render(
      <SavedViewsBar<TestFilters>
        viewType="alerts"
        filters={{}}
        onApply={vi.fn()}
      />,
    );
    expect(
      screen.getByText(/save your current filters to come back to them/i),
    ).toBeInTheDocument();
  });
});
