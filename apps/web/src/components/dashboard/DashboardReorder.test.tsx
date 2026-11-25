/**
 * Component event regressions through the rendered dashboard. These tests
 * cover React handlers and layout persistence; native text selection and
 * clipboard behavior belong to the browser journey.
 */
import type { AnchorHTMLAttributes } from 'react';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { TimeWindowProvider } from '@/components/layout/TimeWindowProvider';
import { __setDemoModeForTests } from '@/lib/demoMode';

const metrics = vi.hoisted(() => ({
  alerts: { total: 4, new: 2, critical: 1, high: 1, medium: 1, low: 1, mttr: 0, mttr_sample_count: 0 },
  cases: { open: 1, inProgress: 1, resolvedThisWeek: 0 },
  sources: [], topMitre: [], alertsTrend: [], threatsBySource: [],
}));

vi.mock('swr', () => ({
  __esModule: true,
  default: (key: unknown) => ({
    data: Array.isArray(key) && key[0] === 'dashboard-metrics' ? metrics : undefined,
    error: undefined,
    isLoading: false,
    mutate: vi.fn(),
  }),
  mutate: vi.fn(() => Promise.resolve()),
}));

vi.mock('@/lib/api', () => ({
  authApi: { currentUser: () => null, updateUserPreferences: vi.fn() },
  metricsApi: { getDashboard: vi.fn(), getSOC: vi.fn(), getFunnel: vi.fn(), getPipelineHealth: vi.fn() },
  connectorsApi: { list: vi.fn() },
  investigationsApi: { getCostAggregate: vi.fn() },
}));

vi.mock('next/link', () => ({
  default: (props: AnchorHTMLAttributes<HTMLAnchorElement>) => <a {...props} />,
}));

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push: vi.fn(), replace: vi.fn(), refresh: vi.fn() }),
  usePathname: () => '/dashboard',
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock('next/dynamic', () => ({ default: () => () => null }));
vi.mock('@/lib/realtime', () => ({
  useRealtimeChannel: () => ({ status: 'disconnected', lastEvent: null, events: [] }),
}));

import { DashboardView } from './DashboardView';

const ORDER_KEY = 'aisoc:dashboard:widget-order';
const INITIAL_ORDER = [
  'top-metrics', 'charts-row', 'welcome', 'funnel-kpis',
  'efficiency-and-pipeline', 'bottom-row', 'soc-performance',
];

function widget(id: string) {
  return screen.getByLabelText(`Dashboard widget: ${id}`);
}

function handle(id: string) {
  return within(widget(id)).getByRole('button', { name: 'Drag to reorder' });
}

function currentOrder() {
  return [...document.querySelectorAll('[aria-label^="Dashboard widget:"]')]
    .map((node) => node.getAttribute('aria-label')!.replace('Dashboard widget: ', ''));
}

function dragData() {
  return {
    effectAllowed: 'uninitialized',
    dropEffect: 'none',
    setData: vi.fn(),
    setDragImage: vi.fn(),
  };
}

function expectIdle() {
  expect(document.querySelector('[aria-label^="Dashboard widget:"].opacity-40')).toBeNull();
  expect(document.querySelector('[aria-label^="Dashboard widget:"].ring-2')).toBeNull();
}

function renderDashboard() {
  return render(<TimeWindowProvider><DashboardView /></TimeWindowProvider>);
}

beforeAll(() => {
  // jsdom has no native drag engine. The old pointer-down handler constructs
  // a bubbling DragEvent with no DataTransfer; a MouseEvent has the standard
  // event semantics needed to expose that handler's unintended state change.
  if (typeof DragEvent === 'undefined') vi.stubGlobal('DragEvent', MouseEvent);
});

afterAll(() => { vi.unstubAllGlobals(); });

beforeEach(() => {
  localStorage.clear();
  localStorage.setItem(ORDER_KEY, JSON.stringify(INITIAL_ORDER));
  __setDemoModeForTests(false);
});

afterEach(() => {
  cleanup();
  __setDemoModeForTests(null);
});

describe('dashboard handle-only reordering', () => {
  it('does not start widget reordering when a child link starts a native drag', () => {
    renderDashboard();
    const link = within(widget('top-metrics')).getByRole('link', { name: /^Active Alerts/ });
    fireEvent.dragStart(link, { dataTransfer: dragData() });

    expectIdle();
    expect(currentOrder()).toEqual(INITIAL_ORDER);
  });

  it('does not start widget reordering on handle pointer-down or click', () => {
    renderDashboard();
    fireEvent.pointerDown(handle('top-metrics'));
    expectIdle();
    fireEvent.pointerUp(handle('top-metrics'));
    fireEvent.click(handle('top-metrics'));

    expectIdle();
    expect(currentOrder()).toEqual(INITIAL_ORDER);
  });

  it('uses the actual drop target and persists handle reordering across remounts', () => {
    const view = renderDashboard();
    const dataTransfer = dragData();
    fireEvent.dragStart(handle('top-metrics'), { dataTransfer });
    expect(widget('top-metrics')).toHaveClass('opacity-40');
    fireEvent.dragOver(widget('funnel-kpis'), { dataTransfer });
    expect(widget('funnel-kpis')).toHaveClass('ring-2');

    // The final drop can target a different widget from the last dragover.
    expect(fireEvent.drop(widget('charts-row'), { dataTransfer })).toBe(false);
    const reordered = ['charts-row', 'top-metrics', ...INITIAL_ORDER.slice(2)];
    expect(currentOrder()).toEqual(reordered);
    expect(JSON.parse(localStorage.getItem(ORDER_KEY)!)).toEqual(reordered);
    expectIdle();

    view.unmount();
    renderDashboard();
    expect(currentOrder()).toEqual(reordered);
    expectIdle();
  });

  it('clears a cancelled drag without committing the hovered target', () => {
    renderDashboard();
    const dataTransfer = dragData();
    fireEvent.dragStart(handle('top-metrics'), { dataTransfer });
    fireEvent.dragOver(widget('charts-row'), { dataTransfer });
    expect(widget('charts-row')).toHaveClass('ring-2');
    fireEvent.dragEnd(handle('top-metrics'), { dataTransfer });

    expect(currentOrder()).toEqual(INITIAL_ORDER);
    expect(JSON.parse(localStorage.getItem(ORDER_KEY)!)).toEqual(INITIAL_ORDER);
    expectIdle();
  });

  it.each(['dragOver', 'drop'] as const)('does not intercept %s without an active widget drag', (event) => {
    renderDashboard();
    expect(fireEvent[event](widget('charts-row'), { dataTransfer: dragData() })).toBe(true);

    expectIdle();
    expect(currentOrder()).toEqual(INITIAL_ORDER);
    expect(JSON.parse(localStorage.getItem(ORDER_KEY)!)).toEqual(INITIAL_ORDER);
  });
});
