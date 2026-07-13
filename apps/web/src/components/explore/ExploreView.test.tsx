/**
 * Smoke tests for the Advanced Data Explorer (Phase C1).
 *
 * Pins the behaviours an SOC would file a bug against if they regressed:
 *   1. Source tabs render and switch; non-events sources show a pivot link.
 *   2. An NL question is translated (nlQueryApi.translate) into SQL and run
 *      (lakeApi.sql), and the returned rows render in the results table.
 *   3. A raw-SQL run calls lakeApi.sql with the editor contents.
 *   4. A backend error surfaces the ErrorState (not a crash).
 *
 * We mock `@/lib/api` + react-hot-toast so the test focuses on the view layer.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { LakeQueryResponse } from '@/lib/api';

const api = vi.hoisted(() => ({
  sql: vi.fn(),
  translate: vi.fn(),
}));

vi.mock('@/lib/api', () => ({
  lakeApi: { sql: api.sql, schema: vi.fn() },
  nlQueryApi: { translate: api.translate },
}));

vi.mock('react-hot-toast', () => ({
  default: { error: vi.fn(), success: vi.fn() },
}));

import { ExploreView } from './ExploreView';

const RESULT: LakeQueryResponse = {
  columns: ['event_time', 'severity', 'user_name'],
  rows: [
    ['2026-07-12T08:00:00', 'critical', 'svc-backup'],
    ['2026-07-12T07:00:00', 'high', 'alice'],
  ],
  row_count: 2,
  row_cap: 100,
  referenced_tables: ['raw_events'],
  elapsed_ms: 42,
  executed_at: '2026-07-12T08:00:01',
};

beforeEach(() => {
  api.sql.mockReset();
  api.translate.mockReset();
});

describe('ExploreView', () => {
  it('renders the source tabs and the events explorer by default', () => {
    render(<ExploreView />);
    expect(screen.getByRole('heading', { name: /Data Explorer/i })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Events (lake)', pressed: true })).toBeInTheDocument();
    expect(screen.getByLabelText(/Ask in plain English/i)).toBeInTheDocument();
  });

  it('switches to a non-events source and shows a pivot link', async () => {
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.click(screen.getByRole('button', { name: 'Identity' }));
    expect(screen.getByRole('link', { name: /Open Identity/i })).toHaveAttribute('href', '/identity');
  });

  it('translates an NL question to SQL, runs it, and renders rows', async () => {
    api.translate.mockResolvedValue({
      request_id: 'r1',
      question: 'q',
      esql: 'SELECT * FROM raw_events LIMIT 10',
      spl: '',
      kql: '',
      explanation: '',
      created_at: '',
      engine: 'deterministic',
      grammar_validated: true,
    });
    api.sql.mockResolvedValue(RESULT);
    const user = userEvent.setup();
    render(<ExploreView />);

    await user.type(screen.getByLabelText(/Ask in plain English/i), 'show critical events');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    expect(api.translate).toHaveBeenCalledWith({ question: 'show critical events' });
    expect(api.sql).toHaveBeenCalledWith({ sql: 'SELECT * FROM raw_events LIMIT 10', row_cap: 100 });

    const table = await screen.findByRole('table');
    expect(within(table).getByText('svc-backup')).toBeInTheDocument();
    expect(screen.getByText(/2 rows/)).toBeInTheDocument();
  });

  it('runs raw SQL from the editor', async () => {
    api.sql.mockResolvedValue(RESULT);
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.click(screen.getByRole('button', { name: 'Run query' }));
    expect(api.sql).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('table')).toBeInTheDocument();
  });

  it('surfaces a backend error without crashing', async () => {
    api.sql.mockRejectedValue(new Error('rate limited'));
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.click(screen.getByRole('button', { name: 'Run query' }));
    expect(await screen.findByText(/Query failed/i)).toBeInTheDocument();
    expect(screen.getByText(/rate limited/i)).toBeInTheDocument();
  });
});
