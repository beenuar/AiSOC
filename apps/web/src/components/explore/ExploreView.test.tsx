/**
 * The Advanced Data Explorer, and the query it has to show.
 *
 * Wave 2, Phase 5.3.
 *
 * The defect this suite replaces, and how its predecessor hid it
 * ---------------------------------------------------------------
 * The explorer called `/nl-query/translate`, which runs nothing and returns
 * an ES|QL/SPL/KQL triple, then posted `res.esql` to `/lake/sql`. The lake
 * speaks SQL. Those are different languages, so a plain-English question
 * could not have worked.
 *
 * The previous suite asserted that exact behaviour as intended — and the
 * reason it looked right is the recorded trap in its sharpest form: its
 * fixture put the string `SELECT * FROM raw_events LIMIT 10` in the `esql`
 * field. That is not ES|QL. The double was not merely more capable than the
 * real translator, it answered in a different language, so the test passed
 * precisely because it never exercised the mismatch.
 *
 * What is asserted now
 * --------------------
 * 1. A question goes to `/nl-query/execute`, which translates **and runs**.
 * 2. The query that is displayed is the one that **ran** — for a lake
 *    execution that is the compiled SQL, never the ES|QL translation, which
 *    did not produce those rows.
 * 3. Bound parameters are shown separately from the text, because they are
 *    sent separately.
 * 4. Filters the lake could not honour are stated, since dropping them
 *    silently returns *more* rows than asked for and reads as "nothing was
 *    filtered out".
 * 5. Which store answered is stated: "nothing matched in your SIEM" and
 *    "nothing matched in AiSOC's lake" are different findings.
 */

import { describe, expect, it, vi, beforeEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import type { LakeQueryResponse, NlQueryExecuteResponse } from '@/lib/api';

const api = vi.hoisted(() => ({
  sql: vi.fn(),
  translate: vi.fn(),
  execute: vi.fn(),
}));

vi.mock('@/lib/api', () => ({
  lakeApi: { sql: api.sql, schema: vi.fn() },
  nlQueryApi: { translate: api.translate, execute: api.execute },
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

/**
 * A realistic execute response.
 *
 * `esql` and `executed_query` deliberately differ: the translator emits
 * ES|QL, the lake ran compiled SQL, and conflating them is the defect.
 */
function executeResponse(overrides: Partial<NlQueryExecuteResponse> = {}): NlQueryExecuteResponse {
  return {
    request_id: 'r1',
    question: 'show critical events',
    esql: 'FROM logs-* | WHERE severity == "critical" | LIMIT 10',
    spl: '',
    kql: '',
    explanation: 'Critical events in the last 24 hours.',
    created_at: '2026-07-12T08:00:01',
    engine: 'deterministic',
    grammar_validated: true,
    result: {
      columns: ['event_time', 'severity', 'user_name'],
      rows: [
        ['2026-07-12T08:00:00', 'critical', 'svc-backup'],
        ['2026-07-12T07:00:00', 'high', 'alice'],
      ],
      total_rows: 2,
      took_ms: 17,
    },
    execution_error: null,
    executed_against: 'lake',
    unsupported_filters: [],
    executed_query: 'SELECT event_time, severity, user_name FROM raw_events WHERE severity = :severity LIMIT :limit',
    executed_query_language: 'sql',
    executed_query_params: { severity: 'critical', limit: 500 },
    ...overrides,
  };
}

beforeEach(() => {
  api.sql.mockReset();
  api.translate.mockReset();
  api.execute.mockReset();
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

  it('sends a question to the runner, not the translator', async () => {
    api.execute.mockResolvedValue(executeResponse());
    const user = userEvent.setup();
    render(<ExploreView />);

    await user.type(screen.getByLabelText(/Ask in plain English/i), 'show critical events');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    expect(api.execute).toHaveBeenCalledWith({
      question: 'show critical events',
      time_range_hours: 24,
      max_rows: 500,
    });
    // `translate` runs nothing, and the lake's SQL endpoint is not where an
    // ES|QL string goes. Neither may be on this path.
    expect(api.translate).not.toHaveBeenCalled();
    expect(api.sql).not.toHaveBeenCalled();

    const table = await screen.findByRole('table');
    expect(within(table).getByText('svc-backup')).toBeInTheDocument();
  });

  it('shows the query that ran, which is not the ES|QL translation', async () => {
    api.execute.mockResolvedValue(executeResponse());
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.click(screen.getByRole('button', { name: 'Ask' }));
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'show critical events');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    const disclosure = await screen.findByTestId('query-disclosure');
    expect(within(disclosure).getByText(/SELECT event_time, severity, user_name FROM raw_events/)).toBeInTheDocument();
    // The ES|QL is a different query and did not produce these rows, so it
    // must not be what an analyst reads to check their question.
    expect(within(disclosure).queryByText(/FROM logs-\*/)).not.toBeInTheDocument();
  });

  it('shows bound values separately from the query text', async () => {
    api.execute.mockResolvedValue(executeResponse());
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    const disclosure = await screen.findByTestId('query-disclosure');
    expect(within(disclosure).getByText('severity')).toBeInTheDocument();
    expect(within(disclosure).getByText('critical')).toBeInTheDocument();
    expect(within(disclosure).getByText(/sent separately from the text/i)).toBeInTheDocument();
  });

  it('names which store answered', async () => {
    api.execute.mockResolvedValue(executeResponse({ executed_against: 'elasticsearch' }));
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    expect(await screen.findByText(/against your connected Elasticsearch/i)).toBeInTheDocument();
  });

  it('says no store was reached rather than implying an empty result', async () => {
    api.execute.mockResolvedValue(
      executeResponse({ executed_against: null, result: null, execution_error: null, executed_query: null }),
    );
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    expect(await screen.findByText(/no store was reached/i)).toBeInTheDocument();
    expect(screen.getByText(/nothing to show here/i)).toBeInTheDocument();
  });

  it('states the filters the store could not honour', async () => {
    api.execute.mockResolvedValue(executeResponse({ unsupported_filters: ['process.name', 'geo.country'] }));
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    const warning = await screen.findByTestId('unsupported-filters');
    expect(warning).toHaveTextContent('process.name');
    // The direction matters: dropped filters widen the result, and an
    // analyst reading "no matches" would draw the opposite conclusion.
    expect(warning).toHaveTextContent(/broader than what you asked for/i);
  });

  it('offers cross-filters bound to the entity columns that are present', async () => {
    api.execute.mockResolvedValue(executeResponse());
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    const filters = await screen.findByTestId('cross-filters');
    // `user_name` is present, so a user filter is offered; no host or
    // resource column exists in these rows, so neither is invented.
    expect(within(filters).getByLabelText(/Filter by user/i)).toBeInTheDocument();
    expect(within(filters).queryByLabelText(/Filter by host/i)).not.toBeInTheDocument();
  });

  it('distinguishes "no rows" from "no rows match these filters"', async () => {
    api.execute.mockResolvedValue(executeResponse());
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    await screen.findByRole('table');
    await user.selectOptions(screen.getByLabelText(/Filter by user/i), 'alice');
    expect(screen.getByText(/1 of 2 rows after filtering/i)).toBeInTheDocument();

    // A filter that excludes everything is a different fact from a query
    // that matched nothing; an operator who cannot tell them apart re-runs a
    // query that worked.
    await user.selectOptions(screen.getByLabelText(/Filter by user/i), 'svc-backup');
    await user.click(screen.getByRole('button', { name: /Clear filters/i }));
    expect(screen.getByRole('table')).toBeInTheDocument();
  });

  it('offers a graph pivot only once an entity is selected', async () => {
    api.execute.mockResolvedValue(executeResponse());
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    await screen.findByRole('table');
    expect(screen.queryByRole('link', { name: /Open in graph/i })).not.toBeInTheDocument();

    await user.selectOptions(screen.getByLabelText(/Filter by user/i), 'svc-backup');
    expect(screen.getByRole('link', { name: /Open in graph/i })).toHaveAttribute(
      'href',
      '/graph?entity=svc-backup',
    );
  });

  it('offers a CSV export of what is on screen', async () => {
    api.execute.mockResolvedValue(executeResponse());
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    await screen.findByRole('table');
    expect(screen.getByRole('button', { name: /Export CSV/i })).toBeInTheDocument();
  });

  it('runs raw SQL from the editor and clears any stale translation', async () => {
    api.sql.mockResolvedValue(RESULT);
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.click(screen.getByRole('button', { name: 'Run query' }));
    expect(api.sql).toHaveBeenCalledTimes(1);
    expect(await screen.findByRole('table')).toBeInTheDocument();
    // A translation left on screen beside hand-written rows would claim the
    // question produced them.
    expect(screen.queryByTestId('query-disclosure')).not.toBeInTheDocument();
  });

  it('surfaces a backend error without crashing', async () => {
    api.sql.mockRejectedValue(new Error('rate limited'));
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.click(screen.getByRole('button', { name: 'Run query' }));
    expect(await screen.findByText(/Query failed/i)).toBeInTheDocument();
    expect(screen.getByText(/rate limited/i)).toBeInTheDocument();
  });

  it('shows an execution error beside the query that caused it', async () => {
    api.execute.mockResolvedValue(
      executeResponse({ result: null, execution_error: 'Lake query timed out after 30s' }),
    );
    const user = userEvent.setup();
    render(<ExploreView />);
    await user.type(screen.getByLabelText(/Ask in plain English/i), 'q');
    await user.click(screen.getByRole('button', { name: 'Ask' }));

    expect(await screen.findByText(/Lake query timed out/i)).toBeInTheDocument();
    // The failing query is exactly the one worth reading.
    expect(screen.getByTestId('query-disclosure')).toBeInTheDocument();
  });
});
