import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import { ComparisonTable } from './ComparisonTable';

// Smoke test for the landing-page comparison table. The point isn't to pin
// every cell value — those can change as the harness evolves — but to catch
// regressions where the table fails to render at all (broken import, missing
// VENDORS, etc.) and to guard the honesty claims we deliberately rolled back
// from gimmick land in P1.
describe('ComparisonTable', () => {
  it('renders the AiSOC row plus both competitor categories', () => {
    render(<ComparisonTable />);

    expect(screen.getByText('AiSOC')).toBeInTheDocument();
    expect(screen.getByText('Closed-source AI SOC')).toBeInTheDocument();
    expect(screen.getByText('Closed-source SOAR')).toBeInTheDocument();
  });

  it('declares the reproducibility claim as PR-gated, not "every commit"', () => {
    // P1 honesty fix — the AiSOC reduction cell must say "main / develop",
    // never "every commit". If someone sneaks the old wording back in, this
    // test fails.
    render(<ComparisonTable />);

    const cell = screen.getByText(/every PR to main \/ develop/i);
    expect(cell).toBeInTheDocument();
    expect(screen.queryByText(/every commit/i)).toBeNull();
  });

  it('quotes the reduction measured against the correlation key the product runs', () => {
    render(<ComparisonTable />);

    // Substring match — the cell reads
    // "33.3% (real correlation key, fixed noisy stream)".
    expect(screen.getByText(/33\.3% \(real correlation key/)).toBeInTheDocument();
    // The legacy four-tier figure describes an algorithm this product does not
    // run, so it must not appear in a vendor comparison at all.
    expect(screen.queryByText(/75\.3/)).toBeNull();
  });
});
