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

  it('tags the alert-reduction number as a measurement, not a marketing claim', () => {
    render(<ComparisonTable />);

    // Substring match — the cell reads "75.3% (measured on fixed noisy stream)".
    expect(screen.getByText(/75\.3% \(measured/)).toBeInTheDocument();
  });
});
