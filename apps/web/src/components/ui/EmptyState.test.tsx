import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';

import { EmptyState, EmptyStateIcons } from './EmptyState';

// WS-F5 — guard the contract that a few dozen list views now depend on:
//   1. The "default" variant renders an action when one is provided.
//   2. The "planned-v1.1" variant *suppresses* actions and shows a badge,
//      because deferred features must not advertise outbound links.
//   3. Icons render with `aria-hidden` so screen readers skip them and
//      announce the title instead.

describe('EmptyState', () => {
  it('renders title, description, and action for the default variant', () => {
    render(
      <EmptyState
        title="No alerts yet"
        description="Connect a data source to start streaming."
        action={<button>Connect</button>}
      />,
    );

    expect(screen.getByRole('status')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /no alerts yet/i })).toBeInTheDocument();
    expect(screen.getByText(/connect a data source/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /connect/i })).toBeInTheDocument();
  });

  it('renders without description or action when omitted', () => {
    render(<EmptyState title="Nothing to see" />);

    expect(screen.getByRole('heading', { name: /nothing to see/i })).toBeInTheDocument();
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('shows the "Planned for v1.1" badge for the planned-v1.1 variant', () => {
    render(
      <EmptyState
        title="Saved views are coming"
        description="Filter+column presets land in v1.1."
        variant="planned-v1.1"
      />,
    );

    expect(screen.getByText(/planned for v1\.1/i)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: /saved views are coming/i })).toBeInTheDocument();
  });

  it('suppresses actions for the planned-v1.1 variant', () => {
    // Per the WS-F5 plan: deferred features show "planned for v1.1" copy with
    // NO outbound links. Even if a caller passes an action, we drop it.
    render(
      <EmptyState
        title="Replayable timeline"
        description="Coming soon."
        variant="planned-v1.1"
        action={<a href="/somewhere">Should be hidden</a>}
      />,
    );

    expect(screen.queryByRole('link', { name: /should be hidden/i })).not.toBeInTheDocument();
  });

  it('honors a custom badge label on planned-v1.1', () => {
    render(
      <EmptyState
        title="Custom"
        variant="planned-v1.1"
        badge="Coming Q3"
      />,
    );

    expect(screen.getByText(/coming q3/i)).toBeInTheDocument();
    // Default label should not also show.
    expect(screen.queryByText(/planned for v1\.1/i)).not.toBeInTheDocument();
  });

  it('does not render the badge on the default variant', () => {
    render(
      <EmptyState
        title="Default with badge prop"
        variant="default"
        badge="Should not appear"
      />,
    );

    expect(screen.queryByText(/should not appear/i)).not.toBeInTheDocument();
  });

  it('exports a stable set of empty-state icons', () => {
    // These icons are referenced from many list views; this test guards
    // against an accidental rename or removal during a refactor.
    const expected = ['alert', 'case', 'search', 'shield', 'audit', 'marketplace', 'ledger'] as const;
    for (const key of expected) {
      expect(EmptyStateIcons[key]).toBeTruthy();
    }
  });

  it('marks SVG icons as aria-hidden so titles drive announcements', () => {
    const { container } = render(
      <EmptyState
        icon={EmptyStateIcons.alert}
        title="No alerts"
      />,
    );

    const svg = container.querySelector('svg');
    expect(svg).not.toBeNull();
    expect(svg).toHaveAttribute('aria-hidden', 'true');
  });
});
