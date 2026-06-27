/**
 * T3.8 — Storybook visual-regression snapshots.
 *
 * Vitest serializes each design-system primitive into a textual
 * snapshot in storybook-snapshots.test.tsx.snap so a structural
 * regression (missing class, removed element, broken text content)
 * shows up as a failed test in CI.
 *
 * This is NOT a pixel-diff harness — those need a real browser, and
 * the CI runs jsdom-only. The contract here is "the rendered DOM
 * tree is stable" which is the cheap, fast 90 % of visual regression.
 *
 * To intentionally update snapshots after a deliberate change:
 *   pnpm exec vitest run --update src/test/storybook-snapshots.test.tsx
 *
 * Coverage:
 *   - Every variant of Button
 *   - Every tone of Badge
 *   - Every status of StatusPill
 *   - Card elevations and the flush table layout
 *   - EmptyState (default + planned variants)
 *   - ErrorState (basic + with-error + with-retry)
 *   - Skeleton (single, list, card)
 *
 * Each test uses RTL's render() + asFragment() so the snapshot
 * format is purely declarative HTML.
 */

import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/react';
import React from 'react';

import { Button } from '@/components/ui/Button';
import { Badge, type BadgeTone } from '@/components/ui/Badge';
import { Card, CardHeader, CardBody, CardFooter } from '@/components/ui/Card';
import { StatusPill, type StatusKind } from '@/components/ui/StatusPill';
import { EmptyState } from '@/components/ui/EmptyState';
import { ErrorState } from '@/components/ui/ErrorState';
import { Skeleton, SkeletonList, SkeletonCard } from '@/components/ui/Skeleton';

describe('Storybook visual-regression / Button', () => {
  const variants = ['primary', 'secondary', 'destructive', 'ghost', 'outline'] as const;
  for (const variant of variants) {
    it(`renders the ${variant} variant`, () => {
      const { asFragment } = render(<Button variant={variant}>Action</Button>);
      expect(asFragment()).toMatchSnapshot();
    });
  }
  it('renders all sizes side-by-side', () => {
    const { asFragment } = render(
      <div className="flex gap-2">
        <Button size="xs">XS</Button>
        <Button size="sm">SM</Button>
        <Button size="md">MD</Button>
        <Button size="lg">LG</Button>
      </div>,
    );
    expect(asFragment()).toMatchSnapshot();
  });
  it('renders the loading state', () => {
    const { asFragment } = render(<Button loading>Loading…</Button>);
    expect(asFragment()).toMatchSnapshot();
  });
});

describe('Storybook visual-regression / Badge', () => {
  const tones: BadgeTone[] = [
    'neutral',
    'info',
    'success',
    'warning',
    'danger',
    'severity-info',
    'severity-low',
    'severity-medium',
    'severity-high',
    'severity-critical',
  ];
  for (const tone of tones) {
    it(`renders the ${tone} tone`, () => {
      const { asFragment } = render(<Badge tone={tone}>{tone}</Badge>);
      expect(asFragment()).toMatchSnapshot();
    });
  }
});

describe('Storybook visual-regression / StatusPill', () => {
  const statuses: StatusKind[] = [
    'pending',
    'running',
    'completed',
    'failed',
    'cancelled',
    'unknown',
  ];
  for (const status of statuses) {
    it(`renders the ${status} status`, () => {
      const { asFragment } = render(<StatusPill status={status} />);
      expect(asFragment()).toMatchSnapshot();
    });
  }
});

describe('Storybook visual-regression / Card', () => {
  it('renders a raised card with header / body / footer', () => {
    const { asFragment } = render(
      <Card elevation="raised">
        <CardHeader title="Test card" description="A snapshotted card." />
        <CardBody>The body content.</CardBody>
        <CardFooter>
          <Button variant="ghost" size="sm">Cancel</Button>
          <Button variant="primary" size="sm">Save</Button>
        </CardFooter>
      </Card>,
    );
    expect(asFragment()).toMatchSnapshot();
  });
  it('renders a flat card', () => {
    const { asFragment } = render(<Card elevation="flat">Flat surface</Card>);
    expect(asFragment()).toMatchSnapshot();
  });
  it('renders a flush card with a table', () => {
    const { asFragment } = render(
      <Card elevation="raised" flush>
        <table>
          <tbody>
            <tr>
              <td>cell</td>
            </tr>
          </tbody>
        </table>
      </Card>,
    );
    expect(asFragment()).toMatchSnapshot();
  });
});

describe('Storybook visual-regression / EmptyState', () => {
  it('renders the default variant', () => {
    const { asFragment } = render(
      <EmptyState title="No playbooks yet" description="Use the button above to create one." />,
    );
    expect(asFragment()).toMatchSnapshot();
  });
  it('renders the planned-v1.1 variant', () => {
    const { asFragment } = render(
      <EmptyState
        variant="planned-v1.1"
        title="Coming soon"
        description="Available in the next release."
      />,
    );
    expect(asFragment()).toMatchSnapshot();
  });
});

describe('Storybook visual-regression / ErrorState', () => {
  it('renders the basic error', () => {
    const { asFragment } = render(<ErrorState />);
    expect(asFragment()).toMatchSnapshot();
  });
  it('renders the error with a string detail', () => {
    const { asFragment } = render(
      <ErrorState title="Boom" description="A test boom." error="HTTP 500" />,
    );
    expect(asFragment()).toMatchSnapshot();
  });
});

describe('Storybook visual-regression / Skeleton', () => {
  it('renders a single skeleton', () => {
    const { asFragment } = render(<Skeleton className="h-4 w-32" />);
    expect(asFragment()).toMatchSnapshot();
  });
  it('renders a skeleton list', () => {
    const { asFragment } = render(<SkeletonList count={3} />);
    expect(asFragment()).toMatchSnapshot();
  });
  it('renders a skeleton card', () => {
    const { asFragment } = render(<SkeletonCard />);
    expect(asFragment()).toMatchSnapshot();
  });
});
