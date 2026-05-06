import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

// next/link wants a Next.js router context; for a smoke test we mock it.
vi.mock('next/link', () => ({
  default: ({ children, href }: { children: React.ReactNode; href: string }) => (
    <a href={href}>{children}</a>
  ),
}));

// framer-motion's runtime needs window APIs we don't bother spinning up
// in a unit test. The "motion." factory is just a thin wrapper here — render
// the underlying tag.
vi.mock('framer-motion', () => {
  const factory = (Tag: React.ElementType) =>
    function MotionStub(props: Record<string, unknown>) {
      const { children, ...rest } = props as {
        children?: React.ReactNode;
      } & Record<string, unknown>;
      // Strip framer-motion-only props before they leak onto a DOM element.
      delete (rest as Record<string, unknown>).initial;
      delete (rest as Record<string, unknown>).animate;
      delete (rest as Record<string, unknown>).transition;
      delete (rest as Record<string, unknown>).whileHover;
      delete (rest as Record<string, unknown>).whileTap;
      return <Tag {...(rest as Record<string, unknown>)}>{children}</Tag>;
    };
  return {
    motion: new Proxy({}, { get: (_t, key: string) => factory(key as React.ElementType) }),
  };
});

import { Hero } from './Hero';

describe('Hero', () => {
  it('renders the headline and primary CTAs', () => {
    render(<Hero />);

    expect(screen.getByRole('heading', { level: 1 })).toHaveTextContent(/auditable AI SOC/i);
    expect(screen.getByRole('link', { name: /open the demo/i })).toHaveAttribute(
      'href',
      'https://tryaisoc.com/cases/INC-001?tab=ledger',
    );
    expect(screen.getByRole('link', { name: /open console/i })).toHaveAttribute('href', '/dashboard');
  });

  it('describes the eval harness as PR-gated, never "every commit"', () => {
    // P1 honesty fix: the body copy must mention "every PR" / "main / develop"
    // rather than the older "every commit" wording.
    render(<Hero />);

    expect(screen.getByText(/every PR targeting/i)).toBeInTheDocument();
    expect(screen.queryByText(/every commit/i)).toBeNull();
  });
});
