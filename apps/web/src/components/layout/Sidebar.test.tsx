import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

// Mock Next.js routing primitives. The Sidebar reads `usePathname` to decide
// which item is active and uses `<Link>` for navigation; for a smoke test we
// just need both to behave as plain functions/elements.
vi.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
}));

vi.mock('next/link', () => ({
  default: ({
    children,
    href,
    className,
  }: {
    children: React.ReactNode;
    href: string;
    className?: string;
  }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

import { Sidebar } from './Sidebar';

describe('Sidebar', () => {
  it('renders the AiSOC mark and the major nav sections', () => {
    render(<Sidebar />);

    // Brand
    expect(screen.getByText('Ai')).toBeInTheDocument();
    expect(screen.getByText('SOC')).toBeInTheDocument();

    // Section headings — Dashboard sits in an unlabelled lead section,
    // everything else is grouped under one of these four titles.
    expect(screen.getByText('Threat Operations')).toBeInTheDocument();
    expect(screen.getByText('Intelligence')).toBeInTheDocument();
    expect(screen.getByText('Automation')).toBeInTheDocument();
    expect(screen.getByText('Platform')).toBeInTheDocument();
  });

  it('exposes the marketplace and compliance entry points', () => {
    render(<Sidebar />);

    const marketplace = screen.getByRole('link', { name: /marketplace/i });
    expect(marketplace).toHaveAttribute('href', '/marketplace');

    const compliance = screen.getByRole('link', { name: /compliance/i });
    expect(compliance).toHaveAttribute('href', '/compliance');
  });

  it('renders the MIT license attribution in the footer', () => {
    render(<Sidebar />);

    const license = screen.getByRole('link', { name: /MIT License/i });
    expect(license).toHaveAttribute('href', 'https://github.com/beenuar/AiSOC');
  });
});
