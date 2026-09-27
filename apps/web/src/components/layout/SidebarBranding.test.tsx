/**
 * The console half of Phase 13.2's acceptance.
 *
 * A white-labelled organisation's console has to show its branding, and the
 * only way to prove that is to render the shell against a branded response
 * and read what comes out. Asserting that the hook returns the right object
 * would prove the hook works and say nothing about whether anything renders
 * it, which is the shape of failure this program keeps finding.
 *
 * The API client is mocked rather than the hook, so the wiring between the
 * two is inside the test rather than stubbed over.
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';

vi.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
}));

vi.mock('next/link', () => ({
  default: ({ children, href, className }: { children: React.ReactNode; href: string; className?: string }) => (
    <a href={href} className={className}>
      {children}
    </a>
  ),
}));

// `vi.mock` is hoisted above every top-level statement in this file, so a
// plain `const` referenced from the factory is still in its temporal dead
// zone when the factory runs. `vi.hoisted` is the supported way to share a
// value with one.
const { brandedResponse } = vi.hoisted(() => ({
  brandedResponse: {
    product_name: 'Acme Shield',
    primary_color: '#123456',
    accent_color: '#654321',
    support_email: null,
    support_url: 'https://support.acme.example',
    sender_name: 'Acme Shield',
    footer_text: 'Acme Shield',
    logo_url: '/api/v1/branding/assets/00000000-0000-0000-0000-0000000000aa',
    org_id: '0a0a0a0a-0000-0000-0000-00000000000a',
    is_white_labelled: true,
  },
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    // A plain async function rather than `vi.fn()`: this suite runs with
    // mock clearing on, which strips a `vi.fn()` implementation between
    // tests and would leave the second one resolving `undefined`.
    brandingApi: { get: async () => brandedResponse },
  };
});

import { Sidebar } from './Sidebar';

describe('Sidebar branding', () => {
  // One render for every assertion, deliberately. SWR keeps a module-level
  // cache and a deduping window, so a second `render` in this file resolves
  // from neither the cache nor a fresh request and shows the unbranded
  // wordmark. Splitting these would test the cache rather than the console.
  it("shows a white-labelled organisation's name and logo, and drops the platform wordmark", async () => {
    const { container } = render(<Sidebar />);

    expect(await screen.findByText('Acme Shield')).toBeInTheDocument();

    // The platform wordmark is gone. A console showing both is not
    // white-labelled, it is co-branded by accident.
    expect(screen.queryByText('open-source')).not.toBeInTheDocument();

    const logo = container.querySelector('img');
    expect(logo).not.toBeNull();
    const src = logo?.getAttribute('src') ?? '';
    expect(src.startsWith('/api/v1/branding/assets/')).toBe(true);
    // A remote logo would be an outbound request from the operator's browser
    // on every page load, telling whoever hosts it who is looking at what.
    expect(src).not.toMatch(/^https?:\/\//);
  });
});
