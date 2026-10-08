/**
 * The browser tab is a surface, and it carried the platform name.
 *
 * Next resolves `metadata` at build time, with no request and therefore no
 * tenant, so an analyst at a white-labelled provider read the platform's
 * product name in every tab and in every bookmark they made. The correction
 * can only happen in the browser.
 *
 * These cases mount the real console shell inside the real theme provider —
 * the same nesting `app/layout.tsx` and `app/(app)/layout.tsx` produce —
 * rather than the title component on its own. A component that works and is
 * mounted nowhere is the failure this repository keeps finding, and rendering
 * it directly could not tell the two apart.
 *
 * Each render gets its own SWR cache. The branding hook keys on the constant
 * string `branding`, so a second render in one file would resolve from the
 * first one's cache and the second case would be testing the cache.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, waitFor } from '@testing-library/react';
import { SWRConfig } from 'swr';

vi.mock('next/navigation', () => ({
  usePathname: () => '/dashboard',
  useRouter: () => ({ push: () => {} }),
  useSearchParams: () => new URLSearchParams(),
}));

vi.mock('next/link', () => ({
  default: ({ children, href }: { children: React.ReactNode; href: string }) => <a href={href}>{children}</a>,
}));

const { state } = vi.hoisted(() => ({
  state: {
    response: {
      product_name: 'AiSOC',
      primary_color: '#2563EB',
      accent_color: '#7C3AED',
      support_email: null,
      support_url: null,
      sender_name: 'AiSOC',
      footer_text: 'AiSOC',
      logo_url: null,
      org_id: null,
      is_white_labelled: false,
    },
  },
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return { ...actual, brandingApi: { get: async () => state.response, logo: actual.brandingApi.logo } };
});

import { AppShell } from './AppShell';
import { ThemeProvider } from '@/components/theme/ThemeProvider';

function mountConsole() {
  return render(
    <ThemeProvider>
      <SWRConfig value={{ provider: () => new Map() }}>
        <AppShell demoMode={false}>dashboard</AppShell>
      </SWRConfig>
    </ThemeProvider>,
  );
}

beforeEach(() => {
  vi.stubGlobal('fetch', async () => new Response('{}', { status: 200 }));
});

afterEach(() => {
  document.title = '';
  vi.unstubAllGlobals();
});

describe('the console tab title', () => {
  it("replaces the platform name with the organisation's", async () => {
    state.response = { ...state.response, product_name: 'Acme Shield', is_white_labelled: true };
    document.title = 'Honeytokens | AiSOC';

    mountConsole();

    // The section the route named survives; only the product does not. A
    // component that overwrote the whole title would lose the page.
    await waitFor(() => expect(document.title).toBe('Honeytokens | Acme Shield'));
  });

  it('leaves an unbranded deployment alone', async () => {
    state.response = { ...state.response, product_name: 'AiSOC', is_white_labelled: false };
    document.title = 'Honeytokens | AiSOC';

    mountConsole();

    // The negative control. Rewriting unconditionally would be invisible
    // today and a silent corruption the moment the platform default moves.
    await waitFor(() => expect(document.title).toBe('Honeytokens | AiSOC'));
  });
});
