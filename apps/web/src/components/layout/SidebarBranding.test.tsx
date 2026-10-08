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
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
    //
    // `logo` is the real implementation. It is the function that attaches the
    // credential, and stubbing it would move the thing under test outside the
    // test — which is how the sidebar shipped an `<img src>` the API answers
    // 401 to while this file passed.
    brandingApi: { get: async () => brandedResponse, logo: actual.brandingApi.logo },
  };
});

import { Sidebar } from './Sidebar';

const LOGO_OBJECT_URL = 'blob:http://localhost/brand-logo';

/** Every request the component made, in order. */
let requests: Array<{ url: string; headers: Record<string, string> }>;

beforeEach(() => {
  requests = [];
  vi.stubGlobal('fetch', async (url: string, init?: RequestInit) => {
    requests.push({ url: String(url), headers: (init?.headers ?? {}) as Record<string, string> });
    // The two members `brandingApi.logo` reads, and nothing else. A real
    // `Response` wrapping a real `Blob` depends on undici/jsdom interop that
    // differs between a developer machine and the runner: this test passed
    // here under every combination tried — single file, full suite, with
    // coverage — and returned a null logo on CI. Doubling the contract the
    // code reads removes the variable rather than guessing at it.
    return {
      ok: true,
      status: 200,
      blob: async () => new Blob(['<svg/>'], { type: 'image/svg+xml' }),
    } as unknown as Response;
  });
  // jsdom implements neither half of the object-URL API. Browser plumbing,
  // not ours — stubbed so the component's own code path still runs.
  vi.stubGlobal('URL', Object.assign(URL, {
    createObjectURL: () => LOGO_OBJECT_URL,
    revokeObjectURL: () => undefined,
  }));
  window.localStorage.setItem('aisoc.responder.accessToken', 'a-session-token');
});

afterEach(() => {
  window.localStorage.clear();
  vi.unstubAllGlobals();
});

describe('Sidebar branding', () => {
  // One render for every assertion, deliberately. SWR keeps a module-level
  // cache and a deduping window, so a second `render` in this file resolves
  // from neither the cache nor a fresh request and shows the unbranded
  // wordmark. Splitting these would test the cache rather than the console.
  // 20s, against vitest's 5s default. The case waits on two chained async
  // hops and the wait below is budgeted at 8s, so the test has to outlive
  // it — at the default the case timed out before asserting anything, which
  // reports nothing about the logo either way.
  it("shows a white-labelled organisation's name, palette and logo, and drops the platform wordmark", { timeout: 20_000 }, async () => {
    const { container } = render(<Sidebar />);

    expect(await screen.findByText('Acme Shield')).toBeInTheDocument();

    // The platform wordmark is gone. A console showing both is not
    // white-labelled, it is co-branded by accident.
    expect(screen.queryByText('open-source')).not.toBeInTheDocument();

    // Two chained async hops, not one: branding resolves, and only then does
    // the component fetch the asset with its credential and turn the blob
    // into an object URL. The wait is budgeted at 8s inside the 20s test
    // timeout above, so the two cannot cross — at vitest's 5s default this
    // case timed out before it could assert anything.
    //
    // The request is asserted before the element, so a failure says which
    // of the two hops broke. "expected null not to be null" on its own does
    // not distinguish a logo that was never requested from one that was
    // requested and never rendered, and that ambiguity cost a full CI round.
    await vi.waitFor(
      () => {
        expect(
          requests.map((r) => r.url),
          'the component never requested the logo asset',
        ).toContainEqual(expect.stringContaining('/branding/assets/'));
      },
      { timeout: 8_000 },
    );
    await vi.waitFor(
      () => {
        expect(
          container.querySelector('img'),
          'the asset was requested but no <img> rendered, so the blob never became an object URL',
        ).not.toBeNull();
      },
      { timeout: 8_000 },
    );
    const logo = container.querySelector('img') as HTMLImageElement;

    // The resolved palette reaches the chrome. `accent_color` was read by
    // nothing in the tree while the documentation listed it as branded.
    expect(screen.getByText('Acme Shield')).toHaveStyle({ color: '#123456' });
    expect(logo.parentElement).toHaveStyle({ borderColor: '#654321' });

    // The defect, stated as an assertion: the raw asset path must never be
    // the `src`. That route authenticates a bearer token, and an `<img>` can
    // only send a cookie — so this is what 401'd on every real deployment.
    const src = logo.getAttribute('src') ?? '';
    expect(src).toBe(LOGO_OBJECT_URL);
    expect(src.startsWith('/api/v1/branding/assets/')).toBe(false);
    // A remote logo would be an outbound request from the operator's browser
    // on every page load, telling whoever hosts it who is looking at what.
    expect(src).not.toMatch(/^https?:\/\//);

    // And the fetch that replaced it carried the credential.
    const assetRequest = requests.find((request) => request.url.includes('/branding/assets/'));
    expect(assetRequest).toBeDefined();
    expect(assetRequest?.headers.Authorization).toBe('Bearer a-session-token');
  });
});
