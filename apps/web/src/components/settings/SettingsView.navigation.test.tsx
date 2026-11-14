import { act, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { NavigationTestProvider } from '@/test/NavigationTestProvider';
import { ThemeProvider } from '@/components/theme/ThemeProvider';
import { SettingsView } from './SettingsView';

// Panel data is independent of navigation. Keep the actual view, router hook,
// sidebar and panels; do not issue backend requests for this component suite.
vi.mock('swr', () => ({
  default: () => ({ data: undefined, error: undefined, isLoading: false, mutate: vi.fn() }),
}));

function renderSettings() {
  return render(<ThemeProvider><SettingsView /></ThemeProvider>, { wrapper: NavigationTestProvider });
}

beforeEach(() => {
  window.history.replaceState(null, '', '/settings');
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Settings URL navigation', () => {
  it('opens Deployment & AI directly from the onboarding deep link', () => {
    window.history.replaceState(null, '', '/settings?tab=deployment');
    renderSettings();

    expect(screen.getByRole('heading', { name: 'Deployment & AI' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'Profile' })).not.toBeInTheDocument();
  });

  it.each([
    ['profile', 'Profile'],
    ['workspace', 'Workspace'],
    ['integrations', 'Integrations'],
    ['autonomy', 'Autonomy guardrails'],
    ['api-keys', 'API keys'],
    ['scim', 'SCIM provisioning'],
    ['branding', 'Branding'],
    ['retention', 'Retention'],
    ['rule-packs', 'Rule packs'],
    ['delegations', 'Delegations'],
    ['notifications', 'Notifications'],
    ['appearance', 'Appearance'],
    ['deployment', 'Deployment & AI'],
    ['audit', 'Audit log'],
    ['about', 'About'],
  ])('selects the %s section from its URL', (tab, label) => {
    window.history.replaceState(null, '', `/settings?tab=${tab}`);
    renderSettings();

    const nav = within(screen.getByRole('navigation', { name: 'Settings sections' }));
    expect(nav.getByRole('button', { current: 'page' })).toHaveTextContent(label);
  });

  it.each(['', '?tab=', '?tab=unknown', '?tab=constructor', '?tab=%2Fsettings'])
  ('falls back to Profile for %s', (query) => {
    window.history.replaceState(null, '', `/settings${query}`);
    renderSettings();

    expect(screen.getByRole('heading', { name: 'Profile' })).toBeInTheDocument();
  });

  it('updates the URL on a click and keeps unrelated query values and the fragment', async () => {
    window.history.replaceState(null, '', '/settings?window=7d&filter=a&filter=b#details');
    renderSettings();
    await userEvent.click(screen.getByRole('button', { name: /^Deployment & AI/ }));

    expect(await screen.findByRole('heading', { name: 'Deployment & AI' })).toBeInTheDocument();
    const url = new URL(window.location.href);
    expect(url.searchParams.get('tab')).toBe('deployment');
    expect(url.searchParams.get('window')).toBe('7d');
    expect(url.searchParams.getAll('filter')).toEqual(['a', 'b']);
    expect(url.hash).toBe('#details');
  });

  it('follows a query-only navigation without remounting', async () => {
    renderSettings();
    act(() => window.history.pushState(null, '', '/settings?tab=deployment'));
    expect(await screen.findByRole('heading', { name: 'Deployment & AI' })).toBeInTheDocument();

    act(() => window.history.replaceState(null, '', '/settings?tab=invalid'));
    expect(await screen.findByRole('heading', { name: 'Profile' })).toBeInTheDocument();
  });

  it('does not add history entries when the selected section is clicked again', async () => {
    window.history.replaceState(null, '', '/settings?tab=deployment');
    renderSettings();
    const push = vi.spyOn(window.history, 'pushState');
    await userEvent.click(screen.getByRole('button', { name: /^Deployment & AI/ }));

    expect(push).not.toHaveBeenCalled();
  });
});
