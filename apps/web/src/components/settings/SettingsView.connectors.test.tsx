import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { SWRConfig } from 'swr';
import { connectorsApi } from '@/lib/api';
import { SettingsView } from './SettingsView';
import { NavigationTestProvider } from '@/test/NavigationTestProvider';

beforeEach(() => {
  window.history.replaceState(null, '', '/settings');
  vi.spyOn(connectorsApi, 'list').mockResolvedValue({ connectors: [], total: 0 });
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('Settings integration links', () => {
  it.each(['+ Add connector', 'Add connector'])(
    'routes "%s" to the existing connector inventory',
    async (name) => {
      const user = userEvent.setup();
      // Keep the real view, Link and SWR behavior; isolate only the API and cache.
      render(
        <SWRConfig value={{ provider: () => new Map() }}>
          <SettingsView />
        </SWRConfig>,
        { wrapper: NavigationTestProvider },
      );
      // The sidebar button's accessible name concatenates the label and its
      // description ("IntegrationsManage the connectors…"), so a \b after the
      // label can never match — both sides are word characters.
      await user.click(screen.getByRole('button', { name: /^Integrations/ }));
      await screen.findByRole('heading', { name: 'No connectors yet' });

      expect(connectorsApi.list).toHaveBeenCalled();
      expect(screen.getByRole('link', { name })).toHaveAttribute(
        'href',
        '/connectors',
      );
    },
  );
});
