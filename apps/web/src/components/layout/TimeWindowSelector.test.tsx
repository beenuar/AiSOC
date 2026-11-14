import { describe, expect, it, beforeEach, vi } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { TimeWindowSelector } from './TimeWindowSelector';
import { TimeWindowProvider } from './TimeWindowProvider';
import { TIME_WINDOW_STORAGE_KEY } from '@/lib/timeWindow';

const currentUserMock = vi.fn(() => null as { preferences?: Record<string, unknown> } | null);
const updateUserPreferencesMock = vi.fn(
  (_p: Record<string, unknown>) => Promise.resolve() as Promise<unknown>,
);

vi.mock('@/lib/api', () => ({
  authApi: {
    currentUser: () => currentUserMock(),
    updateUserPreferences: (p: Record<string, unknown>) => updateUserPreferencesMock(p),
  },
}));

beforeEach(() => {
  try {
    window.localStorage.removeItem(TIME_WINDOW_STORAGE_KEY);
  } catch {
    /* ignore */
  }
  currentUserMock.mockReset();
  currentUserMock.mockReturnValue(null);
  updateUserPreferencesMock.mockReset();
  updateUserPreferencesMock.mockResolvedValue(undefined as never);
});

function renderSelector() {
  return render(
    <TimeWindowProvider>
      <TimeWindowSelector />
    </TimeWindowProvider>,
  );
}

describe('TimeWindowSelector', () => {
  it('renders the short label for the active window', () => {
    renderSelector();
    expect(screen.getByRole('button', { name: /Time window/ })).toBeInTheDocument();
    // Default is "24h".
    expect(screen.getByRole('button', { name: /Time window/ })).toHaveTextContent('24h');
  });

  it('opens the dropdown and shows the four windows', async () => {
    renderSelector();
    await userEvent.click(screen.getByRole('button', { name: /Time window/ }));

    const list = screen.getByRole('listbox', { name: /Select time window/i });
    const options = within(list).getAllByRole('option');
    expect(options).toHaveLength(4);
    expect(options.map((o) => o.textContent?.trim().split('\n')[0])).toEqual([
      'Last hour',
      'Last 24 hours',
      'Last 7 days',
      'Last 30 days',
    ]);
  });

  it('updates the active window on click', async () => {
    renderSelector();
    const trigger = screen.getByRole('button', { name: /Time window/ });
    await userEvent.click(trigger);

    await userEvent.click(screen.getByRole('option', { name: /Last 7 days/i }));

    // Dropdown should close and the trigger reflects the new selection.
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
    expect(trigger).toHaveTextContent('7d');
    // Persistence: localStorage + server.
    expect(window.localStorage.getItem(TIME_WINDOW_STORAGE_KEY)).toBe('7d');
    expect(updateUserPreferencesMock).toHaveBeenCalledWith({ timeWindow: '7d' });
  });

  it('marks the active window with aria-selected', async () => {
    renderSelector();
    await userEvent.click(screen.getByRole('button', { name: /Time window/ }));

    const active = screen
      .getAllByRole('option')
      .find((opt) => opt.getAttribute('aria-selected') === 'true');
    expect(active).toBeDefined();
    expect(active).toHaveTextContent('Last 24 hours');
  });

  it('closes on Escape', async () => {
    renderSelector();
    const trigger = screen.getByRole('button', { name: /Time window/ });
    await userEvent.click(trigger);

    expect(screen.getByRole('listbox')).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument();
  });
});
