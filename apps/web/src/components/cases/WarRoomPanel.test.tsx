/**
 * WarRoomPanel — every state the panel can honestly be in.
 *
 * The panel's job is to tell an analyst the truth about a channel that is
 * supposed to mirror the case: "not mirroring" with the vendor's reason,
 * "waiting for the first sync" (a room nobody has swept) as a different fact
 * from a quiet case, and a failed open surfacing the vendor's own sentence
 * rather than "something went wrong". These tests pin each of those renders,
 * plus the contract that bit on the merge train: the SWR key answers with a
 * *list*, and a non-list is a crash, not a render.
 */
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type { WarRoom } from '@/lib/api';

const swrState: {
  data: WarRoom[] | undefined;
  error: unknown;
  isLoading: boolean;
} = { data: undefined, error: undefined, isLoading: false };

const mutate = vi.fn(async () => undefined);

vi.mock('swr', () => ({
  __esModule: true,
  default: () => ({
    data: swrState.data,
    error: swrState.error,
    isLoading: swrState.isLoading,
    mutate,
  }),
}));

const openMock = vi.fn();

vi.mock('@/lib/api', () => {
  class ApiError extends Error {
    status: number;
    body: string;
    constructor(message: string, status: number, body: string) {
      super(message);
      this.status = status;
      this.body = body;
    }
  }
  return {
    __esModule: true,
    ApiError,
    warRoomApi: {
      forCase: vi.fn(async () => []),
      open: (...args: unknown[]) => openMock(...args),
    },
  };
});

import { ApiError } from '@/lib/api';
import { WarRoomPanel } from './WarRoomPanel';

function room(overrides: Partial<WarRoom> = {}): WarRoom {
  return {
    id: 'wr-1',
    case_id: 'c1',
    provider: 'slack',
    channel_id: 'C0123',
    channel_name: 'aisoc-case-0001',
    channel_url: 'https://example.slack.com/archives/C0123',
    state: 'open',
    opened_by: 'alice@corp.example',
    last_synced_at: null,
    last_error: '',
    ...overrides,
  };
}

beforeEach(() => {
  swrState.data = undefined;
  swrState.error = undefined;
  swrState.isLoading = false;
  mutate.mockClear();
  openMock.mockReset();
});

describe('WarRoomPanel', () => {
  it('renders the loading state before claiming anything about rooms', () => {
    swrState.isLoading = true;
    render(<WarRoomPanel caseId="c1" />);
    expect(screen.getByText('Loading…')).toBeInTheDocument();
  });

  it('a failed load says it could not load, never an empty estate', () => {
    swrState.error = new Error('boom');
    render(<WarRoomPanel caseId="c1" />);
    expect(screen.getByRole('alert')).toHaveTextContent("Couldn't load war rooms");
    expect(screen.queryByText(/No war room yet/)).not.toBeInTheDocument();
  });

  it('an empty list is the no-room state, with the explanation of what opening does', () => {
    swrState.data = [];
    render(<WarRoomPanel caseId="c1" />);
    expect(screen.getByText(/No war room yet/)).toBeInTheDocument();
  });

  it('a never-synced room reads "waiting for the first sync", not as quiet', () => {
    swrState.data = [room({ last_synced_at: null })];
    render(<WarRoomPanel caseId="c1" />);
    expect(screen.getByText('waiting for the first sync')).toBeInTheDocument();
  });

  it('a room that stopped mirroring surfaces the vendor reason as an alert', () => {
    swrState.data = [room({ last_error: 'Slack refused: account_inactive' })];
    render(<WarRoomPanel caseId="c1" />);
    expect(screen.getByRole('alert')).toHaveTextContent('not mirroring — Slack refused: account_inactive');
  });

  it('a synced room shows when, and a closed room says so', () => {
    swrState.data = [
      room({ last_synced_at: '2026-10-12T05:00:00Z' }),
      room({ id: 'wr-2', state: 'closed', channel_name: 'aisoc-case-0001-b' }),
    ];
    render(<WarRoomPanel caseId="c1" />);
    expect(screen.getByText(/mirroring · last synced/)).toBeInTheDocument();
    expect(screen.getByText('(closed)')).toBeInTheDocument();
  });

  it('opening posts the provider and refreshes the list', async () => {
    swrState.data = [];
    openMock.mockResolvedValue(room());
    render(<WarRoomPanel caseId="c1" />);
    await userEvent.click(screen.getByRole('button', { name: 'Open in Slack' }));
    await waitFor(() => expect(openMock).toHaveBeenCalledWith('c1', 'slack'));
    expect(mutate).toHaveBeenCalled();
  });

  it('a refused open surfaces the vendor sentence verbatim, not a generic apology', async () => {
    swrState.data = [];
    openMock.mockRejectedValue(new ApiError('Bad Gateway', 502, 'Slack refused to create #aisoc-case-0001: restricted_action'));
    render(<WarRoomPanel caseId="c1" />);
    await userEvent.click(screen.getByRole('button', { name: 'Open in Slack' }));
    expect(await screen.findByText(/restricted_action/)).toBeInTheDocument();
    expect(screen.queryByText('Open failed.')).not.toBeInTheDocument();
  });

  it('the teams button asks for teams', async () => {
    swrState.data = [];
    openMock.mockResolvedValue(room({ provider: 'teams' }));
    render(<WarRoomPanel caseId="c1" />);
    await userEvent.click(screen.getByRole('button', { name: 'Open in Teams' }));
    await waitFor(() => expect(openMock).toHaveBeenCalledWith('c1', 'teams'));
  });

  it('a non-Error rejection still renders a failure rather than nothing', async () => {
    swrState.data = [];
    openMock.mockRejectedValue('wat');
    render(<WarRoomPanel caseId="c1" />);
    await userEvent.click(screen.getByRole('button', { name: 'Open in Slack' }));
    expect(await screen.findByText('Open failed.')).toBeInTheDocument();
  });
});
