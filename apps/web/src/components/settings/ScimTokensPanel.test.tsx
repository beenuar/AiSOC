/**
 * The console surface `apps/docs/docs/operations/scim.md` promised.
 *
 * The doc said "mint one from the console, or through the API". Only the
 * second half existed: `/api/v1/scim-tokens` had shipped with the SCIM
 * surface and nothing under `apps/web/src` referenced it, so an
 * administrator following the doc looked for a panel that was not there.
 *
 * What these cases are for
 * -------------------------
 * The API client is mocked rather than the component's own hooks, so the
 * wiring between the two is inside the test. The three properties worth
 * pinning are the ones where a mistake is expensive rather than visible:
 *
 * - the raw secret appears exactly once, because the backend returns it
 *   exactly once and a panel that discarded it would leave the credential
 *   unrecoverable;
 * - a load failure renders an error and no rows, because a fabricated row
 *   invites someone to trust or revoke a credential that does not exist;
 * - a failed revoke leaves the row showing as active, because the reverse
 *   tells an administrator a live provisioning key is dead.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const mockList = vi.hoisted(() => vi.fn());
const mockCreate = vi.hoisted(() => vi.fn());
const mockRotate = vi.hoisted(() => vi.fn());
const mockRevoke = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', () => ({
  __esModule: true,
  scimTokensApi: {
    list: mockList,
    create: mockCreate,
    rotate: mockRotate,
    revoke: mockRevoke,
  },
}));

const mockToastError = vi.hoisted(() => vi.fn());
vi.mock('react-hot-toast', () => ({
  __esModule: true,
  default: { success: vi.fn(), error: mockToastError },
}));

import { ScimTokensPanel } from './ScimTokensPanel';

const TOKEN = {
  id: 'cd1d6cf0-0000-0000-0000-000000000001',
  name: 'corporate-directory',
  prefix: 'aisoc_scim_AbCd',
  org_id: null,
  created_at: '2026-03-10T09:00:00Z',
  last_used_at: null,
  expires_at: null,
  revoked_at: null,
  rotated_from_id: null,
  active: true,
};

beforeEach(() => {
  vi.clearAllMocks();
  mockList.mockResolvedValue([TOKEN]);
});

describe('ScimTokensPanel', () => {
  it('lists the tenant’s credentials from the real endpoint', async () => {
    render(<ScimTokensPanel />);

    await waitFor(() => expect(mockList).toHaveBeenCalled());
    expect(await screen.findByText('corporate-directory')).toBeInTheDocument();
    expect(screen.getByText('aisoc_scim_AbCd')).toBeInTheDocument();
  });

  it('shows the raw secret once, with the reason it cannot be shown again', async () => {
    mockCreate.mockResolvedValue({ ...TOKEN, token: 'aisoc_scim_the_only_time_this_exists' });
    const user = userEvent.setup();
    render(<ScimTokensPanel />);
    await waitFor(() => expect(mockList).toHaveBeenCalled());

    await user.type(screen.getByLabelText('Credential name'), 'okta');
    await user.click(screen.getByRole('button', { name: /create credential/i }));

    expect(await screen.findByText('aisoc_scim_the_only_time_this_exists')).toBeInTheDocument();
    expect(screen.getByText(/cannot be shown again/i)).toBeInTheDocument();
    expect(mockCreate).toHaveBeenCalledWith({ name: 'okta', expires_in_days: null });
  });

  it('rotates with the grace window the operator chose', async () => {
    mockRotate.mockResolvedValue({ ...TOKEN, token: 'aisoc_scim_replacement' });
    const user = userEvent.setup();
    render(<ScimTokensPanel />);
    await screen.findByText('corporate-directory');

    await user.selectOptions(screen.getByLabelText('Rotation grace window'), '0');
    await user.click(screen.getByRole('button', { name: /rotate/i }));

    // Zero is the disclosure case: the old secret dies immediately and the
    // next sync fails until the replacement is in place. Sending the
    // default instead would leave a disclosed credential live for a day.
    await waitFor(() => expect(mockRotate).toHaveBeenCalledWith(TOKEN.id, 0));
  });

  it('renders an error and no rows when the list cannot be loaded', async () => {
    mockList.mockRejectedValue(new Error('upstream is down'));
    render(<ScimTokensPanel />);

    expect(await screen.findByText(/could not load scim credentials/i)).toBeInTheDocument();
    expect(screen.queryByText('corporate-directory')).not.toBeInTheDocument();
  });

  it('leaves the row showing as active when a revoke fails', async () => {
    mockRevoke.mockRejectedValue(new Error('nope'));
    const user = userEvent.setup();
    render(<ScimTokensPanel />);
    await screen.findByText('corporate-directory');

    await user.click(screen.getByRole('button', { name: /revoke/i }));

    await waitFor(() => expect(mockToastError).toHaveBeenCalled());
    expect(screen.getByText('Active')).toBeInTheDocument();
    expect(screen.getByText('corporate-directory')).toBeInTheDocument();
  });

  it('says a credential has never been used rather than dashing the cell', async () => {
    // `last_used_at` is how an abandoned integration is found. A dash reads
    // as "no data", and the fact here is "nobody has ever synced with this".
    render(<ScimTokensPanel />);
    expect(await screen.findByText('Never')).toBeInTheDocument();
  });
});
