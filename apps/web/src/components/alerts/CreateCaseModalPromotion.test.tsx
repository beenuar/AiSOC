/**
 * The promotion modal's own submit path.
 *
 * `AlertCaseSeverity.test.tsx` proves the *detail view* now sends the alert's
 * severity when it promotes. It reaches that assertion through
 * `AlertDetailView`, so the modal — the other call site of the mapping this
 * change unified, and the one an analyst actually clicks through — never runs
 * in it. A regression in `handleSubmit` would leave that suite green.
 *
 * So this covers the modal end to end: both tabs, the guard that refuses a
 * stub title, and the severity the seeded select actually submits.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

const push = vi.hoisted(() => vi.fn());

vi.mock('next/navigation', () => ({
  useRouter: () => ({ push, replace: vi.fn(), refresh: vi.fn(), back: vi.fn() }),
  usePathname: () => '/alerts/a1',
  useSearchParams: () => new URLSearchParams(),
}));

const createCase = vi.hoisted(() => vi.fn());
const linkAlerts = vi.hoisted(() => vi.fn());
const listCases = vi.hoisted(() => vi.fn());
const toastError = vi.hoisted(() => vi.fn());
const toastSuccess = vi.hoisted(() => vi.fn());

vi.mock('react-hot-toast', () => ({
  default: { success: toastSuccess, error: toastError },
}));

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    casesApi: { ...actual.casesApi, create: createCase, linkAlerts, list: listCases },
  };
});

import type { Alert } from '@/lib/api';
import { CreateCaseModal } from './CreateCaseModal';

function alertWith(severity: Alert['severity']): Alert {
  return {
    id: 'alert-1',
    title: 'Credential dumping via LSASS access',
    description: 'desc',
    severity,
    status: 'new',
    source: 'crowdstrike',
    tenantId: 't1',
    createdAt: '2026-10-01T00:00:00Z',
    updatedAt: '2026-10-01T00:00:00Z',
  } as Alert;
}

beforeEach(() => {
  push.mockReset();
  createCase.mockReset();
  createCase.mockResolvedValue({ id: 'c1', caseNumber: 'CASE-1' });
  linkAlerts.mockReset();
  linkAlerts.mockResolvedValue({ id: 'c9', caseNumber: 'CASE-9' });
  listCases.mockReset();
  listCases.mockResolvedValue({ cases: [{ id: 'c9', caseNumber: 'CASE-9', title: 'Existing intrusion' }] });
  toastError.mockReset();
  toastSuccess.mockReset();
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe('creating a new case from the modal', () => {
  it("submits the alert's severity, not the server default", async () => {
    render(<CreateCaseModal open onClose={vi.fn()} alert={alertWith('critical')} />);

    await userEvent.click(screen.getByRole('button', { name: /create case/i }));

    await waitFor(() => expect(createCase).toHaveBeenCalled());
    expect(createCase.mock.calls[0][0]).toMatchObject({ severity: 'critical', alertIds: ['alert-1'] });
  });

  it('folds `info` to the lowest tier a case can hold', async () => {
    // Cases have no `info`. Submitting it raw would be refused by the server
    // enum, which is why both call sites resolve through one mapping.
    render(<CreateCaseModal open onClose={vi.fn()} alert={alertWith('info')} />);

    await userEvent.click(screen.getByRole('button', { name: /create case/i }));

    await waitFor(() => expect(createCase).toHaveBeenCalled());
    expect(createCase.mock.calls[0][0]).toMatchObject({ severity: 'low' });
  });

  it('does not hardcode one tier for every alert', async () => {
    // The negative control: a mapping that always answered `critical` would
    // satisfy the first case and be a worse defect than the one it fixed.
    render(<CreateCaseModal open onClose={vi.fn()} alert={alertWith('low')} />);

    await userEvent.click(screen.getByRole('button', { name: /create case/i }));

    await waitFor(() => expect(createCase).toHaveBeenCalled());
    expect(createCase.mock.calls[0][0]).toMatchObject({ severity: 'low' });
  });

  it('refuses a title too short to identify the case later', async () => {
    render(<CreateCaseModal open onClose={vi.fn()} alert={alertWith('high')} />);

    await userEvent.clear(screen.getByLabelText(/title/i));
    await userEvent.type(screen.getByLabelText(/title/i), 'ab');
    await userEvent.click(screen.getByRole('button', { name: /create case/i }));

    expect(createCase).not.toHaveBeenCalled();
    expect(toastError).toHaveBeenCalled();
  });

  it('reports a failed create instead of navigating to a case that does not exist', async () => {
    createCase.mockRejectedValue(new Error('500'));
    render(<CreateCaseModal open onClose={vi.fn()} alert={alertWith('high')} />);

    await userEvent.click(screen.getByRole('button', { name: /create case/i }));

    await waitFor(() => expect(toastError).toHaveBeenCalled());
    expect(push).not.toHaveBeenCalled();
  });
});

describe('attaching the alert to an existing case', () => {
  it('links rather than creating a second case for the same alert', async () => {
    render(<CreateCaseModal open onClose={vi.fn()} alert={alertWith('high')} />);

    await userEvent.click(screen.getByRole('button', { name: /add to existing case/i }));
    await waitFor(() => expect(listCases).toHaveBeenCalled());
    await screen.findByRole('option', { name: /CASE-9/ });
    await userEvent.selectOptions(screen.getByLabelText(/open case/i), 'c9');
    await userEvent.click(screen.getByRole('button', { name: /add to case/i }));

    await waitFor(() => expect(linkAlerts).toHaveBeenCalledWith('c9', ['alert-1']));
    expect(createCase).not.toHaveBeenCalled();
  });

  it('refuses to submit when no case has been picked', async () => {
    render(<CreateCaseModal open onClose={vi.fn()} alert={alertWith('high')} />);

    await userEvent.click(screen.getByRole('button', { name: /add to existing case/i }));
    await userEvent.click(screen.getByRole('button', { name: /add to case/i }));

    expect(linkAlerts).not.toHaveBeenCalled();
    expect(toastError).toHaveBeenCalled();
  });
});

describe('the modal renders nothing while closed', () => {
  it('mounts no dialog, and asks the API for no cases', () => {
    render(<CreateCaseModal open={false} onClose={vi.fn()} alert={alertWith('high')} />);

    expect(screen.queryByRole('dialog')).toBeNull();
    expect(listCases).not.toHaveBeenCalled();
  });
});
