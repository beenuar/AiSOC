/**
 * A case opened from an alert inherits that alert's severity.
 *
 * The defect: `AlertDetailView`'s "Start AI investigation" promotes the alert
 * to a case and calls `casesApi.create({ title, description, alertIds })` with
 * no `severity`. The client only serialises the key when it is present, so the
 * server default applies — `cases.py` declares `severity: CaseSeverity =
 * "medium"`. A critical alert therefore opened a MEDIUM case, and every
 * downstream surface that sorts, pages or escalates on case severity saw the
 * wrong number.
 *
 * The sibling path does it correctly: `CreateCaseModal` seeds its severity
 * select from `alertSeverityToCaseSeverity(alert.severity)`. Two call sites
 * promoting the same alert disagreed about how urgent the result was.
 *
 * Against the pre-change tree, `inherits the alert's severity` fails with
 * `severity: undefined`.
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
const investigate = vi.hoisted(() => vi.fn());
const getAlert = vi.hoisted(() => vi.fn());

vi.mock('@/lib/api', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/api')>();
  return {
    ...actual,
    alertsApi: { ...actual.alertsApi, get: getAlert },
    casesApi: { ...actual.casesApi, create: createCase, investigate },
  };
});

import type { Alert } from '@/lib/api';
import { AlertDetailView } from './AlertDetailView';
import { alertSeverityToCaseSeverity } from './CreateCaseModal';

function alertWith(id: string, severity: Alert['severity']): Alert {
  return {
    id,
    title: 'Ransomware encryption behaviour',
    description: 'desc',
    severity,
    status: 'new',
    source: 'crowdstrike',
    tenantId: 't1',
    riskScore: 90,
    createdAt: '2026-10-01T00:00:00Z',
    updatedAt: '2026-10-01T00:00:00Z',
  } as Alert;
}

beforeEach(() => {
  push.mockReset();
  createCase.mockReset();
  createCase.mockResolvedValue({ id: 'c1', caseNumber: 'CASE-1' });
  investigate.mockReset();
  investigate.mockResolvedValue({});
  getAlert.mockReset();
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

// SWR keys on `['alert', alertId]` and dedupes repeat reads of the same key
// for 2s, so each case needs its own id or the second render replays the
// first one's payload.
async function launchInvestigation(alertId: string, severity: Alert['severity']) {
  getAlert.mockResolvedValue(alertWith(alertId, severity));
  render(<AlertDetailView alertId={alertId} />);

  const button = await screen.findByRole('button', { name: /start ai investigation/i });
  await userEvent.click(button);

  await waitFor(() => expect(createCase).toHaveBeenCalled());
  return createCase.mock.calls[0][0] as { severity?: string };
}

describe('promoting an alert to a case carries the alert severity', () => {
  it("inherits the alert's severity instead of defaulting to medium", async () => {
    const payload = await launchInvestigation('alert-crit', 'critical');

    expect(payload.severity).toBe('critical');
  });

  it('does not simply hardcode the most urgent value', async () => {
    // The negative control for the assertion above: a fix that always sent
    // 'critical' would pass it, and would be a worse defect than the one
    // being fixed.
    const payload = await launchInvestigation('alert-low', 'low');

    expect(payload.severity).toBe('low');
  });

  it('folds the alert-only `info` tier through the shared mapping', async () => {
    // Cases do not model `info`. Sending it raw would be rejected by the
    // server enum, so the one mapping both call sites use folds it to `low`.
    const payload = await launchInvestigation('alert-info', 'info');

    expect(payload.severity).toBe('low');
  });
});

describe('the mapping has exactly one definition', () => {
  it('is the helper the modal already uses', () => {
    expect(alertSeverityToCaseSeverity('critical')).toBe('critical');
    expect(alertSeverityToCaseSeverity('high')).toBe('high');
    expect(alertSeverityToCaseSeverity('medium')).toBe('medium');
    expect(alertSeverityToCaseSeverity('low')).toBe('low');
    expect(alertSeverityToCaseSeverity('info')).toBe('low');
  });
});
