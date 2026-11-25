import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';

import { IncidentTimelineView } from './IncidentTimeline';

import type { IncidentTimeline, IncidentTimelineEntry } from '@/lib/api';

const T0 = '2026-05-14T08:00:00Z';

function entry(partial: Partial<IncidentTimelineEntry> & { kind: 'alert' | 'event'; at: string; title: string }): IncidentTimelineEntry {
  return {
    alertId: 'alert-1',
    severity: null,
    chainStage: null,
    chainPosition: null,
    connectorType: null,
    mitreTechniques: [],
    action: null,
    userName: null,
    hostname: null,
    sourceIp: null,
    ...partial,
  };
}

function timeline(partial: Partial<IncidentTimeline> = {}): IncidentTimeline {
  return {
    caseId: 'INC-001',
    entries: [],
    alertCount: 0,
    eventCount: 0,
    eventsAvailable: true,
    eventsUnavailableReason: null,
    sourceEventIdsTruncated: false,
    truncationNote: '',
    disclaimer: 'Times are taken from the source records themselves.',
    ...partial,
  };
}

describe('IncidentTimelineView', () => {
  it('renders alerts and the events behind them in one list', () => {
    render(
      <IncidentTimelineView
        data={timeline({
          alertCount: 1,
          eventCount: 1,
          entries: [
            entry({ kind: 'event', at: T0, title: 'process_create', action: 'process_create' }),
            entry({ kind: 'alert', at: '2026-05-14T08:10:00Z', title: 'Credential dumping', severity: 'critical' }),
          ],
        })}
      />,
    );

    expect(screen.getByText('process_create')).toBeInTheDocument();
    expect(screen.getByText('Credential dumping')).toBeInTheDocument();
  });

  it('groups alerts under their kill-chain stage', () => {
    render(
      <IncidentTimelineView
        data={timeline({
          alertCount: 2,
          entries: [
            entry({ kind: 'alert', at: T0, title: 'recon alert', chainStage: 'reconnaissance', chainPosition: 1 }),
            entry({ kind: 'alert', at: '2026-05-14T09:00:00Z', title: 'exec alert', chainStage: 'execution', chainPosition: 2 }),
          ],
        })}
      />,
    );

    expect(screen.getByText(/reconnaissance/i)).toBeInTheDocument();
    expect(screen.getByText(/execution/i)).toBeInTheDocument();
  });

  it('keeps an event beside the alert it produced, not in a trailing bucket', () => {
    // Grouping events on their own (absent) stage sweeps every event to the
    // end of the page, tearing the evidence away from the alert it explains
    // and destroying the chronology this view exists to show.
    render(
      <IncidentTimelineView
        data={timeline({
          alertCount: 1,
          eventCount: 1,
          entries: [
            entry({ kind: 'event', at: T0, title: 'lsass_access', action: 'lsass_access', alertId: 'alert-1' }),
            entry({
              kind: 'alert',
              at: '2026-05-14T08:10:00Z',
              title: 'Credential dumping',
              severity: 'critical',
              alertId: 'alert-1',
              chainStage: 'credential-access',
            }),
          ],
        })}
      />,
    );

    const list = screen.getByRole('list', { name: 'Incident chronology' });
    const text = list.textContent ?? '';
    expect(text.indexOf('lsass_access')).toBeGreaterThan(-1);
    expect(text.indexOf('lsass_access')).toBeLessThan(text.indexOf('Credential dumping'));
    // One stage group, not a staged one plus an unstaged one.
    expect(screen.queryByText(/not placed in an attack story/i)).not.toBeInTheDocument();
  });

  it('says the lake could not be read rather than showing no events', () => {
    // The distinction this view exists to preserve: "nobody looked" must
    // never render the same as "nothing happened".
    render(
      <IncidentTimelineView
        data={timeline({
          alertCount: 1,
          eventsAvailable: false,
          eventsUnavailableReason:
            'The event lake is not configured on this deployment, so the raw events behind these alerts cannot be shown.',
          entries: [entry({ kind: 'alert', at: T0, title: 'an alert', severity: 'high' })],
        })}
      />,
    );

    expect(screen.getByText(/not configured on this deployment/i)).toBeInTheDocument();
    // And the alerts still render: losing the lake does not lose the case.
    expect(screen.getByText('an alert')).toBeInTheDocument();
  });

  it('does not claim the lake failed when it simply had no rows', () => {
    render(
      <IncidentTimelineView
        data={timeline({
          alertCount: 1,
          eventCount: 0,
          entries: [entry({ kind: 'alert', at: T0, title: 'an alert' })],
        })}
      />,
    );

    expect(screen.queryByText(/could not be shown|not configured/i)).not.toBeInTheDocument();
  });

  it('publishes the provenance ceiling instead of implying completeness', () => {
    render(
      <IncidentTimelineView
        data={timeline({
          alertCount: 1,
          sourceEventIdsTruncated: true,
          truncationNote:
            'At least one alert reached the 200-event provenance ceiling, so more events contributed to this incident than are listed.',
          entries: [entry({ kind: 'alert', at: T0, title: 'an alert' })],
        })}
      />,
    );

    expect(screen.getByText(/200-event provenance ceiling/i)).toBeInTheDocument();
  });

  it('shows the disclaimer rather than implying causation', () => {
    render(<IncidentTimelineView data={timeline({ entries: [entry({ kind: 'alert', at: T0, title: 'a' })] })} />);
    expect(screen.getByText(/times are taken from the source records/i)).toBeInTheDocument();
  });

  it('has an honest empty state when the case links no alerts', () => {
    render(<IncidentTimelineView data={timeline()} />);
    expect(screen.getByText(/no alerts are linked to this case/i)).toBeInTheDocument();
  });

  it('renders the event detail an analyst needs to recognise it', () => {
    render(
      <IncidentTimelineView
        data={timeline({
          eventCount: 1,
          entries: [
            entry({
              kind: 'event',
              at: T0,
              title: 'lsass_access',
              action: 'lsass_access',
              userName: 'svc-backup',
              hostname: 'WIN-DC01',
              sourceIp: '10.20.30.40',
            }),
          ],
        })}
      />,
    );

    expect(screen.getByText('svc-backup')).toBeInTheDocument();
    expect(screen.getByText('WIN-DC01')).toBeInTheDocument();
    expect(screen.getByText('10.20.30.40')).toBeInTheDocument();
  });
});
