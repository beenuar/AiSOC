/**
 * An attack story is the easiest thing in a SOC console to fabricate.
 *
 * Given one alert with one technique, a plausible five-stage kill chain can
 * be drawn and it will look more convincing than the single event it came
 * from. These tests are mostly about what the component must refuse to draw.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AttackStory, buildEvidenceSources, buildStages } from './AttackStory';
import type { Alert, MitreAttack } from '@/lib/api';

function makeAlert(overrides: Partial<Alert> = {}): Alert {
  return {
    id: 'a1b2c3d4-0000-0000-0000-000000000000',
    title: 'Suspicious PowerShell execution',
    description: 'Encoded command launched from Office',
    severity: 'high',
    status: 'new',
    source: 'CrowdStrike',
    tenantId: 't1',
    riskScore: 72,
    createdAt: '2026-09-22T10:00:00Z',
    updatedAt: '2026-09-22T10:00:00Z',
    ...overrides,
  } as Alert;
}

const technique = (tactic: string, id: string, name = 'Technique'): MitreAttack => ({
  tactic,
  technique: name,
  techniqueId: id,
});

describe('buildStages', () => {
  it('orders stages by kill-chain position, not by input order', () => {
    const stages = buildStages([
      technique('exfiltration', 'T1041'),
      technique('initial-access', 'T1566'),
      technique('lateral-movement', 'T1021'),
    ]);
    expect(stages.map((s) => s.tactic)).toEqual([
      'initial-access',
      'lateral-movement',
      'exfiltration',
    ]);
  });

  it('does not interpolate the stages between the ones observed', () => {
    // The whole point. Initial access + exfiltration is two stages, not the
    // eleven between them — a guess drawn as a diagram reads as a finding.
    const stages = buildStages([
      technique('initial-access', 'T1566'),
      technique('exfiltration', 'T1041'),
    ]);
    expect(stages).toHaveLength(2);
  });

  it('groups multiple techniques under one tactic', () => {
    const stages = buildStages([
      technique('execution', 'T1059.001', 'PowerShell'),
      technique('execution', 'T1059.003', 'Windows Command Shell'),
    ]);
    expect(stages).toHaveLength(1);
    expect(stages[0].techniques).toHaveLength(2);
  });

  it('treats a repeated technique id as a duplicate, not a second occurrence', () => {
    const stages = buildStages([
      technique('execution', 'T1059.001'),
      technique('execution', 'T1059.001'),
    ]);
    expect(stages[0].techniques).toHaveLength(1);
  });

  it('sorts an unrecognised tactic last rather than first', () => {
    // First would place a vendor-specific label at the head of the chain and
    // imply it started there.
    const stages = buildStages([
      technique('vendor-specific-thing', 'X0001'),
      technique('impact', 'T1486'),
    ]);
    expect(stages.map((s) => s.tactic)).toEqual(['impact', 'vendor-specific-thing']);
  });

  it('tolerates casing and spacing differences in tactic names', () => {
    const stages = buildStages([
      technique('Initial Access', 'T1566'),
      technique('initial-access', 'T1190'),
    ]);
    expect(stages).toHaveLength(1);
  });

  it('ignores techniques with no tactic rather than inventing one', () => {
    const stages = buildStages([technique('', 'T9999')]);
    expect(stages).toHaveLength(0);
  });
});

describe('buildEvidenceSources', () => {
  it('omits a source that contributed nothing', () => {
    // An empty source reads as "we looked and found nothing", which is a
    // different claim from "this source was not involved".
    const sources = buildEvidenceSources(makeAlert({ source: 'CrowdStrike' }), [], []);
    expect(sources.map((s) => s.source)).toEqual(['CrowdStrike']);
  });

  it('does not count an unknown source as a source', () => {
    const sources = buildEvidenceSources(makeAlert({ source: 'unknown' }), [], []);
    expect(sources).toHaveLength(0);
  });

  it('counts contributions per source', () => {
    const sources = buildEvidenceSources(
      makeAlert({ source: 'Okta' }),
      [
        { id: '1', timestamp: '', type: 't', title: 'x', source: 'audit_log' },
        { id: '2', timestamp: '', type: 't', title: 'y', source: 'audit_log' },
      ],
      [],
    );
    expect(sources.find((s) => s.source === 'Audit log')?.count).toBe(2);
  });
});

describe('AttackStory', () => {
  it('says a single-stage detection is not a chain', async () => {
    render(<AttackStory alert={makeAlert({ mitreAttack: [technique('execution', 'T1059')] })} />);
    expect(await screen.findByText(/single-stage detection, not a/i)).toBeInTheDocument();
  });

  it('does not claim a single stage is a chain when there are several', () => {
    render(
      <AttackStory
        alert={makeAlert({
          mitreAttack: [technique('initial-access', 'T1566'), technique('impact', 'T1486')],
        })}
      />,
    );
    expect(screen.queryByText(/single-stage detection/i)).not.toBeInTheDocument();
  });

  it('attributes a missing tactic map to the detection, not to the activity', () => {
    render(<AttackStory alert={makeAlert({ mitreAttack: [] })} />);
    expect(
      screen.getByText(/gap in the detection.s metadata rather than a statement/i),
    ).toBeInTheDocument();
  });

  it('flags that a single evidence source is not corroboration', () => {
    render(<AttackStory alert={makeAlert({ source: 'CrowdStrike' })} />);
    expect(screen.getByText(/Corroboration across sources/i)).toBeInTheDocument();
  });

  it('shows the alert confidence without computing a second number', () => {
    render(<AttackStory alert={makeAlert({ confidenceScore: 84, confidenceLabel: 'high' })} />);
    expect(screen.getByText('84')).toBeInTheDocument();
    expect(screen.getByText(/not a probability that the verdict is correct/i)).toBeInTheDocument();
  });

  it('omits confidence entirely when none was scored', () => {
    // Rendering 0 would say every verdict was baseless; the truth is that
    // none was measured.
    render(<AttackStory alert={makeAlert({ confidenceScore: undefined })} />);
    expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
  });

  it('stages an action for approval rather than executing it', async () => {
    const onStageActions = vi.fn();
    render(
      <AttackStory
        alert={makeAlert({
          recommendedActions: [
            { priority: 'high', action: 'Isolate WS-042', rationale: 'Confirmed execution' },
          ],
        })}
        onStageActions={onStageActions}
      />,
    );

    expect(screen.getByText(/Nothing executes from this panel/i)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('checkbox'));
    expect(onStageActions).toHaveBeenCalledWith([
      expect.objectContaining({ action: 'Isolate WS-042' }),
    ]);
    expect(screen.getByText(/sends them for approval/i)).toBeInTheDocument();
  });

  it('says so when no action was recommended', () => {
    render(<AttackStory alert={makeAlert({ recommendedActions: [] })} />);
    expect(screen.getByText(/No actions have been recommended/i)).toBeInTheDocument();
  });

  it('renders nothing fabricated for a bare alert', () => {
    // The adversarial case: an alert with no techniques, no timeline, no
    // entities and no actions must produce four honest empty states rather
    // than a plausible story.
    render(<AttackStory alert={makeAlert({ source: 'unknown' })} />);
    expect(screen.getByText(/no ATT&CK tactic is mapped/i)).toBeInTheDocument();
    expect(screen.getByText(/No evidence source is attributable/i)).toBeInTheDocument();
    expect(screen.getByText(/No actions have been recommended/i)).toBeInTheDocument();
    expect(screen.queryByRole('listitem')).not.toBeInTheDocument();
  });
});
