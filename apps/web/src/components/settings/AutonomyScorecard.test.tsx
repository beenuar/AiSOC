/**
 * Tests for the autonomy posture scorecard (Phase C3).
 *
 * Pins the copilot-default contract: the posture only flips to Autopilot when a
 * high/critical-blast action is configured to auto-execute; otherwise it stays
 * Copilot (a human signs off on high-blast actions). Also checks the pure
 * compute (distribution by blast radius, auto-exec + override counts) and the
 * rendered summary.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import type {
  AgreementResponse,
  AgreementWindow,
  AutonomyActionPolicy,
  AutonomyBlastRadius,
  AutonomyGrant,
} from '@/lib/api';
import {
  AutonomyScorecard,
  computeScorecard,
  formatRate,
  summariseTrackRecord,
} from './AutonomyScorecard';

function action(
  name: string,
  blast: AutonomyBlastRadius,
  auto: number,
  overridden = false,
): AutonomyActionPolicy {
  return {
    action: name,
    blast_radius: blast,
    thresholds: { auto, review: Math.max(0, auto - 0.2), escalation: Math.max(0, auto - 0.4) },
    default_thresholds: { auto: 1, review: 0.8, escalation: 0.6 },
    overridden,
  };
}

describe('computeScorecard', () => {
  it('defaults to copilot when no high-blast action auto-executes', () => {
    const card = computeScorecard([
      action('notify_slack', 'read', 0.5), // low blast auto-exec is fine
      action('isolate_host', 'high', 1.0), // auto == 1.0 => never auto
      action('block_ip', 'medium', 0.9),
    ]);
    expect(card.posture).toBe('copilot');
    expect(card.total).toBe(3);
    expect(card.autoExecuting).toBe(2); // notify + block_ip
    expect(card.highBlastAuto).toBe(0);
  });

  it('flips to autopilot when a high-blast action auto-executes', () => {
    const card = computeScorecard([
      action('isolate_host', 'high', 0.85), // high blast, auto-executes
    ]);
    expect(card.posture).toBe('autopilot');
    expect(card.highBlastAuto).toBe(1);
  });

  it('counts overrides and distribution by blast radius', () => {
    const card = computeScorecard([
      action('a', 'read', 0.5, true),
      action('b', 'read', 0.5),
      action('c', 'critical', 1.0),
    ]);
    expect(card.overridden).toBe(1);
    expect(card.byBlast.read).toBe(2);
    expect(card.byBlast.critical).toBe(1);
  });

  it('handles an empty policy', () => {
    const card = computeScorecard([]);
    expect(card.total).toBe(0);
    expect(card.posture).toBe('copilot');
  });
});

describe('AutonomyScorecard', () => {
  it('renders the Copilot badge by default', () => {
    render(<AutonomyScorecard actions={[action('isolate_host', 'high', 1.0)]} />);
    expect(screen.getByText('Copilot')).toBeInTheDocument();
    expect(screen.getByText(/always require a human/i)).toBeInTheDocument();
  });

  it('renders the Autopilot badge with a warning when high-blast auto-executes', () => {
    render(<AutonomyScorecard actions={[action('isolate_host', 'high', 0.8)]} />);
    expect(screen.getByText('Autopilot')).toBeInTheDocument();
    expect(screen.getByText(/auto-execute/i)).toBeInTheDocument();
  });
});

// ─── Measured track record (gap-closure Phase 2.2) ───────────────────────────
//
// The posture above is what the tenant configured. This half is what the agent
// earned. The tests worth having are about the two ways this display can lie:
// printing a zero where nothing was measured, and printing a rate without the
// count behind it.

function agreementResponse(overrides: Partial<AgreementWindow> = {}): AgreementResponse {
  const window: AgreementWindow = {
    resolved: 120,
    labelled: 100,
    unlabeled: 20,
    answered: 90,
    abstained: 10,
    agreed: 87,
    malicious_support: 31,
    malicious_caught: 29,
    agreement_rate: 87 / 90,
    malicious_recall: 29 / 31,
    abstention_rate: 10 / 100,
    ...overrides,
  };
  return {
    tenant_id: 't',
    scope_kind: 'tenant',
    scope_key: '*',
    window,
    recent: { ...window, answered: 50, agreed: 40, agreement_rate: 0.8 },
    window_start: '2026-08-27T00:00:00+00:00',
    window_end: '2026-09-26T00:00:00+00:00',
    thresholds: {
      min_decisions: 100,
      min_malicious: 30,
      min_agreement: 0.95,
      min_malicious_recall: 0.9,
      max_abstention_rate: 0.3,
      window_days: 30,
      demotion_agreement: 0.9,
      demotion_malicious_recall: 0.8,
      drift_sample: 50,
      drift_min_answered: 20,
    },
    reconciled: 0,
    by_alert_class: [],
    by_rule: [],
    by_source: [],
    by_model: [],
  };
}

describe('formatRate', () => {
  it('renders a missing denominator as words, never as zero', () => {
    // A zero here says the agent was wrong every time. "It was never asked" is
    // a different fact, and on a new deployment it is always the true one.
    expect(formatRate(null)).toBe('not measured');
    expect(formatRate(undefined)).toBe('not measured');
  });

  it('renders a real zero as a zero', () => {
    expect(formatRate(0)).toBe('0.0%');
  });
});

describe('summariseTrackRecord', () => {
  it('returns nothing when no agreement has been fetched', () => {
    expect(summariseTrackRecord(undefined)).toBeNull();
  });

  it('marks a tenant with no closed decisions as unmeasured', () => {
    const summary = summariseTrackRecord(
      agreementResponse({ resolved: 0, labelled: 0, answered: 0, abstained: 0, agreed: 0 }),
    );
    expect(summary?.measured).toBe(false);
  });

  it('carries the counts each rate was computed over', () => {
    const summary = summariseTrackRecord(agreementResponse());
    expect(summary?.answered).toBe(90);
    expect(summary?.maliciousSupport).toBe(31);
    expect(summary?.labelled).toBe(100);
  });

  it('carries the trailing slice separately from the window', () => {
    // The window average is where a gradual decline hides. Folding the two
    // into one number would make this card conceal the thing it exists to show.
    const summary = summariseTrackRecord(agreementResponse());
    expect(summary?.agreement).toBeCloseTo(87 / 90);
    expect(summary?.recentAgreement).toBeCloseTo(0.8);
  });
});

describe('<AutonomyScorecard /> track record', () => {
  it('says there is no measurement rather than rendering zeroes', () => {
    render(<AutonomyScorecard actions={[action('block_ip', 'medium', 0.9)]} />);
    expect(screen.getByText(/No measured track record yet/i)).toBeInTheDocument();
  });

  it('shows the sample as a fraction of the floor, not as a percentage', () => {
    // On a card where every other figure is a percentage, "47%" would be read
    // as a fifth accuracy number rather than as progress toward a threshold.
    render(
      <AutonomyScorecard
        actions={[action('block_ip', 'medium', 0.9)]}
        agreement={agreementResponse()}
      />,
    );
    expect(screen.getByText('100 / 100')).toBeInTheDocument();
    expect(screen.getByText('31 / 30 malicious')).toBeInTheDocument();
  });

  it('prints not measured for a rate with no denominator', () => {
    render(
      <AutonomyScorecard
        actions={[action('block_ip', 'medium', 0.9)]}
        agreement={agreementResponse({ malicious_support: 0, malicious_caught: 0, malicious_recall: null })}
      />,
    );
    expect(screen.getByText('not measured')).toBeInTheDocument();
  });
});

// ─── Earned autonomy (gap-closure Phase 2.3) ─────────────────────────────────
//
// One property, and it is the reason the grant carries a `source` at all: an
// override must stay legible as an override. Autonomy somebody earned and
// autonomy somebody overruled a refusal to grant behave identically and are
// very different things to be reading during an incident review.

function grant(overrides: Partial<AutonomyGrant> = {}): AutonomyGrant {
  return {
    id: 'g1',
    scope_kind: 'alert_class',
    scope_key: 'identity',
    capability: 'auto_close',
    state: 'granted',
    source: 'earned',
    is_override: false,
    ...overrides,
  };
}

describe('<AutonomyScorecard /> earned autonomy', () => {
  it('says nothing when the tenant holds no capabilities', () => {
    render(<AutonomyScorecard actions={[action('block_ip', 'medium', 0.9)]} grants={[]} />);
    expect(screen.queryByText(/Autonomy granted/i)).not.toBeInTheDocument();
  });

  it('labels an earned grant as earned', () => {
    render(<AutonomyScorecard actions={[action('block_ip', 'medium', 0.9)]} grants={[grant()]} />);
    expect(screen.getByText('earned')).toBeInTheDocument();
    expect(screen.queryByText('operator override')).not.toBeInTheDocument();
  });

  it('labels an override as an override and shows the stated reason', () => {
    render(
      <AutonomyScorecard
        actions={[action('block_ip', 'medium', 0.9)]}
        grants={[
          grant({
            source: 'operator_override',
            is_override: true,
            override_reason: 'Accepted for a two-week pilot',
          }),
        ]}
      />,
    );
    expect(screen.getByText('operator override')).toBeInTheDocument();
    expect(screen.getByText('Accepted for a two-week pilot')).toBeInTheDocument();
  });

  it('keeps a demoted grant visible with why it was taken away', () => {
    // A capability that was revoked is more interesting than one never held,
    // and hiding it would make "what happened to our auto-close" unanswerable
    // from this page.
    render(
      <AutonomyScorecard
        actions={[action('block_ip', 'medium', 0.9)]}
        grants={[grant({ state: 'demoted', demoted_reason: 'recent_drift' })]}
      />,
    );
    expect(screen.getByText('demoted')).toBeInTheDocument();
    expect(screen.getByText('recent_drift')).toBeInTheDocument();
  });
});
