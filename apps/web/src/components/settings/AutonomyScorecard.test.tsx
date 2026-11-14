/**
 * Tests for the autonomy posture scorecard (Phase C3).
 *
 * Pins the copilot-default contract: the posture only flips to Autopilot when a
 * high/critical-blast action really does reach a vendor unattended; otherwise it
 * stays Copilot. Also checks the pure compute (distribution by blast radius,
 * auto-exec + unimplemented counts) and the rendered summary.
 *
 * Issue #1243 rewrote what "auto-executes" means here. It used to be
 * `thresholds.auto < 1` — a reading of the confidence threshold beside each
 * row, which no dispatch path consults — and on shipped defaults that made
 * nineteen of nineteen actions autonomous and put an Autopilot badge on a
 * deployment that queues all of them. It is now `effective_auto_execute`, which
 * the API resolves from the autonomy tier and the action's capability contract.
 *
 * The tests that mattered most are the two that encode the difference:
 * `a reachable confidence threshold is not an auto-execution` fails on the
 * pre-fix compute, and `an action with no verdict is not assumed autonomous`
 * pins the fail-closed direction.
 */

import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import type {
  AgreementResponse,
  AgreementWindow,
  AutonomyActionPolicy,
  AutonomyBlastRadius,
  AutonomyEffective,
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
  runtime: Partial<AutonomyActionPolicy> = {},
): AutonomyActionPolicy {
  return {
    action: name,
    blast_radius: blast,
    thresholds: { auto, review: Math.max(0, auto - 0.2), escalation: Math.max(0, auto - 0.4) },
    default_thresholds: { auto: 1, review: 0.8, escalation: 0.6 },
    overridden,
    // Default to the posture a stock install actually has: a registered verb
    // that a human signs off on.
    capability: name,
    executable: true,
    effective_auto_execute: false,
    auto_executes_at_any_tier: false,
    effective_tier: 'L1',
    effective_reason: 'The action\u2019s contract requires analyst approval even at 100% confidence.',
    ...runtime,
  };
}

const AUTO = { effective_auto_execute: true, auto_executes_at_any_tier: true } as const;

function effective(overrides: Partial<AutonomyEffective> = {}): AutonomyEffective {
  return {
    tier: 'L1',
    tier_label: 'L1-Notify',
    tier_source: 'environment',
    max_automatic_impact: 'read_only',
    auto_executing_actions: [],
    high_blast_auto_executing: [],
    unimplemented_actions: [],
    thresholds_are_advisory: true,
    advisory_note:
      'These thresholds are advisory: nothing in the response path reads them yet.',
    ...overrides,
  };
}

describe('computeScorecard', () => {
  it('a reachable confidence threshold is not an auto-execution', () => {
    // The defect, as a test. Every one of these has `auto < 1`, which the
    // pre-fix compute read as autonomous — including the high-blast one, which
    // is what flipped the badge to Autopilot on a stock install.
    const card = computeScorecard([
      action('lookup_ip', 'read', 0.0),
      action('isolate_host', 'high', 0.92),
      action('block_ip', 'high', 0.9),
    ]);
    expect(card.posture).toBe('copilot');
    expect(card.autoExecuting).toBe(0);
    expect(card.highBlastAuto).toBe(0);
  });

  it('defaults to copilot when no high-blast action auto-executes', () => {
    const card = computeScorecard([
      action('search_siem', 'read', 0.5, false, AUTO), // a read running itself is fine
      action('isolate_host', 'high', 1.0),
      action('block_ip', 'medium', 0.9, false, AUTO),
    ]);
    expect(card.posture).toBe('copilot');
    expect(card.total).toBe(3);
    expect(card.autoExecuting).toBe(2); // search_siem + block_ip
    expect(card.highBlastAuto).toBe(0);
  });

  it('flips to autopilot when a high-blast action auto-executes', () => {
    const card = computeScorecard([action('isolate_host', 'high', 0.85, false, AUTO)]);
    expect(card.posture).toBe('autopilot');
    expect(card.highBlastAuto).toBe(1);
  });

  it('an action with no verdict is not assumed autonomous', () => {
    // An older API, or a field that failed to serialise. Announcing autonomy
    // that is not there is the failure this card exists to stop, so an absent
    // answer counts as "a human approves".
    const card = computeScorecard([
      {
        ...action('isolate_host', 'high', 0.85),
        effective_auto_execute: undefined,
        auto_executes_at_any_tier: undefined,
      },
    ]);
    expect(card.posture).toBe('copilot');
    expect(card.autoExecuting).toBe(0);
  });

  it('counts a verb with no executor apart from one a human approves', () => {
    const card = computeScorecard([
      action('delete_object', 'critical', 0.95, false, { capability: null, executable: false }),
      action('isolate_host', 'high', 0.92),
    ]);
    expect(card.unimplemented).toBe(1);
    expect(card.autoExecuting).toBe(0);
    expect(card.highBlastTotal).toBe(2);
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
    render(<AutonomyScorecard actions={[action('isolate_host', 'high', 0.92)]} />);
    expect(screen.getByText('Copilot')).toBeInTheDocument();
    expect(screen.getByText(/always require a human/i)).toBeInTheDocument();
  });

  it('claims only what the current tier supports when a contract could ever allow it', () => {
    // `auto_executes_at_any_tier` is true, so "no tier executes these
    // unattended" would be false. The weaker sentence is the true one.
    render(
      <AutonomyScorecard
        actions={[action('isolate_host', 'high', 0.92, false, { auto_executes_at_any_tier: true })]}
      />,
    );
    expect(screen.getByText('Copilot')).toBeInTheDocument();
    expect(screen.getByText(/at the current autonomy tier/i)).toBeInTheDocument();
    expect(screen.queryByText(/no autonomy tier/i)).not.toBeInTheDocument();
  });

  it('renders the Autopilot badge with a warning when high-blast auto-executes', () => {
    render(<AutonomyScorecard actions={[action('isolate_host', 'high', 0.8, false, AUTO)]} />);
    expect(screen.getByText('Autopilot')).toBeInTheDocument();
    expect(screen.getByText(/auto-execute/i)).toBeInTheDocument();
  });

  it('names the tier the posture was derived from, and where it came from', () => {
    // A badge with no stated basis is how a posture read off the wrong table
    // went unchallenged for as long as it did.
    render(
      <AutonomyScorecard actions={[action('isolate_host', 'high', 0.92)]} effective={effective()} />,
    );
    expect(screen.getByText('L1-Notify')).toBeInTheDocument();
    expect(screen.getByText(/deployment default/i)).toBeInTheDocument();
    expect(screen.getByText(/up to read only impact/i)).toBeInTheDocument();
  });

  it('says the thresholds are advisory rather than leaving the sliders to imply otherwise', () => {
    render(
      <AutonomyScorecard actions={[action('isolate_host', 'high', 0.92)]} effective={effective()} />,
    );
    expect(screen.getByText(/nothing in the response path reads them/i)).toBeInTheDocument();
  });

  it('names the verbs with no executor instead of showing them as gated actions', () => {
    render(
      <AutonomyScorecard
        actions={[
          action('delete_object', 'critical', 0.95, false, { capability: null, executable: false }),
        ]}
        effective={effective({ unimplemented_actions: ['delete_object'] })}
      />,
    );
    expect(screen.getByText(/No executor is registered for/i)).toBeInTheDocument();
    expect(screen.getByText('delete_object')).toBeInTheDocument();
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
