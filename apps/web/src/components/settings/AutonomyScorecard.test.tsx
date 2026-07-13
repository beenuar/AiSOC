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
import type { AutonomyActionPolicy, AutonomyBlastRadius } from '@/lib/api';
import { AutonomyScorecard, computeScorecard } from './AutonomyScorecard';

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
