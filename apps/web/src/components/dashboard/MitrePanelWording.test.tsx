/**
 * The two MITRE panels say which MITRE thing they measure.
 *
 * Reported as "MITRE panels contradict each other": the dashboard showed
 * **No technique coverage yet** beside an efficiency row reading **MITRE
 * coverage 3/201**. They were never measuring the same thing —
 *
 *   * *Top MITRE ATT&CK Tactics* ranks **tactics**, from `Alert.mitre_tactics`
 *     (`metrics.py::get_dashboard_metrics`);
 *   * *MITRE coverage* counts distinct **techniques**, and unions alerts with
 *     every enabled detection rule (`metrics.py::_mitre_covered`).
 *
 * — so two different numbers are legitimate. The copy was not: one panel
 * named the other's unit, and the other claimed its figure came from the
 * tenant's alerts when most of it comes from the rule catalogue. A reader had
 * no way to tell a real disagreement from a wording bug.
 *
 * The empty description was separately false. It promised tactics would rank
 * "once detections start firing", and they will not: the detection engine
 * sets `mitre_techniques` and never `mitre_tactics`
 * (`services/fusion/app/services/detection_engine.py`), so a tenant whose
 * detections fire all day still sees this panel empty.
 *
 * These are wording assertions, which is what the defect is. Populating
 * tactics from techniques is a data change and is deliberately not attempted
 * here — see the pull request.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const dashboard = readFileSync(
  join(__dirname, 'DashboardView.tsx'),
  'utf8',
);
const efficiency = readFileSync(join(__dirname, 'EfficiencyReport.tsx'), 'utf8');

/** The empty state of the tactics panel, as written in the source. */
function tacticsPanelEmptyState(): string {
  const anchor = dashboard.indexOf('Top MITRE ATT&CK Tactics');
  expect(anchor, 'the tactics panel has been renamed').toBeGreaterThan(-1);
  // The panel's own JSX block, up to the next sibling panel.
  const end = dashboard.indexOf('Connected Sources', anchor);
  return dashboard.slice(anchor, end > anchor ? end : anchor + 1200);
}

describe('the tactics panel describes tactics', () => {
  it('does not call its own empty state "technique coverage"', () => {
    expect(tacticsPanelEmptyState()).not.toMatch(/technique coverage/i);
  });

  it('names tactics in its empty title', () => {
    expect(tacticsPanelEmptyState()).toMatch(/emptyTitle="[^"]*tactic/i);
  });

  it('does not promise tactics appear once detections fire', () => {
    // They do not: the detection engine populates `mitre_techniques` only.
    expect(tacticsPanelEmptyState()).not.toMatch(/once detections start firing/i);
  });
});

describe('the coverage row describes techniques', () => {
  it('does not claim to count tactics', () => {
    // The `<BarRow>`, not the `<LoadingBar>` placeholder above it — only the
    // former carries a description.
    const start = efficiency.indexOf('label="MITRE coverage"\n');
    expect(start, 'the coverage row has been renamed').toBeGreaterThan(-1);
    const row = efficiency.slice(start, start + 600);

    expect(row).not.toMatch(/Tactic \+ technique/i);
    expect(row).toMatch(/technique/i);
  });
});
