'use client';

/**
 * SOC operations dashboard.
 *
 * `/dashboard` answers "what is happening in the estate". This one answers
 * "is the machine that tells me what is happening actually working" — a
 * different question, and the one an alert-centric view structurally cannot
 * answer, because every failure mode of the pipeline makes it *quieter*.
 *
 * Five panels, each backed by one real endpoint:
 *
 *   - connector fleet staleness          GET /api/v1/health/fleet
 *   - rejected events by reason          GET /api/v1/health/dead-letters
 *   - alert severity + disposition       GET /api/v1/alerts/stats
 *   - agent runs, tokens, spend          GET /api/v1/costs/dashboard
 *   - actions awaiting approval          GET /api/v1/approvals?status=pending
 *
 * Plus the existing funnel strip and detection-coverage summary, which are
 * already real-data-driven and are reused rather than re-implemented.
 *
 * Every panel owns its own fetch, loading, empty and error state. One dead
 * endpoint blanks one panel and says why, rather than taking the page down or
 * — the failure mode this codebase has shipped before — quietly substituting
 * plausible numbers.
 */

import { FunnelKpiBar } from '../FunnelKpiBar';
import { PipelineHealth } from '../PipelineHealth';
import { ConnectorFleetPanel } from './ConnectorFleetPanel';
import { RejectedEventsPanel } from './RejectedEventsPanel';
import { AlertPosturePanel } from './AlertPosturePanel';
import { AgentThroughputPanel } from './AgentThroughputPanel';
import { ResponseActionsPanel } from './ResponseActionsPanel';
import { DetectionCoveragePanel } from './DetectionCoveragePanel';

export function OperationsDashboard() {
  return (
    <div className="space-y-5">
      <header>
        <h1 className="text-xl font-semibold text-gray-100">SOC operations</h1>
        <p className="mt-1 text-sm text-gray-500">
          Whether the detection pipeline is working, independent of whether it is
          finding anything. Every panel is driven by a live API response; a panel
          with no data says so rather than showing a placeholder.
        </p>
      </header>

      <FunnelKpiBar period="24h" />

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <ConnectorFleetPanel />
        <div className="space-y-4">
          <PipelineHealth />
          <RejectedEventsPanel />
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <AlertPosturePanel />
        <DetectionCoveragePanel />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <AgentThroughputPanel />
        <ResponseActionsPanel />
      </div>
    </div>
  );
}
