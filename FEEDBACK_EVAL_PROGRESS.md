# Feedback-eval hardening — progress tracker

Session-scratch progress file for the community-feedback brief (reflex behaviour, retrospective
analysis, precision/recall, alert reduction, evidence references, model suitability).
This file is session scratch: it tracks lane state so interrupted work can resume.

- Branch: `feat/feedback-eval-hardening` (worktree `/Users/beenu/Desktop/AiSOC-feedback-eval`)
- Base: `origin/main` @ `828ff9c5` (PR #1575 merge; #1576 in history; #1578 expected to merge mid-task — re-fetch+merge before finalizing)
- Constraints: NO push / NO merge / NO PR — local commits only. Never enable model-driven auto-closure.
- Sibling lane: bizctx (PR #1578) owns services/fusion confidence.py+asset_context.py+fusion_engine.py,
  services/actions approval_rules/dispatcher/approval_gate + api vendored copy — expect conflicts there; combine, never take one side.
- Throwaway Postgres (mine): `feedback-pg` on 55435 (bizctx-pg on 55434 is NOT mine).

## Phase status

- [x] §1 Baseline audit + gap table (in final report)
- [x] §2 Model attribution provenance + decision safeguards (attribution module; eligibility binds measurements to attributed serving identity; scorecard provenance_status + refuse-to-advertise on serving_mismatch; benchmark table Attribution column)
- [x] §3 Stage timings + queue delay + decision contract on worker/replay/logs
- [x] §4 Retro-hunt dry-run mode at the write boundary; model-knowledge disclosure on scorecards (freeze machinery pre-existing, verified)
- [x] §5 Full-cohort recall + 4 closure cuts + reliability counts + per-severity in scorer; deterministic baseline row published
- [x] §6 Conservative fallback key (before 42.6%/36 cross-rule → after 24.5%/0); SET NX creation race fixed; live-Redis suite + CI job
- [x] §7 --task verdict matrix + runtime/config records; live rows NOT MEASURED (no project credential; harness tooling key deliberately not spent)
- [x] §8 Annotated claim-support measurement (TP7 FP0 FN1 TN8 pinned; found+fixed scheduled_scan support-key gap); bundles/ledger verified pre-existing
- [x] §9 benchmark.md (attribution column + mechanism + third reduction figure), CHANGELOG, gates green, main merged (#1578 combined)
- [x] §10 Final report delivered in session summary

## Notes / decisions

(append below)

### Done so far
- app/core/model_attribution.py: gateway_header > response_body (id-witness guard against langchain requested-name fallback); never copies requested alias. run_provenance_status: verified/self_reported/unattributed(:partial)/serving_mismatch/no_calls.
- cost_telemetry: CallRecord/CostTracker/CostSummary carry attribution_source + system_fingerprint; summary exports attribution_sources.
- replay runner: decisions carry attribution_sources + severity.
- aisoc_benchmark/replay.py: full-cohort malicious recall (+4 bucket counts), 4 closure metrics (proposed-only, executed pinned 0), requested/attempted/completed/failed/unattempted, per_severity segment, attribution aggregation + renderer sections.
- eligibility: ELIGIBLE requires model_attribution; BLOCKED('cannot be bound') otherwise; decision carries model_attribution. auto_triage passes serving identity; basis line serving_model=...; exchange records serving_model/attribution/system_fingerprint.
- run_verdict_eval: provenance_status + advertisable_as_model_performance + attribution_sources on scorecard; exit 2 on live serving_mismatch (scorecard still written as diagnostic); requested_total threaded.
- check_verdict_quality: Attribution column; serving_mismatch rows refused; historical rows render 'unverified (recorded before per-decision attribution existed)'; benchmark block regenerated.

### Key audit findings (for final gap table)
- fusion: build_alert (stateless detection_engine.py:326-355 + windowed_detection.py:893-918) never sets mitre_tactics; rules carry techniques only (no tactic key in any of 760+1770+76 rules); correlation_key falls to {tenant}:{entity}:unknown and entity-less to {tenant}:unknown:unknown (tenant-wide collapse). Correlator GET-then-SET race, index-TTL vs incident-TTL asymmetry. Incidents Redis-only.
- retro-hunt: full subsystem exists (workers/retro_hunt_consumer.py + services/retro_hunt/); idempotent via UNIQUE sighting + alert idempotency key; occurrence vs intel time separated; NO dry-run/eval mode; never links original decisions.
- eligibility recorded pre-resolution alias (fixed this session: serving identity now).
- run_model_matrix records no sampling/context/hardware (§7 todo).
- measure_triage_reliability.py REPAIRED since withdrawal (imports registry; test imports it).

### Final state
- Merged origin/main @ df369dfd (#1578) combining CHANGELOG sides; all suites green post-merge: fusion 1058, agents 2193, api 5022, benchmark 101, root gates OK.
- Containers: feedback-redis (63790) can be removed; feedback-pg never needed.
