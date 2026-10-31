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

- [ ] §1 Baseline audit + gap table
- [x] §2 Model attribution provenance + decision safeguards (attribution module; eligibility binds measurements to attributed serving identity; scorecard provenance_status + refuse-to-advertise on serving_mismatch; benchmark table Attribution column)
- [ ] §3 Reflex path observability + bounded verification
- [ ] §4 Historical replay vs re-hunting separation
- [ ] §5 Evaluation data + metric definitions (precision/recall/confusion/closure)
- [ ] §6 Alert reduction through production path
- [ ] §7 Model suitability matrix (offline harness; live only if creds exist)
- [ ] §8 Evidence references + adversarial checks
- [ ] §9 Tests, reports, documentation
- [ ] §10 Final report

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
