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
- [ ] §2 Model attribution provenance + decision safeguards
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
