# Phase 4a — read-only approval split + verification probes

Worktree: `/Users/beenu/Desktop/AiSOC-p4a`, branch `fix/read-only-approval-and-probes` off `origin/main` (46b1ad74).

## Item 1 — a pure read in the analyst queue

- [x] Reproduced through the API: `POST /actions` with `search_siem` at the default tier returned
      `awaiting_approval`; `POST /live-actions/dispatch` executed the same verb.
- [x] Root cause: `TIER_MAX_AUTOMATIC["L1"] = None`, contradicting `maturity.py`
      (`_AUTO_ALLOWED_AT_TIER[L1_NOTIFY] = {MINIMAL}`) and `_IMPACT_BLAST` (READ_ONLY <=> MINIMAL).
- [x] Unified: new `approval_matrix.evaluate_contract()` is the single grading entry; the
      dispatcher's local READ_ONLY bypass deleted; `approval_gate` calls the same function.
- [x] Two tests that *encoded* the defect rewritten to assert the correct behaviour (both halves).
- [x] Second instance found by the sweep: `update_alert_disposition` had no `ACTION_BLAST_RADIUS`
      entry, and four call sites read that table with two different fallbacks (MEDIUM vs HIGH).
      Added the entry (LOW, per its own contract note); `blast_radius.py` now fails closed to HIGH.
- [x] Cross-door sweep: 345 combinations. Baseline on origin/main: 5 disagreements. Now: 0.
- [ ] Invariant test file committed.

## Item 2 — eleven bridged response verbs with no probe

Unprobed: block_ioc, create_notable_event, create_ticket, force_mfa, kill_process,
quarantine_file, reset_password, revoke_session, run_av_scan, run_script, search_siem.
Priority: kill_process, quarantine_file, run_script.

- [ ] Classify each: real probe / honest unverified / demote.

## Constraints in force

- autospec'd signature tests for any new vendor arm
- dry-run credential-strip list must match the client factory exactly (AST test re-derives it)
- no fake success; `executed` is the only field meaning a vendor was touched
- CHANGELOG under `[Unreleased]`, expect conflicts, resolve as union

## Status at PR open

PR: https://github.com/beenuar/AiSOC/pull/873 (4 commits)
- ee99dae3 approval fix + invariant test
- 960b2a38 probes
- 010a1600 changelog
- e5a4e8f8 claim-to-gate row (140 rows, 132 GATED / 8 PARTIAL / 0 NO GATE)

Local verification: 737 actions tests pass (671 on main); mypy 24 findings = baseline;
ruff clean; check_action_contract OK; check_claim_gate_matrix OK; attribution OK.
Remaining: watch CI, resolve conflicts, merge without --delete-branch, confirm main moved.
