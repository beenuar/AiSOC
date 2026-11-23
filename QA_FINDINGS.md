# QA lane findings — NOT committed

Tree measured: /tmp/aisoc-qa @ 7d0c5f418 (origin/main at QA start; main moved to
035bb516b mid-pass when the sibling merged #2005 — both fix branches rebased onto
it before push). Live stack: project qa-aisoc from a HOME-visible worktree of the
same commit, qa-* names, 58xxx ports, api built from HEAD, all else GHCR :latest
(verified == HEAD by image revision label after the publish run for 7d0c5f418
completed). Sibling lane's worktrees/branches/PRs/containers untouched throughout.

## Verdict
Two confirmed repo defects, both fixed in open PRs:
- PR #2012 — dead destinations across the shipped marketing surface (Discord
  invite invalid per Discord API; X account 404; 17 mailtos at a no-MX domain
  incl. the privacy deletion route and a security contact contradicting
  SECURITY.md; hero + why-open-source demo deep links 301-swallowed; NXDOMAIN
  mesh-hub default; stale badge example). Failing-test-first
  (tests/test_dead_destination_links.py), negative control recorded, hostname
  allow-list ratcheted.
- PR #2013 — klauspost/compress v1.20.1 → v1.20.2 in services/ingest
  (GO-2026-6865, panic on crafted frames, govulncheck-traced reachable from
  otlp.Receiver.writeProto). Below CI audit's high/critical bar by policy;
  fixed because attacker-reachable on the network-facing service.

## Pass 1 — static (all rc values pipeless)
PASS: route_auth, route_tenant_scope, tenant_query_predicates,
module_reachability, migration_numbering (chain sequential → 167),
orm_migration_parity, claim_gate_matrix, readme_gates, action_contract,
connector_paging, default_egress, attribution --all, competitor_names,
raw_sql_columns, activity_projection, export_openapi --check, mypy_baseline,
published_images, hosted_hostname (+ --self-test), changelog_frozen,
security_audit validate-ignores.
HONEST REFUSALS (tooling absent, then supplied): security_audit python/go
refused vacuous zeros until pip-audit/govulncheck installed — gate behaved
correctly.

Defect-class sweeps: (a) ClickHouse column drift — custom AST sweep over every
non-test raw_events SQL across all services vs 64 real columns: CLEAN
(note: check_raw_sql_columns excludes ClickHouse by design; no standing gate
for this class — observation only). (b) swallowed-exception→empty: all
documented LLM-optional/best-effort patterns; guardrails.py {}-on-failure is
real but module has no production importer — known, documented
(autonomy_effective.py; console states "advisory — nothing in the response
path reads them yet" in-product, verified live). (c) exists-unwired security
fns: validate_raw_sql guards a raw-SQL path that doesn't exist (all osquery
clients render via allowlist); verify_pins test-pinned; rest were decorated
routes. (d) status vocabularies: clean (resolution_time owns the closed
predicate; war_room 'resolved' deliberate). (e) str(uuid) binds: set_config/
CAST patterns, Postgres-only paths. (f) enum-repr writes: plain strings. (g)
utcnow: existing code only.

## Suites (CI-parity: Python 3.11 locked venvs, minimal env)
- api: 5,572 passed, 0 failed (exactly the figure in recent merge bodies)
- agents: pass (rc 0) · actions: 2,132 passed (rc 0, no DATABASE_URL — CI parity)
- connectors: pass (scheduler disabled) · fusion: pass
- ingest Go: all packages ok (isolated GOMODCACHE)
- web: tsc clean, eslint clean on touched files, full vitest green
- repo gate suite: links branch 2,057 passed / compress branch 2,048 passed;
  single residual failure on both = test_live_initdb_installed_database_is_current,
  PROVEN environmental (bind mount from /tmp is empty inside the colima VM —
  same commit passes in 5.86 s from a HOME-visible worktree).

False-alarm triage worth keeping: an earlier run showed api 34F/528E and
actions 76F — decomposed into (1) live services on default localhost ports
(another stack's postgres on 5432, clickhouse on 9000) turning CI's
connection-refused paths into auth-failure paths, and (2) the actions
kill-switch/tenant-policy reads **correctly failing closed** when a configured
DB is unreachable (my harness set DATABASE_URL; CI doesn't for that job) —
i.e. a live confirmation of the fail-closed posture, not a defect. Python 3.14
vs CI's 3.11 accounted for the rest.

## Pass 2 — live end-to-end (subset per brief; VM headroom ~6.5 GiB)
Ran: postgres redis zookeeper kafka clickhouse ingest-worker fusion api
connectors agents realtime web + ollama/litellm/ollama-pull.
- Fresh-volume initdb applied and RECORDED all 164 migrations (aisoc_schema_migrations
  = 164 = files) — the v23.1.0 fix working.
- bootstrap_admin printed one-time password (disposable stack).
- Ingest auth: no token → 401, wrong token → 401, service token → accepted (fail-closed).
- Pipeline PROVEN twice: event → ClickHouse lake row (MITRE projected) →
  fusion alert (Postgres) → triage. Deterministic tier: honest
  llm_failed_fallback + tier=deterministic + heuristic ai_summary. Model tier:
  llama3.2:3b-instruct-q4_K_M via litellm — measured 1,250 prompt / 99
  completion tokens, 34.7 s CPU, verdict true_positive @0.9 → escalated under
  default_deny threshold, persisted to ledger (run b21ac8d4…).
- API smoke: alerts/cases/detections(2,966 rules)/connectors/lake/playbooks/
  investigations/cases/attention all 200 with honest states; threat-intel and
  graph answer honest degraded/profile-aware messages for services not in the
  subset; no 500s anywhere.
- Console walkthrough (browser): login → dashboard (live funnel, honest
  "not measured" denominators, real counts from my QA events) → alerts
  (2 real alerts, Investigation Rail honest "one stage observed… nothing
  inferred", confidence 64/100 with rationale) → cases (honest empty) →
  detection rules (2,966) → connectors (honest zeros) → settings (15 sections;
  autonomy panel states the advisory-threshold truth in-product). No 4xx/5xx
  page resources; deferred controls carry "Planned for v1.1" badges (not dead
  buttons); footer version matches VERSION (23.6.1) after re-pull.
- Link audit: every external destination fetched → the dead set became PR #2012.
- Teardown: compose down -v, qa image removed, 0 qa containers left.

Environment events during the pass (not repo defects, recorded honestly):
- colima mounts only $HOME → /tmp bind mounts empty in containers (empty
  initdb on first attempt; the live-initdb test failure).
- Both my and the other lane's kafka containers vanished ~18:38–18:43Z with no
  docker die/destroy events; VM uptime 32 days (no restart). Unattributed
  external action. Mine recreated; agents consumer self-recovered with named
  operator guidance.
- A shared venv (/tmp/venv-api-rel) broke mid-pass (another lane modifying
  it) — switched to own /tmp/venv-qa-* set.
- Go module cache has root-owned dirs from 2023 → isolated GOMODCACHE.
- GHCR :latest initially looked 4 days stale — my pull had been killed
  mid-flight; registry digest check + re-pull resolved it (publish pipeline
  healthy; :latest == HEAD).

## Pass 3 — security posture
- pip-audit vs real locked exports (api 117 / agents 125 / actions 50 /
  connectors 53 / fusion 71 pinned lines): all five CLEAN with explicit
  verdicts (no vacuous zeros).
- govulncheck services/ingest: 1 module finding (GO-2026-6865) → fixed in PR
  #2013; post-bump zero module findings. 23 stdlib findings are the LOCAL
  go1.26.3 toolchain's; shipped image builds FROM golang:1.26-alpine (floats
  to current patch at build time) — not a tree defect.
- pnpm audit --prod: "No known vulnerabilities found".
- My diffs: no secrets, no /Users/ paths, no dynamic SQL, no verify= changes,
  no new routes (no new auth surface), attribution + competitor gates green.

## Known pre-existing non-bugs left alone (per brief)
lake_sql.py mypy baseline entry · 13 grandfathered migration collisions ·
azure_event_hubs checkpoint exception (test-pinned) · 9 PARTIAL claim rows.

## Unconfirmed / could-not-verify
- Whether a working Discord exists under a different invite (only the shipped
  one testable).
- check_published_images passed, but the arm64/amd64 manifest contents beyond
  the labels were not independently re-verified this pass.
- Lake-hunt surfaces beyond /lake/schema (e.g. /lake/sql POST) not exercised
  live (subset time); schema endpoint + lake writes verified.
- kafka-container removal actor: no evidence either way.
