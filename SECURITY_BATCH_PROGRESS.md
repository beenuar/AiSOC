# Security batch progress

Thirteen defects found by reading the code at `v14.0.0` (commit `079fdb6`). None
had been exercised against a running deployment, so every item starts with a
reproduction that fails on the untouched tree for the stated reason.

Two of the thirteen are also items in
[`plans/aisoc_parity_plan.plan.md`](plans/aisoc_parity_plan.plan.md). They are
done once, here, and the parity tracker points at this file rather than
repeating the work.

## D0. This batch is public, by the maintainer's decision

The source brief specified coordinated disclosure: a local branch pushed
nowhere, a tracker under `.private/`, and advisory drafts handed over in chat
for the maintainer to publish before any code became visible.

The maintainer chose the opposite: ordinary public pull requests, merged and
released as they land, with advisories filed afterwards against the release.
The reasoning is that this is a self-hosted product whose defaults are readable
by anyone who opens `.env.example`, so the fix reaching self-hosters sooner is
worth more than the delay buying secrecy that the repository does not really
have.

What that changes, and what it does not:

- No `.private/` directory. This file is the tracker and it is committed.
- Commit messages stay neutral and carry no exploit detail, payloads or
  advisory wording. That costs nothing, keeps the history readable, and leaves
  the option of filing advisories against these commits later.
- Advisory drafts are still produced for every defect: reproduction, root
  cause, affected versions, a suggested CVSS v3.1 vector, and whether the fix
  is breaking.
- S1 and S13 both break callers, so this batch lands as a major.

## Pre-existing state, captured before any code was written

Measured on `origin/main` at `079fdb69` with the working tree stashed, so the
numbers describe the untouched tree.

### Gates: 77 of 84 pass

The seven that do not, and why none is a defect in the tree:

| Gate | Exit | Reason |
|---|---|---|
| `check_attribution.py` | 2 | Refuses to scan without `--all`, `--diff-base`, `--commits` or `--text-file`. |
| `check_container_egress.py` | 2 | Refuses without `--service`: "a probe that covers nothing must not report clean". |
| `check_published_secrets.py` | 2 | Refuses without `--check-env`, `--check` or `--list-guarded`. |
| `check_codeql_alerts.py` | 2 | Needs `GITHUB_TOKEN` with `security-events: read`. Refuses rather than reporting clean about alerts it never read. |
| `check_main_run_cancellations.py` | 2 | Needs a token for the Actions API, same refusal. |
| `check_required_check_substance.py` | 2 | Needs a token for the Actions API, same refusal. |
| `check_mypy_baseline.py` | 1 | Environmental, see D14. |

Six of the seven are the gate contract working: they decline to render a
verdict about a corpus they could not read. Only `check_mypy_baseline` reports
a finding, and it does not reproduce in CI.

### Console suite

`apps/web`: 79 files, 816 tests, zero failures. `npx tsc --noEmit` clean.
`npx eslint .` reports 0 errors and 76 warnings, all pre-existing.

## Deviations: where the brief and the tree disagree

### D1. S1c is 61 call sites, not 27

The brief names `RBACView.tsx` and "any other header-less call you find".
Counting by hand with a grep for `fetch('/api/v1` gives 27. The gate written
for the item finds **61** across 21 files, and the extra 34 are not noise:

- template-literal URLs behind a base variable, which the grep pattern cannot
  see: `fetch(\`${API}/api/v1/honeytokens/${id}\`)` on the honeytokens and
  purple-team pages (9 calls);
- six calls inside `apps/web/src/lib/api.ts` itself, five of which sent
  `X-Tenant-Id` and no token, which reads like an identity and is not one;
- sixteen `useSWR` sites whose fetcher is a single-argument function and
  therefore anonymous by construction.

### D2. `require_permission_db` has 27 call sites, not 31

All 27 are in-body `await <principal>.require_permission_db(...)`; there are
**zero** as a `Depends`. They live in four modules only: `autonomy_policy.py`
(9), `tenant_skills.py` (9), `business_context.py` (5), `mcp_servers.py` (4).
The static figure in the brief is exact: 272, being 256 `Depends` plus 16
direct calls.

### D3. S3's "no authorization decision" is narrower than written

All four routes in `services/api/app/api/v1/endpoints/shifts.py` do take
`current_user: AuthUser`, so they authenticate. What is absent is any
`require_permission(...)` and any tenant scoping, so the finding is
cross-tenant read and write of one shared in-process list by any authenticated
principal. The effect stands; the mechanism in the brief does not.

### D4. S7's audit-read restriction is not a wildcard check

`services/api/app/api/v1/endpoints/audit.py` contains no `"*"` comparison.
Both read routes use `Depends(require_permission("audit_log:read"))`. The
outcome the brief describes holds and is stronger than stated: `audit_log:read`
appears in **no** role's permission list in `ROLE_PERMISSIONS`, so only the two
roles holding `["*"]` can read the log. A `tenant_admin` gets 403 because the
permission is unreachable, not because a wildcard was demanded.

### D5. The production compose file already exists and nothing selects it

S1's fix is not "write a production compose". `docker-compose.prod.yml` sets
`ENVIRONMENT: production` and `AISOC_DEV_MODE: 0` as literals on all six Python
services. But `Makefile:102` (`up:`) and `Makefile:142` (`up-full:`) never pass
`-f docker-compose.prod.yml`, and `install.sh` and `install.ps1` contain zero
occurrences of either variable. The file is correct and unreachable from every
documented path.

### D6. `realtime`'s push routes are worse than written

The brief says the tenant comes "from a header or query parameter with no
credential". `services/realtime/src/push.ts:92` reads `x-tenant-id`, falls back
to the `tenant_id` query parameter, and then falls back to the literal string
`'default'`. The three `POST /v1/push/*` routes carry only a rate limiter.

### D7. Ten services default `AISOC_DEV_MODE=1`, and `api` is not one of them

`docker-compose.yml` sets `AISOC_DEV_MODE: ${AISOC_DEV_MODE:-1}` on fusion,
agents, osquery-tls, actions, connectors, threatintel, ueba, honeytokens,
purple-team and slack-bot. The API service has no `AISOC_DEV_MODE` at all; it
reaches the same bypass through `ENVIRONMENT: ${ENVIRONMENT:-development}` and
`AUTH_BYPASS_ENVIRONMENTS`.

### D14. `check_mypy_baseline` fails locally and passes in CI

Locally it reports `(unmanaged)/scripts/run_evals.py: 15 index finding(s),
baseline records 13`. CI is green at the same commit (28 success, 2 skipped on
`079fdb69`), and the local mypy is 2.3.1, which is what `ci.yml:234` pins.

The gate deliberately removes two sources of variance with
`--no-site-packages --no-incremental`, documented at `ci.yml:272`. It does not
pin the interpreter, and this machine runs Python 3.12.6 against CI's 3.11.
Recorded as environmental rather than fixed, and worth noting as a gap in a
gate whose whole purpose is reproducibility.

## S1. Anonymous admin in the documented deployment

Reproduced and confirmed live on `origin/main`. The crux is byte-identical, not
merely similar: `dev_auth.py:29` `DEMO_TENANT_ID` and `bootstrap_admin.py:59`
`DEFAULT_TENANT_ID` are both `00000000-0000-0000-0000-000000000001`, so the
anonymous principal is an `admin` in the same tenant the real operator is
bootstrapped into.

- [x] **S1c** Console credential on every call ([#1069](https://github.com/beenuar/AiSOC/pull/1069))
- [ ] **S1** Production-class defaults on every documented path
- [ ] **S1b** The nine vendored shims, slack-bot and realtime push

## S2 to S13

- [ ] **S2** Copilot conversations and saved hunt searches are tenant-scoped
- [ ] **S3** Fabricated shared shift state
- [ ] **S4** STIX and TAXII demo data served outside demo mode
- [ ] **S5** Login throttling and lockout
- [ ] **S6** SSO stub identities deleted
- [ ] **S7** Audit blind spots
- [ ] **S8** Tenant isolation beyond query predicates
- [ ] **S9** State-changing routes with no authorization decision
- [ ] **S10** Attacker-controlled alert text can close and then silence alerts
- [ ] **S11** Plaintext service traffic
- [ ] **S12** Default Caldera API key
- [ ] **S13** A custom role cannot restrict a user below their built-in role

## Maintainer actions

- [ ] Check whether `tryaisoc.com` runs with a dev-class `ENVIRONMENT` or
      serves more than one real tenant. If it does, assess exposure for S1 to
      S4 and rotate anything those routes could reach.
- [ ] Reserve the PyPI and npm names the packages will use (`aisoc` on PyPI
      belongs to an unrelated project).
- [ ] File the advisories against the release once the batch has landed.

## Notes for the next session

The batch order is dependency-driven, not severity-driven. S1c had to land
before S1 because closing the anonymous path turns 61 console calls into 401s,
and the console had to be able to authenticate first.
