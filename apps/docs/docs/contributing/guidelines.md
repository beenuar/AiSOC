---
sidebar_position: 2
---

# Contribution Guidelines

Thank you for contributing to AiSOC! This guide covers everything you need to
know to land a clean pull request: branching, testing, commit format, the PR
template, plan files for larger work, and the eval-harness gate that protects
agent quality.

For end-to-end project standards (code style, connector contributions,
community marketplace), see also the root-level
[`CONTRIBUTING.md`](https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md).

## Code of Conduct

All contributors must follow our
[Code of Conduct](https://github.com/beenuar/AiSOC/blob/main/CODE_OF_CONDUCT.md).
Be respectful, constructive, and assume good faith.

## Branching Strategy

- `main` — long-lived branch most contributors target. Tags are cut here.
- `develop` — optional integration branch for coordinated multi-PR work. CI
  watches both `main` and `develop`.
- `feature/<name>` — new features.
- `fix/<name>` — bug fixes.
- `docs/<name>` — documentation-only changes.
- `chore/<name>` — tooling, deps, refactors with no behavior change.

Most contributors should branch from `main`. Use `develop` only when
explicitly coordinating a stack of dependent PRs with a maintainer.

## Pull Request Workflow

1. Fork the repo and create a branch from `main`.
2. Make focused commits — one logical change per commit, smallest reviewable
   unit per PR.
3. Write or update tests for any new or changed behavior (see [Testing](#testing)).
4. Run linters and the relevant test suite locally before pushing.
5. Update documentation if behavior, commands, env vars, or APIs changed.
6. If your change touches the agent, orchestrator graph, prompts, tools, RAG
   corpus, or detection content, **re-run the eval harness** and include
   before/after deltas in the PR body (see [Eval harness gate](#eval-harness-gate)).
7. Push to your fork and open a PR against `main`.
8. Fill out the [PR template](#pr-template) completely. Empty checkboxes block
   review.

### PR Template

Every pull request uses the
[default PR template](https://github.com/beenuar/AiSOC/blob/main/.github/PULL_REQUEST_TEMPLATE/pull_request_template.md).
The required sections are:

- **Summary** — 2–3 sentences describing what changed and why.
- **Type of change** — bug fix, feature, breaking change, docs, refactor, or
  CI/infra. Tick exactly one.
- **Related issues** — `Closes #N` for any linked issue.
- **Changes** — bullet list of the key files or areas touched, with a brief
  rationale.
- **Testing** — how you verified the change. Tick the boxes that apply (unit
  tests, integration tests, manual). Include exact manual steps in the
  collapsible block when applicable.
- **Screenshots** — required for any user-facing UI change. Before/after side
  by side, or a short screen recording.
- **Checklist** — code-style compliance, self-review, tests, docs updated, no
  new linter warnings, no sensitive data in the diff.

For new detection rules, use the dedicated
[detection rule template](https://github.com/beenuar/AiSOC/blob/main/.github/PULL_REQUEST_TEMPLATE/detection_rule.md)
which prompts for MITRE ATT&CK technique IDs, fixture coverage, and false-positive
notes.

## Testing

AiSOC has three layers of automated checks. **PRs that fail any layer cannot
land.**

### 1. Linting and type checks

Run before every commit:

```bash
pnpm lint                           # ESLint + Prettier across the workspace
pnpm --filter @aisoc/web typecheck  # TypeScript on the web app
ruff check services/                # Python linting
mypy services/<name>                # type-check the service you touched
( cd services/<name> && go vet ./... && gofmt -l . )
```

CI runs the same commands; passing locally is the cheapest way to avoid
back-and-forth on review.

### 2. Unit and integration tests

Run the suite for whichever surface you touched:

```bash
# Web app
pnpm --filter @aisoc/web test

# Python services
pytest services/api/tests/
pytest services/agents/tests/
pytest services/connectors/tests/
# ...etc.

# Go services
( cd services/ingest && go test ./... )
```

New code requires new tests. New connectors require schema-contract,
`normalize()`, and mocked `test_connection` + `fetch_alerts` tests at minimum.
See [`CONTRIBUTING.md` → Adding New Connectors](https://github.com/beenuar/AiSOC/blob/main/CONTRIBUTING.md#adding-new-connectors)
for the exact shape.

### 3. Eval harness gate {#eval-harness-gate}

This is what prevents agent regressions and is **non-negotiable** for any PR
touching the agent substrate.

Anything that touches `services/agents/`, the orchestrator graph, prompts,
tools, the RAG corpus, or detection content **must** be re-graded against the
public eval harness:

```bash
# Run all four substrate eval suites and write a JSON report.
# Dataset size is fixed (200 incidents); there is no --count flag.
python scripts/run_evals.py --out eval_report.json

# Or run a single eval axis
pytest services/agents/tests/test_mitre_accuracy.py
pytest services/agents/tests/test_alert_reduction.py
pytest services/agents/tests/test_investigation_completeness.py
pytest services/agents/tests/test_response_quality.py
```

The harness writes `eval_report.json` and `eval_mitre_accuracy_report.json`,
which the public [eval harness page](../benchmark) renders. The same harness
runs in CI on every PR.

**If your PR regresses any axis below the published baseline**, the PR body
must include:

1. The before/after delta for each affected axis.
2. A written justification for why the regression is acceptable.

> **Be honest about what you measure.** Three of the four metrics are
> substrate self-consistency gates against deterministic synthetic incidents,
> not live agent accuracy scores. The
> [eval harness page](../benchmark) explains exactly which is which. Update
> that page in the same commit if your PR changes a suite's metric category.

### 4. OpenAPI breaking-change gate {#openapi-breaking-change-gate}

A PR that touches `docs/openapi.yaml` is diffed against the base branch by
`scripts/openapi_diff.py`. It fails on any change that would break an existing
generated SDK client: a removed path, operation, schema or property, a changed
property type, an optional field becoming required, a new required field on a
request-shaped schema, a dropped enum value, or a new required parameter.

Run it yourself before pushing:

```bash
git show origin/main:docs/openapi.yaml > /tmp/base-openapi.yaml
python scripts/openapi_diff.py --old /tmp/base-openapi.yaml --new docs/openapi.yaml
```

Additive changes — a new path, a new optional field, a new enum value — are not
flagged. Most spec changes need nothing further.

#### Shipping a break deliberately

Sometimes the break is the point: a schema described data the platform never
measured, or a field promised a number with no formula behind it. Removing it is
correct, and preserving it would keep the lie. Two steps:

1. **Write the record.** Add a `### BREAKING` section under `## [Unreleased]` in
   `CHANGELOG.md` saying what moved, what replaced it, and why it could not be
   preserved. Name each field. This is the half that outlives CI logs.
2. **Get it authorised.** Ask a maintainer to apply the
   `breaking-change-approved` label to the PR.

The label is the authorisation, and it is deliberately a label rather than a
workflow input: GitHub records who applied it and when on the PR timeline, so
the approval is attributable after the fact. The gate re-runs on `labeled` and
`unlabeled`, so applying or removing it takes effect immediately.

Approval is not a skip. The detector still runs, and the job summary lists
**every** breaking change being permitted alongside the CHANGELOG note that
justified it — the record says what was approved, not merely that something was.
The gate refuses the approval outright if the CHANGELOG note is missing, or if
the `### BREAKING` section is unchanged from the base branch (a note written for
an earlier PR does not describe yours).

There is no version-bump requirement here. This repository accumulates under
`[Unreleased]` and bumps `VERSION` when a release is cut, so no single PR can
correctly satisfy one.

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/). The
prefix is enforced by CI and used to generate changelog entries.

```text
feat(connectors): add Tailscale audit log connector
fix(agents): handle empty IOC list in ForensicAgent
docs(quickstart): add Go SDK example
chore(deps): bump pnpm to 9.1.0
test(api): cover RLS rejection path on alerts endpoint
refactor(fusion): extract Bloom dedup into a shared module
```

Allowed types: `feat`, `fix`, `docs`, `chore`, `test`, `refactor`, `perf`,
`ci`, `build`, `revert`. Scope (in parentheses) is optional but encouraged
when it makes the diff clearer.

Breaking changes get a `!` and a `BREAKING CHANGE:` footer:

```text
feat(api)!: rename /alerts/{id}/triage to /alerts/{id}/verdict

BREAKING CHANGE: clients calling POST /alerts/{id}/triage must
migrate to POST /alerts/{id}/verdict before upgrading to v7.
```

## Code Style

| Language   | Linter / formatter            | Type checker        |
| ---------- | ----------------------------- | ------------------- |
| Python     | `ruff` (lint + format)        | `mypy`              |
| TypeScript | ESLint + Prettier             | `tsc --noEmit`      |
| Go         | `gofmt`                       | `go vet`            |
| YAML       | `yamllint` (detections, hunts)| —                   |

Configurations live at the repo root (`ruff.toml`, `eslint.config.mjs`,
`.prettierrc`) and per-service (`pyproject.toml`, `tsconfig.json`, `go.mod`).

## Plan Files (for larger work)

Multi-PR features, refactors, or anything that needs design review before
implementation should land a **plan file** first.

### When to write a plan

Write a plan when your change:

- Touches more than ~5 services or packages.
- Introduces a new top-level concept (a new agent, a new storage tier, a new
  API surface).
- Requires a database migration that is not trivially reversible.
- Changes a public API contract (REST, GraphQL, WebSocket, SDK, MCP tools).
- Is expected to take more than one PR to land.

You don't need a plan for bug fixes, small features, or docs.

### Plan file conventions

- Location: `docs/plans/<short-slug>.md` (create the directory if it doesn't
  yet exist).
- Filename: lowercase, hyphenated, descriptive — e.g.
  `docs/plans/auto-triage-confidence-rework.md`.
- Required sections:
  - **Context** — what problem this solves and why now.
  - **Goals / Non-goals** — explicit list of each.
  - **Proposed change** — the design at a level a reviewer can argue with.
  - **Migration / rollout** — how existing tenants and data are handled.
  - **Eval impact** — which harness axes might move and your hypothesis.
  - **Open questions** — things you want a maintainer to weigh in on.
- Open the plan as its own PR. Maintainers review the plan before any
  implementation PRs land. Once approved, implementation PRs reference the
  plan in their `Related issues` / `Changes` section.

> **Never edit a plan file once it is approved and implementation has started.**
> If the design changes mid-implementation, write a follow-up "amendment" PR
> against the plan file, or open a new plan that supersedes the old one.

## Security

- **Never commit secrets, API keys, or credentials.** Use `.env` files (which
  are git-ignored) and document required keys in the
  [environment variables reference](../deployment/env-vars).
- Run `git diff --staged` before every commit and visually scan for tokens,
  passwords, customer hostnames, or sample payloads with PII.
- Report security vulnerabilities **privately** via GitHub Security
  Advisories at
  [github.com/beenuar/AiSOC/security/advisories/new](https://github.com/beenuar/AiSOC/security/advisories/new).
  Do not open a public issue for vulnerabilities.

See the [security operations guide](../operations/security) for the full
threat model, RBAC layout, audit-log surface, and credential-vault rotation
procedure.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](https://github.com/beenuar/AiSOC/blob/main/LICENSE).
