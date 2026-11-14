---
sidebar_position: 3
---

# Reproducible builds

Every Python service installs from a committed `poetry.lock`, every Go module
from a committed `go.sum`, and every Node install from `pnpm-lock.yaml` or
`package-lock.json`. Two builds of one commit install byte-identical versions,
and nothing re-resolves at image build time.

If you change a dependency, **re-lock in the same commit**. That is the whole
contributor-facing rule; the rest of this page explains what enforces it and
why it exists.

Two gates, one property:

| Gate | Asks |
|---|---|
| `scripts/check_dependency_pins.py` | do all install paths agree on each **package** version |
| `scripts/check_toolchain_pins.py` | do all paths agree on each **runtime** version, and is every install **locked** |

## Changing a dependency

```bash
# 1. edit the manifest
$EDITOR services/api/pyproject.toml

# 2. re-lock, pinned to the resolver the images use
pip install "poetry==2.4.1"
poetry -C services/api lock

# 3. commit pyproject.toml and poetry.lock together
git add services/api/pyproject.toml services/api/poetry.lock
```

Committing one without the other fails two ways on purpose: `poetry install`
inside the image refuses a lock that no longer matches its manifest
("pyproject.toml changed significantly since poetry.lock was last generated"),
and the `Every lock still matches its manifest` CI job runs `poetry check
--lock` against all thirteen services.

Dependabot updates both files in the same pull request, so this does not
freeze the tree — the lock is maintained by tooling, not by hand.

## If the same package is installed somewhere else too

Some packages are installed in more than one place: a manifest, a Dockerfile,
and whichever CI workflows pip-install a service's dependencies to run a test.
When those disagree, CI tests one version and the image ships another.

`scripts/check_dependency_pins.py` fails when any two install paths for the
same package disagree. Run it before pushing:

```bash
python scripts/check_dependency_pins.py --verbose   # what it scanned, and every range it compared
python scripts/check_dependency_pins.py --self-test # proves the gate still detects injected drift
```

A short list of packages must carry **one identical range everywhere**, because
for them a version difference is a correctness or a security difference rather
than a preference:

| Package | Why it is pinned everywhere |
|---|---|
| `fastapi` | Below 0.117 the API cannot be imported at all — see below. |
| `sqlglot` | Parses untrusted operator SQL for the lake tenant-isolation rewriter. 27 renamed the `FROM` argument key and silently dropped the tenant predicate. |
| `cryptography` | The Fernet token format shared between the service that writes vault tokens and the ones that read them, and the Ed25519 plugin signatures `aisoc-cli` produces and the API verifies. |
| `PyJWT` | The only JWT implementation in the tree. |
| `ruff` | `ruff format --check services/` is a hard gate and the formatter's output changes between minors. |
| `poetry` | The resolver that decides what a commit installs. |

Every other dependency may differ per service. They are separate images and
nothing crosses between them, so forcing agreement there would be noise.

## Go and Node

Same property, different ecosystems, and one extra failure mode: a Node
install can simply decline to use the lockfile sitting next to it.

```bash
python scripts/check_toolchain_pins.py --verbose   # every path it scanned and every version it compared
python scripts/check_toolchain_pins.py --self-test # proves it still detects injected drift
```

**Every Node install must be locked.** `pnpm install` needs
`--frozen-lockfile`; `npm install` should be `npm ci`. An image that installs
Node dependencies must also **copy the lockfile into its build context** — the
two go together, because `npm ci` without the lockfile in context fails and
`npm install` without it silently re-resolves. `apps/mobile` is the one
declared exemption: it sits outside the root workspace with a lockfile of its
own, so a root refresh must not red it.

**Every Go module must have its checksums.** Copy `go.sum` unconditionally,
never as `go.sum*` — the glob makes the checksum file optional, so deleting it
downgrades the build to an unverified resolve without failing anything. Every
`go.mod` must also be compiled by some workflow; `packages/sdk-go` was not, and
so was never built by CI at all.

**esbuild overrides stay scoped.** `package.json` pins `vite>esbuild` and
`tsup>esbuild` per parent rather than workspace-wide, because Next bundles its
own esbuild and a workspace-wide override replaces it — which breaks
Turbopack's font import map. That scoping means a `vite` bump can pull a
different esbuild with no esbuild line in the diff, so the gate also pins the
**resolved** set in `EXPECTED_ESBUILD`. Moving it is a deliberate edit, not a
side effect.

## One toolchain version, everywhere

A workflow compiling with a different Go or Node version than the Dockerfile
ships is the package problem one level up: CI proves something about software
the image does not contain.

| Runtime | Version | Declared in |
|---|---|---|
| Go | 1.26 | every `go.mod` directive, every `setup-go`, every `FROM golang:` |
| Node | 22 | every `setup-node`, both Node images, the devcontainer, `install.sh` |
| pnpm | 8.15.1 | `packageManager`, `apps/web/Dockerfile`, `install.sh` |
| Python | 3.11 in every service image | every `FROM python:`, every manifest floor |

The gate compares these in both directions — a version an image ships that no
workflow exercises, *and* a version a workflow uses that no image ships —
because CI versions get bumped and Dockerfiles get forgotten, and a
one-directional check misses exactly that.

`pnpm/action-setup` is `v6.0.9` everywhere except `e2e.yml` and
`visual-regression.yml`, which stay on v4 for a measured reason recorded in
`PNPM_ACTION_EXEMPT`: they run inside the Playwright container, which ships a
global pnpm 11.x, and under v6 pnpm self-switches down to the `packageManager`
pin in a way that leaves `@tailwindcss/oxide`'s native binding unlinked.

**Python is the weaker case, and it is recorded rather than closed.** The
service manifests declare `python = "^3.11"`, which permits 3.12, so the 24
workflows running 3.12 violate nothing written down — but every image ships
3.11, so what CI exercises is not what production runs. Closing it means
moving 24 workflows or re-locking 13 manifests. Until then the set is listed
in `PYTHON_INTERPRETER_SPLIT` and may not grow: a workflow that joins it
without being listed fails, and a listed workflow that no longer differs fails
too.

## Type checking

`scripts/check_mypy_baseline.py` runs mypy over every tree that declares a
`[tool.mypy]` table and fails when any finding grows. The findings are
recorded in `scripts/mypy_baseline.json` exactly as mypy reports them — no
widened config, no excluded tree, and `strict = true` stays strict.

Every tree being configured is not the same as every file being checked. 153
Python files belong to no `pyproject.toml` — `scripts/`, `tests/`, `tools/`
and `plugins/` — so the gate also runs a scope recorded under the key
`(unmanaged)`, configured by `mypy-unmanaged.toml` at the repository root.
That scope is **computed, not listed**: `git ls-files '*.py'` minus every
manifest tree. Adding a script anywhere brings it into scope with no edit,
and deleting a tree's manifest moves that tree's files into this scope rather
than out of coverage.

It is a scoped invocation rather than a root `pyproject.toml` because a root
manifest carrying only `[tool.mypy]` makes `poetry check` answer *"The Poetry
configuration is invalid"* from every directory that does not hold a manifest
of its own — poetry searches upward. The header of `mypy-unmanaged.toml`
records that and the two other measurements behind the choice.

The baseline used to be reproducible only on a CI runner, which is another way
of saying it was not reproducible. mypy reads type information out of installed
packages, so a contributor with a service virtualenv active got mismatches in
both directions — 59 of them with eight dependencies present — and nothing in
the output said the cause was their environment rather than their code.

The gate now removes both variables it can remove. It passes
`--no-site-packages`, so installed packages stop contributing (measured on
`services/connectors`: 73 findings on a bare interpreter, 140 with eight
dependencies installed, and 73 either way once the flag is on), and
`--no-incremental`, because a `.mypy_cache` written under different conditions
is reused by the next run and answered 988 where a cold cache answered 990.
Run it from anywhere:

```bash
pip install 'mypy>=2.3.1,<3'
python scripts/check_mypy_baseline.py
```

The one variable that cannot be removed is mypy itself, so it is recorded. The
baseline carries an `(environment)` block naming the version that produced it,
and the gate refuses to compare across majors — a mypy major *moves* findings
rather than only adding them, so a run under the wrong one would print a screen
of file-level differences that all describe the version. It says that once,
first, instead.

The interpreter is not the variable people assume. Every config here pins
`python_version`, so 3.13 against 3.11 moves exactly two findings in one file —
PEP 701 changed how f-string sub-expressions are attributed to source lines in
3.12, which splits some findings that 3.11 reports once. That is reported as a
note rather than a refusal, because refusing would stop a contributor on 3.12
from running the gate at all over a difference the gate can explain.

Re-record with `--update`. Fixing a finding requires re-recording too, so the
freed headroom cannot silently absorb the next one.

## Why this exists

On 2026-09-24 the `One real event through the real pipeline` job failed, then
passed on re-run with no code change. The API container had died at import:

```
AssertionError: Status code 204 must not have a response body
  app/api/v1/endpoints/community.py:183
```

That file was byte-identical to `main` and the branch touched nothing under
`services/api`. The real cause was four install paths disagreeing about
FastAPI:

- `services/api/pyproject.toml` declared `>=0.111,<0.142` — 120 releases, and
  no lock to choose between them;
- the Dockerfile carried a pip fallback pinning `>=0.111,<0.112`;
- six workflows installed `fastapi` with no version bound at all;
- one workflow pinned `>=0.109,<0.140`.

`community.py` uses `from __future__ import annotations`, so its `-> None`
return annotation reaches FastAPI as the string `"None"`. FastAPI resolves that
through `ForwardRef` to `NoneType` — a class, and therefore truthy — instead of
the falsy `None` singleton it gets without PEP 563. A truthy `response_model`
means "this route returns a body", and FastAPI asserts a 204 does not.
**Every release from 0.111.0 through 0.116.2 refuses to import the module;
0.117.0 and later accept it.**

The fallback fired because `poetry install` hit a transient error, so the image
installed 0.111.1 and the container was dead on arrival. That fallback existed
to stop a registry hiccup from failing a build — but it shipped an image built
from versions nothing had tested, which is worse than a build that fails. It is
gone. `services/api/tests/test_fastapi_floor.py` pins the 0.117 boundary, and
the `Reproducible builds` workflow imports the service at both ends of the
declared range so the bound is a tested claim rather than a guess.

The same shape had already bitten the lake tenant-isolation rewriter once:
`sqlglot` was declared `<31` in one file and `<27` in six others, and on the
versions only the manifest allowed, the rewriter returned queries with no
tenant predicate while reporting success.
