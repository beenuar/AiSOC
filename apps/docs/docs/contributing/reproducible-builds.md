---
sidebar_position: 3
---

# Reproducible builds

Every Python service installs from a committed `poetry.lock`. Two builds of one
commit install byte-identical versions, and nothing re-resolves at image build
time.

If you change a dependency, **re-lock in the same commit**. That is the whole
contributor-facing rule; the rest of this page explains what enforces it and
why it exists.

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
