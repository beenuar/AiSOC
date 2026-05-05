# Contributing to AiSOC

Thank you for your interest in contributing to AiSOC! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please be respectful and constructive in all interactions.

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/AiSOC.git`
3. Add the upstream remote: `git remote add upstream https://github.com/beenuar/AiSOC.git`
4. Create a feature branch: `git checkout -b feature/my-feature`

## Development Setup

See [README.md](README.md#development) for detailed setup instructions.

## Making Changes

### Code Style

- **TypeScript/JavaScript**: ESLint + Prettier (config in root)
- **Python**: `ruff` for linting and formatting, `mypy` for type checking
  (config in [`ruff.toml`](ruff.toml) and per-service `pyproject.toml`)
- **Go**: `gofmt` + `go vet`

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(alerts): add bulk status update endpoint
fix(enrichment): handle rate limit backoff
docs(readme): update deployment instructions
test(agents): add unit tests for investigation agent
```

### Testing

- Write tests for all new features
- Maintain or improve test coverage
- Run the full test suite before submitting a PR

### Public eval harness

Anything that touches the agent (`services/agents/`), the orchestrator
graph, prompts, tools, RAG corpus, or detection content **must** be
re-graded against the public eval harness. The harness lives under
[`scripts/run_evals.py`](scripts/run_evals.py) and per-axis tests under
[`services/agents/tests/`](services/agents/tests/).

```bash
# Run all four substrate eval suites against the bundled 200-incident
# dataset and write a JSON report. The dataset size is fixed by
# services/agents/tests/eval_data/synthetic_incidents.json — there is no
# --count flag.
python scripts/run_evals.py --out eval_report.json

# Or run a single eval axis
pytest services/agents/tests/test_mitre_accuracy.py
pytest services/agents/tests/test_alert_reduction.py
pytest services/agents/tests/test_investigation_completeness.py
pytest services/agents/tests/test_response_quality.py
```

The harness writes `eval_report.json` and `eval_mitre_accuracy_report.json`,
which the public [eval harness page](apps/docs/docs/benchmark.md) renders.
The same harness runs in CI on every PR — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml). PRs that regress any
axis below the published numbers must include a written justification and
before/after delta in the PR body.

> **Be honest about what changed.** The harness runs deterministic substrate
> code (extractors, fusion, templates, judges) against synthetic incidents
> — it does **not** call the live LLM agent. Three of the four metrics are
> substrate self-consistency gates rather than agent accuracy scores. The
> [eval harness page](apps/docs/docs/benchmark.md) explains exactly which is
> which. If your PR changes which metric category a suite belongs to,
> update that page in the same commit.

## Submitting a Pull Request

1. Update your branch: `git fetch upstream && git rebase upstream/main`
2. Run tests:
   - `pnpm --filter @aisoc/web test` (web smoke tests)
   - `pytest services/<name>/tests/` for any Python service you touched
   - `( cd services/<name> && go test ./... )` for any Go service you touched
3. Push to your fork: `git push origin feature/my-feature`
4. Open a PR on GitHub against `main` with a clear description of changes.
   CI also runs on `develop` for integration branches; both targets are
   accepted, but most contributors should target `main`.

## Adding New Connectors

Connectors are runtime data. There is no Dockerfile to build, no
`docker-compose.yml` entry to add, and no separate microservice to ship —
adding a connector means subclassing `BaseConnector`, declaring a `schema()`,
adding a marketplace manifest, and writing tests. The
[connector platform doc](apps/docs/docs/connectors/index.md) explains the
end-to-end click-and-connect flow; this section covers the contributor
mechanics.

### 1. Subclass `BaseConnector`

Add a new file under `services/connectors/app/connectors/<name>.py` and
subclass `BaseConnector` from
[`services/connectors/app/connectors/base.py`](services/connectors/app/connectors/base.py).
Implement four things:

```python
from .base import BaseConnector, ConnectorSchema, Field, OAuthHints

class MyConnector(BaseConnector):
    connector_category = "saas"  # one of: edr, siem, cloud, iam, saas, vcs, network

    @classmethod
    def schema(cls) -> ConnectorSchema:
        return ConnectorSchema(
            name="my-connector",
            label="My Connector",
            description="What this connector pulls and from where.",
            category=cls.connector_category,
            fields=[
                Field(name="api_url", type="text", label="API URL", required=True),
                Field(name="api_token", type="secret", label="API token", required=True, secret=True),
            ],
            oauth=OAuthHints(supported_in_hosted=False),
            default_poll_interval_seconds=300,
        )

    async def test_connection(self) -> dict:
        ...  # one cheap auth-checking call; return {"ok": bool, "message": str, ...}

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict]:
        ...  # raw vendor JSON, no normalization

    def normalize(self, raw_event: dict) -> dict:
        ...  # OCSF-aligned shape; severity ∈ {"info","low","medium","high"}
```

Field types are `text`, `secret`, `select` (with `options`), `textarea`,
and `oauth`. Mark **anything sensitive** with `secret=True` — the
frontend will render those fields as masked inputs and the API service
will encrypt them via the [`CredentialVault`](apps/docs/docs/operations/credentials.md)
before they hit Postgres.

### 2. Register in the connector registry

Add your class to the `_CONNECTOR_CLASSES` tuple and `__all__` in
[`services/connectors/app/connectors/__init__.py`](services/connectors/app/connectors/__init__.py).
The registry powers `/connectors/schemas` and the wizard's catalog grid —
no other wiring required.

### 3. Add a marketplace plugin manifest

Drop a `plugins/<connector-id>/plugin.yaml` mirroring your `schema()`. See
existing entries (`plugins/azure-entra/plugin.yaml`,
`plugins/cloudflare/plugin.yaml`, etc.) for the exact shape. Run:

```bash
pnpm marketplace:sync   # builds marketplace/index.json + syncs to apps/web/public
```

### 4. Write tests

`services/connectors/tests/test_<name>.py` with at minimum:

- A schema-contract test (asserts `schema().name`, required fields, secret
  markers, hosted-OAuth advertising).
- `normalize()` unit tests covering every severity rule you implement —
  use real attacker-shaped fixtures (BEC, role grants, defense evasion).
- A `respx`-mocked `test_connection()` covering success + auth-failure
  paths.
- A `respx`-mocked `fetch_alerts()` roundtrip that asserts your
  normalization produces a well-formed OCSF event.

The bundled test suite already runs against 100+ tests across 9 connectors
— look at `test_azure_connectors.py`, `test_gcp_connectors.py`, and
`test_saas_connectors.py` for the shape.

### 5. Docs

Add `apps/docs/docs/connectors/<connector-id>.md` with prereqs, exact
permissions/scopes, secret rotation walkthrough, severity heuristics
table (mirrors what's in your `normalize()`), and a troubleshooting
section. Add the new page to `apps/docs/sidebars.ts` under the
`Connectors` category.

### Reference connectors

The 14 in-tree connectors are ordered roughly from simplest auth to most
complex: `crowdstrike`, `okta`, `cloudflare` (API token), `splunk`,
`aws_security_hub` (IAM keys), `azure_entra`, `azure_activity`,
`azure_defender`, `m365_audit` (AAD app), `gcp_cloud_audit`, `gcp_scc`,
`google_workspace` (service account JSON + JWT signing), `github`
(fine-grained PAT), `microsoft_sentinel`. Pick the one whose auth model
matches yours and copy from there.

## Community Marketplace

The AiSOC marketplace is content-as-code. Anything in
[`detections/`](detections/), [`playbooks/`](playbooks/), and
[`plugins/`](plugins/) is automatically picked up by
[`scripts/build_marketplace.py`](scripts/build_marketplace.py) and surfaced in
the in-app **Marketplace** view at `/marketplace`. There is no separate
registry to push to — you ship a PR, the index regenerates, and your
contribution shows up.

### Where contributions go

Each content type has a `community/` namespace reserved for outside
contributors:

- Detections → `detections/community/<your-rule>.yaml`
- Playbooks → `playbooks/community/<pack-name>/<your-playbook>.playbook.json`
- Plugins → `plugins/community/<your-plugin-id>/`

These show up in the Marketplace with a **Community** badge (versus the
**Verified** badge on AiSOC-authored content). Core content lives directly
under `detections/<category>/`, `playbooks/packs/v1/<category>/`, and
`plugins/<plugin-id>/`.

### Submitting a contribution

1. Pick the right namespace (rule, playbook, or plugin) and follow the schema
   used by an existing item of the same type. Detection schema lives in
   [`detections/README.md`](detections/README.md), playbook schema in
   [`playbooks/README.md`](playbooks/README.md), plugin schema in
   [`packages/plugin-sdk-py/README.md`](packages/plugin-sdk-py/README.md) and
   [`packages/plugin-sdk-go/README.md`](packages/plugin-sdk-go/README.md).
2. **Rebuild the marketplace index locally:**
   ```bash
   pnpm marketplace:build
   pnpm marketplace:sync
   ```
3. Verify CI will be happy:
   ```bash
   pnpm marketplace:check       # asserts the index matches what's on disk
   python3 scripts/validate_detections.py   # if you added detections
   ```
4. Open a PR. CI runs `marketplace:check`, detection validation, and any
   plugin SDK tests. A maintainer will review for content quality, MITRE
   ATT&CK accuracy, and false-positive notes.

### Quality bar for community marketplace items

- **Detections** must include MITRE ATT&CK technique IDs in `tags` (format
  `mitre.attack.T1234[.567]`) and a fixture under `detections/fixtures/`.
- **Playbooks** must declare a clear trigger, an explicit decision tree, and
  any human-approval gates. No silent destructive actions.
- **Plugins** must implement the relevant SDK interface in either Python or
  Go (preferably both). They must declare `min_aisoc_version`, `license`, and
  a `homepage` URL. Network calls go through the SDK's HTTP helpers, never
  bare `requests` or `net/http` calls.
- All items get `verified: false` and `source: "community"` in the index until
  a maintainer promotes them.

## Reporting Bugs

Please use the GitHub issue tracker. Include:
- AiSOC version
- OS and environment
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
