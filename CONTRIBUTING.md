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
- **Python**: Black + isort + mypy (config in pyproject.toml)
- **Go**: gofmt + golangci-lint

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

## Submitting a Pull Request

1. Update your branch: `git fetch upstream && git rebase upstream/main`
2. Run tests: `pnpm test` (frontend) and `poetry run pytest` (Python)
3. Push to your fork: `git push origin feature/my-feature`
4. Open a PR on GitHub with a clear description of changes

## Adding New Connectors

Connectors are one of the most valuable contributions. To add a new connector:

1. Create a new directory under `integrations/connectors/<name>/`
2. Implement the connector following the pattern in `integrations/connectors/crowdstrike/`
3. Required files:
   - `main.py` — Entry point
   - `connector.py` — Connector class implementing `BaseConnector`
   - `Dockerfile` — Container build file
   - `README.md` — Connector documentation
4. Add connector config to `docker-compose.yml`
5. Write integration tests

Existing connectors you can use as references: `crowdstrike`, `aws-security-hub`, `microsoft-sentinel`, `splunk`, `okta`.

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
