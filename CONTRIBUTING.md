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

## Reporting Bugs

Please use the GitHub issue tracker. Include:
- AiSOC version
- OS and environment
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
