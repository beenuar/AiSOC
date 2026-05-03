---
sidebar_position: 2
---

# Contribution Guidelines

Thank you for contributing to AiSOC! Please read these guidelines before opening a PR.

## Code of Conduct

All contributors must follow our [Code of Conduct](https://github.com/beenuar/aisoc/blob/main/CODE_OF_CONDUCT.md).

## Branching Strategy

- `main` — stable, tagged releases
- `dev` — active development
- `feature/<name>` — new features
- `fix/<name>` — bug fixes

## Pull Requests

1. Fork the repo and create a branch from `dev`
2. Write tests for any new code
3. Ensure CI passes (`pytest`, `go test ./...`, `pnpm lint`)
4. Update documentation if needed
5. Open a PR against `dev`

## Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add VirusTotal enricher plugin
fix: handle empty indicator list in ForensicAgent
docs: update quickstart with Go SDK example
chore: bump pnpm to 9.1.0
```

## Code Style

- **Python**: `ruff` for linting, `mypy` for type checking
- **Go**: `go vet` + `gofmt`
- **TypeScript**: ESLint + Prettier (enforced by CI)

## Security

Never commit secrets, API keys, or credentials. Use `.env` and `.gitignore`.

Report security vulnerabilities privately via GitHub Security Advisories.

## License

By contributing, you agree that your contributions will be licensed under the
[MIT License](https://github.com/beenuar/aisoc/blob/main/LICENSE).
