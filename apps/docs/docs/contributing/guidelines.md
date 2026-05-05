---
sidebar_position: 2
---

# Contribution Guidelines

Thank you for contributing to AiSOC! Please read these guidelines before opening a PR.

## Code of Conduct

All contributors must follow our [Code of Conduct](https://github.com/beenuar/AiSOC/blob/main/CODE_OF_CONDUCT.md).

## Branching Strategy

- `main` — the long-lived branch most contributors target. Tags cut here.
- `develop` — optional integration branch; CI watches both `main` and
  `develop`, so coordinated multi-PR work can land here first.
- `feature/<name>` — new features
- `fix/<name>` — bug fixes

## Pull Requests

1. Fork the repo and create a branch from `main`
   (or from `develop` if you are coordinating a stack of changes there).
2. Write tests for any new code.
3. Ensure CI passes locally: `pnpm lint`, `pnpm --filter @aisoc/web test`,
   `pytest services/<name>/tests/` for Python services you touched, and
   `go test ./...` for Go services you touched.
4. Update documentation if behavior, commands, or APIs changed.
5. Open a PR against `main` (or `develop` if your work is being coordinated
   on the integration branch).

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
[MIT License](https://github.com/beenuar/AiSOC/blob/main/LICENSE).
