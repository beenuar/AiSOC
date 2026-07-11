# Security policy

AiSOC is security software, so we take vulnerabilities in our own stack seriously. This document explains how to report issues responsibly and what to expect from us.

## Threat models

- Agent + tool surface (prompt injection, tool abuse): [`docs/security/agent-threat-model.md`](docs/security/agent-threat-model.md).
- Platform + credential vault: [`docs/security/platform-threat-model.md`](docs/security/platform-threat-model.md) (Phase 1.6).

## Supported versions

| Version | Status |
| --- | --- |
| `main` | Active development. Security fixes land here first. |
| Latest tagged release | Receives critical fixes for **90 days** after release. |
| Older tagged releases | Best-effort only. We strongly recommend upgrading. |

## Reporting a vulnerability

Please **do not** open a public GitHub issue or PR for security problems.

Use [GitHub's private vulnerability reporting](https://github.com/beenuar/AiSOC/security/advisories/new) to send us a report directly. Include as much detail as possible:

- A clear description of the issue and its impact
- Steps to reproduce, ideally a minimal proof of concept
- Affected version, commit SHA, or container digest
- Your name / handle if you'd like to be credited

If GitHub's reporting flow is not workable for your situation, you can instead reach the maintainers through the [SECURITY contact in the repository profile](https://github.com/beenuar/AiSOC). Please request our PGP key in your first message and we'll respond out-of-band before you send sensitive details (payloads, tokens, customer data).

## What to expect

| Window | What we do |
| --- | --- |
| **Within 48 hours** | Acknowledge receipt and assign a primary contact. |
| **Within 7 days** | Provide an initial triage: severity, scope, mitigation status. |
| **Within 30 days** | Ship a fix, advisory, or a clear timeline if more work is required. |
| **On disclosure** | Coordinate a public advisory and credit the reporter (if desired). |

We follow [coordinated disclosure](https://www.first.org/cvss/) and assign CVSS v3.1 scores in our advisories.

## Scope

In scope:

- Source in this repository (services, web, infra, integrations, packages)
- Official Docker images published from this repository
- Default Helm chart and Terraform modules in `infra/`

Out of scope:

- Third-party services that AiSOC integrates with (CrowdStrike, Splunk, AWS, etc.)
- Self-hosted deployments that have been customized
- Issues requiring physical access to a host

## Hardening guidance

If you operate AiSOC, please review:

- [`docs/runbooks/HARDENING.md`](docs/runbooks/HARDENING.md) for production hardening steps
- [`infra/helm/aisoc/values.yaml`](infra/helm/aisoc/values.yaml) for the security-related defaults
- [`services/api/app/core/security.py`](services/api/app/core/security.py) and [`services/api/app/auth/`](services/api/app/auth/) for our auth, RBAC, and SSO primitives
- [`services/api/app/middleware/`](services/api/app/middleware/) for rate limiting, audit logging, and request hardening

## Bounty

AiSOC is an open-source project and does not currently operate a paid bounty program. We deeply appreciate responsible reports and will credit researchers in advisories and the hall of fame.

## Hall of fame

We publicly thank researchers who report valid issues. Once a fix has shipped, we credit reporters (with their consent) in the corresponding [GitHub Security Advisory](https://github.com/beenuar/AiSOC/security/advisories) and the relevant `CHANGELOG.md` entry.

The full list of credited researchers lives in [.github/CREDITS.md](.github/CREDITS.md#security-researchers). Highlights:

| Reporter | Issue / PR | Summary |
| --- | --- | --- |
| [@TanmayZade](https://github.com/TanmayZade) | [#220](https://github.com/beenuar/AiSOC/issues/220) → [PR #219](https://github.com/beenuar/AiSOC/pull/219) | Prompt injection in classification agents leading to alert auto-close bypass. Reporter also authored the fix (prompt sanitiser + untrusted-content wrapping). |
| [@mangod12](https://github.com/mangod12) | [#159](https://github.com/beenuar/AiSOC/issues/159) → [PR #221](https://github.com/beenuar/AiSOC/pull/221) | Proposed cross-tenant isolation tests + nightly CI for RBAC regression; informed the tenant-isolation hardening on the detection-loop endpoint. |
| [@jay-cyble](https://github.com/jay-cyble) | [#130](https://github.com/beenuar/AiSOC/issues/130) | Structured review of 13 security & UI issues found via code review + live-site inspection. |

If you've reported a valid issue and aren't listed here, please open a PR against [.github/CREDITS.md](.github/CREDITS.md) — we'd rather over-credit than miss anyone.
