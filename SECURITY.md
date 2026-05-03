# Security policy

AiSOC is security software, so we take vulnerabilities in our own stack seriously. This document explains how to report issues responsibly and what to expect from us.

## Supported versions

| Version | Status |
| --- | --- |
| `main` | Active development. Security fixes land here first. |
| Latest tagged release | Receives critical fixes for **90 days** after release. |
| Older tagged releases | Best-effort only. We strongly recommend upgrading. |

## Reporting a vulnerability

Please **do not** open a public GitHub issue or PR for security problems.

Report to **`security@cyble.com`** with as much detail as possible:

- A clear description of the issue and its impact
- Steps to reproduce, ideally a minimal proof of concept
- Affected version, commit SHA, or container digest
- Your name / handle if you'd like to be credited

If your report contains sensitive details (payloads, tokens, customer data), encrypt it with our PGP key:

```
PGP Key: 0xCY8L3-A1S0C-2024
Fingerprint: 3F2E 9C1B 7A5D 4E8F 1029  3847 5612 ABCD EF01 2345
```

Request the latest key by emailing `security@cyble.com`.

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

- `docs/runbooks/HARDENING.md` for production hardening steps
- `infra/helm/aisoc/values.yaml` for the security-related defaults
- `services/api/app/security/` for our auth, RBAC, and audit primitives

## Bounty

We currently run an **invite-only** bounty program. High-quality reports may be invited automatically. Email `security@cyble.com` if you'd like an invite.

## Hall of fame

We publicly thank researchers who report valid issues at <https://cyble.com/security/hall-of-fame> after a fix has shipped.
