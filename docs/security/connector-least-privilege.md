# Connector Least-Privilege Scopes

Phase 1.6 of the world-class program. Because a vault compromise pivots into every connected system, each connector credential must be granted the **minimum** scope it needs — read/telemetry for detection, plus only the specific write scopes for any SOAR action the operator enables.

Principle: grant read/audit scopes by default; add a containment scope only when the matching autonomous action is enabled for that connector, and prefer resource-scoped policies over account-wide ones.

This is the living reference; a representative set of the highest-impact connectors is documented below. Contributions adding a connector must include its minimum-scope row (enforced narratively in review; a scope-audit gate is tracked for Phase 10's conformance suite).

## AWS (CloudTrail / GuardDuty / Security Hub)

- Read/detect: `cloudtrail:LookupEvents`, `guardduty:GetFindings`, `guardduty:ListFindings`, `securityhub:GetFindings`.
- Contain (only if enabled): `ec2:AuthorizeSecurityGroupIngress`/`RevokeSecurityGroupIngress` scoped to a quarantine SG; `iam:UpdateAccessKey` scoped to the target user path.
- Do NOT grant: `*:*`, `iam:CreateUser`, org-wide admin.

## Okta

- Read/detect: `okta.logs.read`, `okta.users.read`, `okta.sessions.read`.
- Contain (only if enabled): `okta.users.manage` limited to session-revocation / suspend; scope to a non-admin group where possible.
- Do NOT grant: super-admin API token.

## CrowdStrike Falcon

- Read/detect: Detections `READ`, Hosts `READ`, Event streams `READ`.
- Contain (only if enabled): Host containment `WRITE` (network-contain), Real Time Response only if host-isolation playbooks are enabled.
- Do NOT grant: Falcon administrator, API client management.

## GitHub

- Read/detect: `read:audit_log` (org), `repo:read` metadata, `read:org`.
- Contain (only if enabled): `admin:org` is over-scoped — prefer fine-grained tokens limited to the specific repos/actions (e.g. revoke a compromised deploy key).
- Do NOT grant: classic PAT with full `repo` + `admin:org` unless a specific action requires it.

## Splunk / Elastic (SIEM)

- Read/detect: search/query role on the relevant indexes only.
- Contain: SIEM connectors are read-oriented; no write scope unless a notable-update action is enabled.
- Do NOT grant: admin/`sc_admin`.

## Audit

Until the Phase 10 conformance gate lands, review every connector PR against this principle and record the connector's minimum scope in its docs page under `apps/docs/docs/connectors/<id>.md`. The vault threat model that motivates this is in [`platform-threat-model.md`](platform-threat-model.md).
