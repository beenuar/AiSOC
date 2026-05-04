# Community Playbooks

This directory holds response playbooks contributed by the AiSOC community.

Drop your playbook as
`playbooks/community/<your-pack>/<your-playbook>.playbook.json` and it will
be auto-indexed by
[`scripts/build_marketplace.py`](../../scripts/build_marketplace.py) on the
next `pnpm marketplace:build`. It will appear in the in-app marketplace with
a Community badge.

## Authoring a community playbook

Use any playbook under [`playbooks/packs/v1/`](../packs/v1/) as a template.
Every playbook must:

- Have a stable `id` (kebab-case). Convention for community playbooks:
  `community-<github-handle>-<short-name>`.
- Declare a clear `trigger` (case category, severity threshold, detection ID
  it responds to, etc.).
- Use the standard `steps[]` schema with explicit `kind` (`enrich`, `notify`,
  `action`, `decision`, `wait_for_approval`, …) and a documented
  `description`.
- Mark every irreversible action (account lockout, host isolation, file
  deletion, etc.) behind a `wait_for_approval` step.
- Include MITRE ATT&CK references in `tags` (format `mitre.attack.T1234[.567]`)
  for any technique the playbook is responding to. This is what powers the
  MITRE filter in the marketplace.

## Validation

```bash
pnpm marketplace:build
pnpm marketplace:check
```

CI will reject PRs whose `marketplace/index.json` does not match what the
build script produces.

## Promotion path

Community playbooks start with `verified: false` and `source: "community"`.
A maintainer can promote a playbook into `playbooks/packs/v1/<category>/`
after review.
