# Community Detections

This directory holds detection rules contributed by the AiSOC community.

Anything you drop here as `<your-rule>.yaml` will be picked up by
[`scripts/build_marketplace.py`](../../scripts/build_marketplace.py) on the
next `pnpm marketplace:build` and shown in the in-app marketplace with a
Community badge.

## Authoring a community detection

Use any rule under [`detections/cloud/`](../cloud/),
[`detections/identity/`](../identity/), or
[`detections/endpoint/`](../endpoint/) as a template. Every rule must:

- Declare a stable `id` (kebab-case, no spaces). The convention for community
  contributions is `community-<github-handle>-<short-name>`.
- Map to MITRE ATT&CK via `tags` entries of the form
  `mitre.attack.T1234` or `mitre.attack.T1234.567`. The marketplace MITRE
  filter only sees rules with at least one such tag.
- Set `severity` to one of `low`, `medium`, `high`, `critical`.
- Reference a fixture under [`detections/fixtures/`](../fixtures/) so the
  detection can be replay-tested.
- Include a short `false_positives:` list (even if it is just `[]`) so
  responders know what to expect.

## Validation

Before opening a PR:

```bash
python3 scripts/validate_detections.py
pnpm marketplace:build
pnpm marketplace:check
```

The `marketplace:check` step asserts that `marketplace/index.json` and its
public copy at `apps/web/public/marketplace/index.json` match what the build
script produces from the current contents of this repo. CI will fail
otherwise.

## Promotion path

Community detections start with `verified: false` and `source: "community"`.
After a maintainer reviews the rule against several weeks of real telemetry,
the rule may be promoted into the appropriate top-level category folder
(e.g. `detections/identity/`) and re-marked as verified.
