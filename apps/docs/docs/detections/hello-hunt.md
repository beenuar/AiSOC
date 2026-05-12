---
sidebar_position: 3
title: Hello, hunt — write your first AiSOC detection
description: A walkthrough that ships a runnable AiSOC detection rule end to end. Author the YAML, pin it with positive and negative fixtures, run it against the rule engine, and surface it in the marketplace — no vendor account required.
---

# Hello, hunt

This tutorial walks you end-to-end through the work of adding a new detection rule to AiSOC. By the end you will have:

- A `community-tier` Sigma-style YAML rule under `detections/community/<category>/`.
- A **positive** fixture under `detections/fixtures/positive/` that the rule must match.
- A **negative** fixture under `detections/fixtures/negative/` that the rule must *not* match.
- Local proof that `scripts/validate_detections.py` is happy with all three files.
- Local proof that the rule fires on the positive fixture and stays silent on the negative one when run through the real `services/api/app/services/rule_engine.py`.
- A marketplace entry that surfaces the rule under the `Community` badge after `pnpm marketplace:sync`.

The example rule targets [AWS root-account console logins](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials), because:

- The CloudTrail `ConsoleLogin` shape is well documented and easy to reason about.
- "Root logged in successfully" is a real signal — most production AWS environments lock the root user away after initial setup, so any successful console login under `userIdentity.type: Root` is worth a human eyeballing.
- The rule needs only three field comparisons, which keeps the tutorial focused on the *contract* rather than on detection cleverness.

When you're ready to write a real rule, copy the example, swap the field names, and tighten the condition. The shape stays the same.

## Where the example lives

The reference detection plus its two fixtures live at:

```text
detections/community/cloud/hello-hunt-aws-root-login.yaml
detections/fixtures/positive/hello-hunt-aws-root-login.json
detections/fixtures/negative/hello-hunt-aws-root-login.json
```

Three files, one rule. That's the whole contract.

## Detection tiers — pick the right shelf first

AiSOC sorts detections into three tiers, and each tier has a different bar:

| Tier        | Path                                              | `id` prefix                   | Authoring style       | Bar                                                                                                                                                                                                                  |
| ----------- | ------------------------------------------------- | ----------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `native`    | `detections/{cloud,identity,endpoint,...}/`       | `det-`                        | Spec-generated YAML   | Strict. Must come from `scripts/detection_specs/*.py`, must have positive + negative fixtures, must round-trip through `scripts/generate_detections.py`, must replay cleanly. CI will fail if any of those drift.    |
| `imported`  | `detections/{sigma,car,splunk,chronicle}-imports/`| `<source>-...`                | Importer-generated    | Provenance required (`source`, `source_id`, `source_commit`, `license`, `imported_at`, `imported_by`, `upstream_path`). Fixtures optional. Rules that don't run on our engine land in `_quarantine/` automatically. |
| `community` | `detections/community/<category>/`                | `community-<github-handle>-*` | Hand-authored YAML    | Permissive. No spec required, fixtures encouraged but optional. The validator emits a `WARN` instead of a `FAIL` when there's no spec to round-trip against.                                                         |

This tutorial sticks to the **community** tier on purpose — it's the only tier you can use without modifying `scripts/detection_specs/*.py`. Native rules belong to the curated v1.0 set; the path from "I have a rule idea" to "it ships in `det-*` form" goes through a maintainer review, and that's a different doc.

If you eventually want your rule promoted to native, see [Graduating from `community/` to `native/`](#graduating-from-community-to-native) at the bottom.

## Step 1 — Pick a stable `id`

```yaml
id: community-aisoc-hello-hunt-aws-root-login
```

Three rules to internalise:

1. **Lowercase, kebab-case, no spaces.** The `id` is a wire identifier — it ends up in `match_summary` payloads, in `events.matched_rule_ids`, in marketplace JSON, and in case timelines. Treat it like a primary key.
2. **Prefix with `community-<your-handle>-`.** This is enforced socially, not technically — the validator doesn't reject other shapes — but `marketplace/curated.json` and the in-app filters group by prefix, and reviewers will ask you to rename if you skip it.
3. **Never change it after merge.** Renaming a rule breaks every alert row in production that references it. If the rule needs a behavioural overhaul, give the new version a new `id` and deprecate the old one.

The example uses `aisoc` as the handle because the AiSOC project itself is the author. Real contributions use your GitHub username (`community-jdoe-aws-root-login`) or your org name (`community-acme-aws-root-login`).

## Step 2 — Fill in the metadata block

```yaml
name: "[Hello Hunt] AWS Root Account Console Login"
description: |
  Tutorial detection from apps/docs/docs/detections/hello-hunt.md.
  Fires when AWS CloudTrail records a successful console login under the
  `Root` user identity. Real environments should keep the AWS root account
  unused except for break-glass — any successful console login is worth a
  human eyeballing.
version: 1.0.0
severity: high
category: cloud
tags:
  - mitre.attack.T1078.004
  - tlp.white
  - tutorial
log_source:
  product: aws
  service: cloudtrail
```

A few non-obvious things:

- **`severity` has four tiers, not five.** The validator accepts `low | medium | high | critical`. Vendor 5-tier ladders (Azure, SCC, GitHub) collapse into this set in the connector's `normalize()` — see [Hello, connector](/docs/connectors/hello-connector) for the rationale. Using `informational` here is a hard FAIL.
- **`category` is shared with the connector taxonomy.** Valid values are `network | endpoint | cloud | identity | application | data-exfil`. The detection coverage page groups by this field and the connector router uses it as a routing hint, so picking the wrong one means your rule runs against the wrong event stream.
- **`tags` are the MITRE wiring.** The marketplace MITRE filter only sees rules whose `tags` include at least one entry of the form `mitre.attack.T1234` or `mitre.attack.T1234.567`. Skip the tag, lose the visibility. Use [`attack.mitre.org`](https://attack.mitre.org/) to pick the technique — `T1078.004` (Valid Accounts: Cloud Accounts) is the right one for "someone logged in as root".
- **`log_source` is a hint, not a filter.** The rule engine doesn't gate evaluation on it today — it'll happily try your rule against any flattened event. The field exists so reviewers and downstream tooling know what shape the rule expects. Fill it in anyway; if/when log-source routing lands, your rule will already be ready.

## Step 3 — Write the `detection` block

This is the actual logic. The community tier supports the same Sigma-style shape that the rule engine's [`_sigma_fallback`](https://github.com/beenuar/AiSOC/blob/main/services/api/app/services/rule_engine.py) understands:

```yaml
detection:
  selection:
    eventName: ConsoleLogin
    userIdentity.type: Root
    responseElements.ConsoleLogin: Success
  condition: selection
```

Three things are happening here that you only see if you read the engine:

1. **Field names use dot notation for nested keys.** Before evaluation, every event passes through `_flatten_dict`, which turns `{"userIdentity": {"type": "Root"}}` into `{"useridentity.type": "Root"}`. Both keys and incoming JSON paths are lowercased, so your rule field can be written as `userIdentity.type`, `useridentity.type`, or `USERIDENTITY.TYPE` and they all collide on the same flattened key. The example uses the original AWS casing because that's what the CloudTrail docs say, and matching the upstream spelling makes the rule easier to audit.
2. **Values are matched as `lower(rule) in lower(event)`.** A `selection` entry of `eventName: ConsoleLogin` matches any event whose `eventname` field *contains* the substring `consolelogin`. That's loose by design — it means `ConsoleLogin`, `consoleLogin`, and `ConsoleLoginAttempt` all match. If you need exact equality, write a more specific value, or pair with a second selection that's intentionally narrow.
3. **List values are OR-ed.** `eventName: [ConsoleLogin, AssumeRole]` matches if *any* listed value is a substring of the event field. Inside a single `selection` block, multiple keys are AND-ed (all must match). Across selection blocks, you compose with `condition`.

The `condition` field is parsed as a small boolean expression over selection names. The example uses the simplest case (`condition: selection` — a single selection block must match), but the engine also supports `selection1 and selection2`, `selection1 or selection2`, and `not exclusion`. Anything more complex than that and you're better off graduating to a native spec.

### A note on `keywords` blocks

If a selection value is a YAML list at the top level (instead of a dict), the engine treats it as a **keywords** block — every keyword must appear *somewhere* in the flattened event payload (concatenated). Useful for "does this event mention any of these IOCs?" hunts, but the wider the search the noisier the rule, so prefer field-scoped `selection` blocks for production work.

## Step 4 — Document the rough edges

```yaml
false_positives:
  - Documented break-glass access — verify the change-management ticket
    before closing.
  - Initial AWS account setup before an IAM admin user exists.
playbook: tpl-credential-access
enabled: true
author: AiSOC Tutorial
created: '2026-05-12'
modified: '2026-05-12'
references:
  - https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#lock-away-credentials
```

These fields are optional from the validator's perspective but required for human review:

- **`false_positives`** is the field reviewers stare at first. If it's empty, expect a "what does this miss / over-fire on?" question on the PR. Be specific — "documented break-glass access" is a good answer; "noisy" is not.
- **`playbook`** is a soft binding to a [playbook template](/docs/concepts/playbooks). When a matching alert lands, the case auto-creator uses this hint to suggest a starting playbook. `tpl-credential-access` is the generic credential-access response template that ships with v1.0.
- **`enabled: true`** controls whether the rule runs in production. Community rules ship as `true` by default; flip to `false` if you need to land the rule but don't want it firing yet (e.g. you're staging a backfill).
- **`references`** is what an analyst follows when they're triaging an alert at 2am and have never heard of MITRE T1078.004. Link upstream vendor docs, ATT&CK pages, and (if relevant) the original blog post that prompted the rule.

## Step 5 — Write the positive fixture

The fixture is a single CloudTrail event that **must** trigger the rule. Drop it at `detections/fixtures/positive/<rule-slug>.json` (slug == `id` minus the `community-aisoc-` prefix, so the file is `hello-hunt-aws-root-login.json`):

```json
{
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "userIdentity": {
    "type": "Root",
    "accountId": "123456789012",
    "arn": "arn:aws:iam::123456789012:root"
  },
  "sourceIPAddress": "203.0.113.42",
  "responseElements": {
    "ConsoleLogin": "Success"
  },
  "eventTime": "2026-05-12T18:00:00Z"
}
```

Three rules for fixtures:

1. **Use a real upstream shape.** Copy the JSON straight from the vendor's docs or from a sanitised production sample. AWS `203.0.113.0/24` is RFC 5737 documentation space; `12345...` is a documentation account ID. Never put real customer data in a fixture file.
2. **Keep it minimal.** Only include the fields the rule looks at, plus enough surrounding context that a reviewer can tell what the event represents. Bloated fixtures rot faster.
3. **Match every field the rule reads.** If the rule has three field comparisons, the positive fixture must satisfy all three. The validator doesn't enforce this for community rules, but the rule engine quietly returns zero matches if you forget one — and you'll only catch that when you run the engine yourself in [Step 7](#step-7--run-the-rule-against-the-rule-engine).

## Step 6 — Write the negative fixture

The negative fixture has the same shape but **must not** match. Drop it at `detections/fixtures/negative/hello-hunt-aws-root-login.json`:

```json
{
  "eventName": "ConsoleLogin",
  "eventSource": "signin.amazonaws.com",
  "userIdentity": {
    "type": "IAMUser",
    "userName": "alice",
    "accountId": "123456789012",
    "arn": "arn:aws:iam::123456789012:user/alice"
  },
  "sourceIPAddress": "203.0.113.42",
  "responseElements": {
    "ConsoleLogin": "Success"
  },
  "eventTime": "2026-05-12T18:00:00Z"
}
```

The trick: change *exactly one* thing from the positive fixture so that the rule no longer fires. Here, `userIdentity.type` flips from `Root` to `IAMUser`. Everything else stays identical so a reviewer can see at a glance what the rule is keying on.

This is also the format you'll use later when you tune the rule against a false positive — the FP becomes a new negative fixture, and the rule has to be tightened until it stops matching.

## Step 7 — Run the rule against the rule engine

The validator catches schema and provenance errors, but it does **not** execute community rules — that means a rule with a typo in the field name validates fine and quietly never fires in production. Don't trust the validator for matching behaviour. Drive the engine yourself:

```bash
python3 - <<'PY'
import json
import sys
from pathlib import Path

sys.path.insert(0, "services/api")
from app.services import rule_engine  # noqa: E402

rule_body = Path(
    "detections/community/cloud/hello-hunt-aws-root-login.yaml"
).read_text()

positive = json.loads(
    Path("detections/fixtures/positive/hello-hunt-aws-root-login.json").read_text()
)
negative = json.loads(
    Path("detections/fixtures/negative/hello-hunt-aws-root-login.json").read_text()
)

pos_hits = rule_engine._sigma_fallback(rule_body, [positive])
neg_hits = rule_engine._sigma_fallback(rule_body, [negative])

print(f"positive matched: {len(pos_hits)} (expected 1)")
print(f"negative matched: {len(neg_hits)} (expected 0)")

assert len(pos_hits) == 1, "positive fixture should fire the rule"
assert len(neg_hits) == 0, "negative fixture must not fire the rule"
print("OK — both fixtures behave as expected")
PY
```

Expected output:

```text
positive matched: 1 (expected 1)
negative matched: 0 (expected 0)
OK — both fixtures behave as expected
```

If the positive fixture returns `0`, the rule's field path almost certainly disagrees with the actual flattened event. Re-read [Step 3](#step-3--write-the-detection-block) — the engine lowercases everything, so a typo like `userIdentity.Type` (uppercase `T`) is invisible until you run it through `_flatten_dict`. If the negative fixture returns `1`, your rule is too loose; tighten the values or add a second selection.

## Step 8 — Pin the contract with the validator

```bash
python3 scripts/validate_detections.py
```

For the example rule you should see (somewhere in the long output):

```text
WARN  [community] detections/community/cloud/hello-hunt-aws-root-login.yaml  no spec
PASS  [community] detections/community/cloud/hello-hunt-aws-root-login.yaml
```

The `WARN` is expected — community rules are hand-authored, so there's no entry in `scripts/detection_specs/*.py` to round-trip them against. The `PASS` is what matters: it means the YAML is syntactically valid, has every required field, the severity and category are in the allowed set, and the `id` doesn't collide with any other rule in the corpus.

If you see a `FAIL` on the rule, read the message — it will tell you exactly which field is wrong. Common ones:

- `severity must be one of {low, medium, high, critical}` — you wrote `info` or `informational`. Use `low`.
- `category must be one of ...` — you used a connector category like `saas` or `vcs` that doesn't exist on the detection side.
- `duplicate id ...` — the `id` you picked is already used by another rule. Add your handle to the prefix.

## Step 9 — Surface it in the marketplace

```bash
pnpm marketplace:build
pnpm marketplace:sync
pnpm marketplace:check
```

What each step does:

1. **`marketplace:build`** regenerates `marketplace/index.json` from the on-disk corpus. Your community rule appears under `categories.detections` with `verified: false` and `source: "community"`.
2. **`marketplace:sync`** mirrors `marketplace/index.json` to `apps/web/public/marketplace/index.json` so the in-app catalog grid picks it up. Skipping this step is the most common reason a rule passes validation locally but doesn't show in the UI.
3. **`marketplace:check`** asserts that the two copies match. CI fails on the smallest diff, so always run sync before opening the PR.

After this, the rule shows up in the in-app marketplace at `/marketplace` with a `Community` badge, gated by the MITRE filter you set in `tags`.

## Step 10 — (Optional) Replay the rule against your tenant's live events

If you have a running AiSOC dev stack and want to see the rule fire end to end:

```bash
# 1. Restart the API so it reloads the detection corpus from disk.
docker compose -f docker-compose.dev.yml restart api

# 2. Replay the positive fixture into the ingest pipeline.
curl -X POST http://localhost:8000/v1/ingest/batch \
  -H "Content-Type: application/json" \
  -H "X-Tenant-ID: demo" \
  -d "@detections/fixtures/positive/hello-hunt-aws-root-login.json"

# 3. Watch the rule fire.
curl -s "http://localhost:8000/v1/alerts?rule_id=community-aisoc-hello-hunt-aws-root-login" \
  -H "X-Tenant-ID: demo" | jq '.items[0]'
```

You should see one alert come back with `severity: "high"` and the original CloudTrail event embedded under `raw`. Drop the rule ID into the [Explain Drawer](/docs/api/rest) and you'll get the full lineage: which selection block matched, which field values, and which playbook template the rule recommends.

## Graduating from `community/` to `native/`

When you've run the rule against a few weeks of real telemetry and you want it promoted into the curated v1.0 set:

1. **Open a promotion PR.** Tag a maintainer. The PR should include the false-positive rate you observed, the volume of events evaluated, and at least one example of a real alert the rule produced.
2. **Add a spec entry.** Native rules are generated from `scripts/detection_specs/<category>.py` so the corpus stays auditable. The maintainer will help you author the spec; the existing entries in `cloud.py` are good templates.
3. **Move the YAML.** From `detections/community/<category>/<slug>.yaml` to `detections/<category>/<slug>.yaml`. Change the `id` prefix from `community-...` to `det-` and bump `version`.
4. **Re-run validation.** `python3 scripts/validate_detections.py --strict-fixtures` must pass for native rules — fixtures are no longer optional, and the spec round-trip is enforced.
5. **Mark it verified.** The marketplace build will switch `verified: true` and `source: "native"` automatically based on the file path.

That's the full path. Promotion is intentionally manual — the curated set is one of AiSOC's sharpest selling points, and we'd rather move slowly than dilute it.

## Related

- [Detection coverage](/docs/detections/coverage) — what we ship in the curated v1.0 set, by family.
- [Hello, connector](/docs/connectors/hello-connector) — the sister tutorial for the ingest side.
- [Plugin SDK overview](/docs/plugins/overview) — for connectors and enrichers distributed outside the monorepo.
- [Contributing guidelines](/docs/contributing/guidelines) — broader expectations for PRs that touch `detections/`.
