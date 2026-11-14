# Walkthrough — `aws-credential-exfil`

> **AWS credential exfiltration.** Long-lived IAM access keys belonging
> to a CI service account (`ci-svc-prod`) are used from an ASN the
> workload has never previously contacted, immediately followed by
> `s3:ListBuckets` + bulk `s3:GetObject` against a tagged-confidential
> bucket.

- **Fixture:** [`examples/alerts/aws-credential-exfil.json`](./alerts/aws-credential-exfil.json)
- **MITRE techniques:** T1552, T1567, T1078.004
- **Severity at intake:** `critical`
- **What the sandbox computes:** `event_burst` — 3 timestamped events spanning 23.1 s, 3 inside one 60 s window

> **The step-by-step below describes the full stack.** The offline
> `aisoc-sandbox` run shows the same ledger *shape* but computes only what
> arithmetic over these events can give it — there is no model, no graph, no
> Qdrant and no lake in the wheel, and it emits no confidence score, no
> automation tier and no verdict. Values it cannot compute say so, with the
> reason attached. What it does compute for this scenario is listed above.

## Run it

```bash
# Offline simulator:
aisoc-sandbox demo --scenario aws-credential-exfil

# Real stack (after `make up`, with `pip install -e packages/aisoc-cli`):
aisoc submit examples/alerts/aws-credential-exfil.json
```

## What the agent does, step by step

### Step 0 · DetectAgent · detect

Three CloudTrail events ingest as a single fused incident — the AWS
GuardDuty + native AiSOC detections both fire on the
`UnauthorizedAccess:IAMUser/AnomalousASN` pattern. Fusion deduplicates
the three events and lifts the alert to `severity=critical` because
the bucket carries the `Classification=Confidential` tag.

### Step 1 · TriageAgent · triage

The graph walk identifies that `ci-svc-prod` is a long-lived service
account whose key has never rotated, and that the access pattern
(`sts:GetCallerIdentity` → `s3:ListBuckets` → bulk `s3:GetObject`)
matches three public access-key-leak postmortems from Q1 2026.

**Decision (sandbox):** 2 of 4 signals computed from the events, 1 fired. No confidence score: the sandbox runs no model, so it has nothing to calibrate one from.

### Step 2 · HuntAgent · hunt

Sweeps the last 24 h for any other API calls from `198.51.100.77` or
using `AKIAEXAMPLE7QWERTY`. The hunt confirms the key has been used
from exactly one new IP and against exactly one new bucket — clean
exfil signature, no broader compromise yet.

### Step 3 · RespondAgent · respond

Proposes a five-action containment burst. Graded against the approval
matrix, every one of these verbs lands inside the
`human_approval_required` gate:

- `iam.access_key.deactivate({"access_key_id": "AKIAEXAMPLE7QWERTY"})`
- `iam.user.attach_deny_policy({"user": "ci-svc-prod"})`
- `s3.bucket.block_public_access({"bucket": "acme-prod-customer-pii"})`
- `case.create(...)` at severity `critical`
- `case.notify({"channel": "pagerduty", "service": "soc-tier1"})`**Decision (sandbox):** the same actions are listed as call *shapes*, each marked `executed: false`. The automation tier and the approval posture read `not computed` — the live stack resolves both from the capability contract and the approval matrix, and neither is a thing a severity label can select.

## What the analyst would do next

1. Approve `iam.access_key.deactivate` from the responder PWA. The
   deny policy can wait until the on-call confirms there's no
   automated rotation in flight.
2. Look at the bucket's `s3:GetObject` audit log for the full set of
   objects accessed — the alert shows one specific object, but the
   `additionalEventData.totalObjectsListedInWindow=4137` suggests the
   actor was iterating.
3. Trigger the [secrets-rotation playbook](../playbooks/) for every
   IAM key issued in the last 90 days.
4. Open a separate case for `ci-svc-prod` itself — long-lived keys on
   a CI account is the root cause, and the org should migrate to
   short-lived OIDC tokens.
