---
sidebar_position: 22
title: AWS CloudTrail
description: Native AWS CloudTrail audit-event ingestion with a curated high-signal allow-list — IAM grants, trail tampering, public-S3 changes, KMS destruction, and more.
---

# AWS CloudTrail

The AWS CloudTrail connector polls **management-plane API events** from
the CloudTrail event history. Unlike a raw CloudTrail-to-S3 firehose,
this connector ships with a **curated allow-list of ~80 high-signal
event names** chosen to align 1:1 with AiSOC's bundled cloud detection
content.

That choice is deliberate. A busy production AWS account emits **tens
of thousands of CloudTrail events per minute**, the vast majority of
which are read-only describes / lists from AWS services themselves.
Blindly ingesting all of them would saturate the alert pipeline without
producing any net new detection signal. The allow-list keeps ingest
volume tractable while still surfacing every event the bundled
detections actually fire on.

Use the [AWS GuardDuty](/docs/connectors/aws-guardduty) connector for
ML-based threat detection. Use this CloudTrail connector for
**deterministic detection of sensitive AWS API calls** — IAM grants,
trail tampering, public-S3 changes, KMS key destruction, cross-account
sharing, console logins, and so on.

## What you get

| Source | CloudTrail API | Notes |
|---|---|---|
| Management events | `LookupEvents` | One filtered call per event-name in the allow-list |

Events are normalized with `source: aws_cloudtrail` and
`category: cloud`. The full embedded `CloudTrailEvent` payload is
preserved on `raw_event` so detection rules and playbooks can inspect
`requestParameters`, `responseElements`, and the full `userIdentity`
shape.

## Capabilities

| Capability | Backed by | Notes |
|---|---|---|
| `PULL_ALERTS` | `cloudtrail:LookupEvents` | Default — every connector instance |

CloudTrail is read-only. To **block** a malicious IP that surfaces in a
CloudTrail event (e.g. a `ConsoleLogin` from an unexpected geography),
route the alert through a playbook that uses the
[AWS Security Hub](/docs/connectors/aws-security-hub) connector's
`BLOCK_IP` capability or any other network-control connector.

## Prerequisites

- AWS CloudTrail **enabled** in the region you want to monitor — the
  default `Management events: Read/Write` trail that AWS provisions
  on every account is enough.
- IAM permissions:
  - `cloudtrail:LookupEvents`
  - `cloudtrail:DescribeTrails` (used by `Test connection`)
  - `sts:AssumeRole` (only if you target a role in another account)
- One of:
  - **Static access key** (`AccessKeyId` + `SecretAccessKey`) for a dedicated
    IAM user, **or**
  - **No credentials at all** — AiSOC falls back to the **runtime IAM role
    / instance profile** of the host running the `connectors` service.

The runtime-IAM-role path is strongly preferred for production deployments.

## Setup walkthrough

### 1. (Optional) Create a least-privilege IAM user

If you cannot use an instance role, create a dedicated IAM user with
**only** the policy below, and capture an access key for it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AiSOCCloudTrailRead",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "cloudtrail:DescribeTrails"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. Add the connector in AiSOC

1. **Connectors → Add connector → AWS CloudTrail**.
2. Set **AWS Region** (e.g. `us-east-1`).
3. Leave **Access Key ID** and **Secret Access Key** **blank** to use the
   runtime IAM role. Otherwise paste the static credentials from step 1.
4. Leave **Event allow-list** blank to use AiSOC's curated default
   (recommended). See [Customising the allow-list](#customising-the-allow-list)
   below if you need to override it.
5. **Test connection** — AiSOC calls `DescribeTrails` to verify auth.
6. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll iterates the configured event allow-list and issues one
  paginated `LookupEvents` call per event name, filtered by
  `LookupAttributes={EventName=<name>}` and the time window
  `(now - 300s, now)`.
- Per-event-name results are capped at **100 events per poll** to bound
  memory and respect the AWS CloudTrail rate limit
  (**2 transactions per second per region per account**).
- Failures on any single event-name lookup are logged and skipped — one
  bad attribute does not halt the rest of the poll.

## Severity mapping

CloudTrail events do **not** carry intrinsic severity, so AiSOC labels
each event by sensitivity:

| Event class | Examples | AiSOC severity |
|---|---|---|
| Trail/detection tamper, KMS destruction, root account use, org tampering | `DeleteTrail`, `StopLogging`, `DisableSecurityHub`, `ScheduleKeyDeletion`, `RemoveAccountFromOrganization`, `LeaveOrganization` | `high` |
| Mutating IAM / network / public-S3 / config | `CreateAccessKey`, `AttachUserPolicy`, `PutBucketPolicy`, `AuthorizeSecurityGroupIngress`, `PutKeyPolicy` | `medium` |
| Read-only recon | `GetAccountAuthorizationDetails`, `ListAccessKeys`, `GetSecretValue` | `low` |

If the event has an `errorCode` set (the API call was denied), AiSOC
**bumps the severity up one tier**. A denied destructive action is
often the loudest signal in the account — for example, an attacker
trying `StopLogging` against a trail they don't have permission to
modify.

## Customising the allow-list

The `event_names` field accepts three modes:

- **Blank** (default) — use AiSOC's curated detection-aligned default
  list. This is the right answer for ~95% of operators.
- **Comma-separated event names** — replace the default with your own
  list. Example: `ConsoleLogin,CreateAccessKey,PutBucketPolicy,DeleteTrail`.
  Useful when you've added custom detection content and want to
  surface a narrower set than the default.
- **`*`** — disable filtering entirely. AiSOC will pull every
  CloudTrail event in the time window. **High volume warning** — only
  use this in lab/staging accounts or when you have downstream
  rate-limiting in place. A single production account on `*` can
  generate millions of events per day.

The default list is curated against the bundled
`detections/cloud/aws-*.yaml` rules — every event name in it is
referenced by at least one detection rule.

## Multi-account / multi-region

CloudTrail's management-event history is per-region. To cover an
account globally, add **one connector instance per region** that hosts
production workloads. The connector emits an `aws_region` field on
every event so playbooks can branch on origin.

For multi-account topologies, prefer one connector per
account × region pair, each with its own IAM credentials. CloudTrail
does not have a delegated-administrator pattern equivalent to
GuardDuty.

## Troubleshooting

**`AccessDenied` on `LookupEvents`** — the IAM user / role is missing
`cloudtrail:LookupEvents`. Reattach the policy from step 1.

**Test connection succeeds but no events appear** — confirm the
allow-list is not over-narrow for your account, and that the events
you expect are actually firing in the AWS console under
**CloudTrail → Event history**. Try setting `event_names` to `*`
temporarily (in lab) to confirm the connection works.

**Events arrive several minutes late** — CloudTrail is **eventually
consistent**. AWS publishes a typical end-to-end delivery latency of
~15 minutes. AiSOC polls a 5-minute window every 300 seconds with no
high-water-mark cursor, so events that arrive late will be picked up
on the next poll cycle.

**Rate-limit / `ThrottlingException`** — the allow-list iteration can
hit the 2-TPS-per-region CloudTrail limit if the list is very large
or polling is set very aggressively. Reduce the allow-list, increase
the poll interval, or split the load across multiple connector
instances per region.

**`boto3 is required` at runtime** — boto3 is bundled with the
`services/connectors` Docker image. If you are running the service
outside Docker, install it: `pip install boto3`.

## Related

- [AWS GuardDuty](/docs/connectors/aws-guardduty) — ML-based threat
  detection layered on top of CloudTrail, VPC Flow Logs, and DNS.
- [AWS Security Hub](/docs/connectors/aws-security-hub) — multi-source
  finding aggregator with `BLOCK_IP` / `ALLOW_IP` containment.
- [AWS VPC Flow Logs](/docs/connectors/aws-vpc-flow) — raw network
  telemetry to cross-reference against CloudTrail events.
