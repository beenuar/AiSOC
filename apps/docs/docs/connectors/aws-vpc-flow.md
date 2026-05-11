---
sidebar_position: 23
title: AWS VPC Flow Logs
description: Native AWS VPC Flow Logs ingestion via CloudWatch Logs with a default REJECT-only filter pattern — surfaces blocked network flows without paying to ingest the steady-state ACCEPT firehose.
---

# AWS VPC Flow Logs

The AWS VPC Flow Logs connector pulls **network-flow records** from a
configured CloudWatch Logs log group via the
`logs:FilterLogEvents` API. It defaults to surfacing only **rejected
flows** (the default filter pattern is `?REJECT`) so the alert
pipeline gets the actionable port-scan / blocked-egress signal
without drowning in steady-state ACCEPT noise.

That default is deliberate. Even a tiny VPC publishes **hundreds of
thousands of flow records per minute**, the vast majority of which
are uninteresting ACCEPTed traffic on long-lived TCP sessions. The
bundled detection content in `detections/network/` and
`detections/cloud/` only fires on rejected or unusual flows, port
scans, or specific destinations — so the REJECT-only default
matches what the rules actually consume.

Use this connector together with
[AWS GuardDuty](/docs/connectors/aws-guardduty) (which uses VPC
flow logs as one of its inputs) and
[AWS CloudTrail](/docs/connectors/aws-cloudtrail) (management-plane
events) for full AWS coverage of the network and identity planes.

## What you get

| Source | CloudWatch API | Notes |
|---|---|---|
| VPC flow records | `FilterLogEvents` | One server-side-filtered call per poll, paginated |

Events are normalized with `source: aws_vpc_flow` and
`category: network`. The parsed flow fields (`src_ip`, `dst_ip`,
`src_port`, `dst_port`, `protocol`, `action`, `aws_account_id`,
`cloud_resource` = the ENI ID) are surfaced as top-level alert
fields so detections can match without unwrapping `raw_event`. The
original message body is preserved on `raw_event.message` for v5 /
JSON layouts where the parser cannot do better than passthrough.

## Why CloudWatch Logs and not S3?

AWS lets you publish flow logs to either CloudWatch Logs or S3.

- The **CloudWatch Logs** path is the only one with a real-time,
  queryable API surface — `filter_log_events` supports a CloudWatch
  Logs filter pattern, returns events as JSON envelopes, and tracks
  a cursor we can resume from.
- The **S3** path is cheaper at petabyte scale but requires a
  separate parse / dedupe layer per object and has 5–10 minute
  publish latency.

For an alert-pipeline connector AiSOC wants the lower-latency
CloudWatch path. If you need to bulk-analyse historical flow logs
that already live in S3, run an offline batch job rather than
trying to backfill through this connector.

## Capabilities

| Capability | Backed by | Notes |
|---|---|---|
| `PULL_ALERTS` | `logs:FilterLogEvents` | Records flow into the alert pipeline once normalised |
| `PULL_LOGS` | `logs:FilterLogEvents` | True to the source — these are passive logs |

VPC Flow Logs are read-only. To **block** an offending source IP
that surfaces in a rejected-flow record, route the alert through a
playbook that uses the
[AWS Security Hub](/docs/connectors/aws-security-hub) connector's
`BLOCK_IP` capability (which mutates the security group inline) or
your own NACL-management connector.

## Prerequisites

- A **VPC Flow Log** configured to publish to **CloudWatch Logs**.
  Create it under **VPC → Your VPCs → (vpc) → Flow logs → Create
  flow log → Send to CloudWatch Logs**. Note the log group name —
  you'll need it below.
- IAM permissions:
  - `logs:FilterLogEvents` on the target log group
  - `logs:DescribeLogGroups` on the target log group (used by `Test connection`)
- One of:
  - **Static access key** (`AccessKeyId` + `SecretAccessKey`) for a
    dedicated IAM user, **or**
  - **No credentials at all** — AiSOC falls back to the **runtime IAM
    role / instance profile** of the host running the `connectors`
    service.

The runtime-IAM-role path is strongly preferred for production
deployments.

## Setup walkthrough

### 1. Enable VPC Flow Logs (one-time per VPC)

In the AWS console:

1. **VPC → Your VPCs → (target VPC) → Flow logs → Create flow log**.
2. **Filter**: choose `All` if you want to be able to switch this
   connector to pull ACCEPTs later, or `Reject` to match the
   connector's default filter pattern at the source.
3. **Maximum aggregation interval**: 1 minute (recommended for
   detection latency).
4. **Destination**: `Send to CloudWatch Logs`.
5. **Destination log group**: pick or create one (e.g.
   `/aws/vpc/flowlogs`).
6. **Log format**: leave as the default `AWS default format` for the
   v2 14-field layout, or pick `Custom format` to define a v5
   layout.

### 2. (Optional) Create a least-privilege IAM user

If you cannot use an instance role, create a dedicated IAM user with
**only** the policy below, and capture an access key for it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AiSOCVPCFlowLogsRead",
      "Effect": "Allow",
      "Action": [
        "logs:FilterLogEvents",
        "logs:DescribeLogGroups"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/vpc/flowlogs:*"
    }
  ]
}
```

Tighten the resource ARN to the specific log group ARN from step 1.

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → AWS VPC Flow Logs**.
2. Set **AWS Region** (e.g. `us-east-1`).
3. Set **CloudWatch Logs log group** to the log group from step 1
   (e.g. `/aws/vpc/flowlogs`).
4. Leave **CloudWatch Logs filter pattern** as the default
   `?REJECT` (recommended). See
   [Tuning the filter pattern](#tuning-the-filter-pattern) below.
5. Leave **Flow log version** as `v2` unless you configured a custom
   v5 layout in step 1.
6. Leave **Access Key ID** and **Secret Access Key** **blank** to
   use the runtime IAM role. Otherwise paste the static credentials
   from step 2.
7. **Test connection** — AiSOC calls `DescribeLogGroups` to verify
   auth and that the log group exists.
8. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll calls `FilterLogEvents` with `startTime = now - 300s`
  and `endTime = now`, applying the configured filter pattern
  server-side.
- Pagination: 1,000 events per page (the API max), capped at
  **5,000 events per poll** to bound memory and prevent a single
  misconfigured filter from wedging the scheduler.
- If the log group does not exist or auth fails, the poll logs the
  error and returns an empty batch instead of raising — the
  scheduler stays healthy and the next poll retries.

## Severity mapping

VPC flow records do not carry intrinsic severity, so AiSOC labels
each record by action / log status:

| Condition | Examples | AiSOC severity |
|---|---|---|
| `action = REJECT` | A blocked flow — the loud signal we publish this connector for | `medium` |
| `action = ACCEPT` | An allowed flow — only ingested if the operator overrode the default filter | `low` |
| `log_status` ∈ `{NODATA, SKIPDATA}` | Collection gap reported by AWS — useful for the pipeline-health channel | `info` |
| Anything else | Unparsed / v5-passthrough records | `low` |

## Tuning the filter pattern

The `filter_pattern` field is a CloudWatch Logs filter expression
applied server-side, before AiSOC pays to fetch the record. Three
common modes:

- **`?REJECT`** (default) — surfaces only blocked flows. The right
  default for ~95% of operators.
- **Empty string** — disables the server-side filter and ingests
  every flow record. **High volume warning** — only use this in lab
  / staging accounts or when you have downstream rate-limiting in
  place. A single production VPC on `""` can generate tens of
  millions of records per day.
- **Custom expression** — anything CloudWatch Logs filter syntax
  accepts. Examples:
  - `?REJECT ?ERROR` — reject + downstream service errors
  - `[version, account, eni, src!="10.*", dst, ...]` — fixed-column
    pattern matching against parsed fields (v2 only)

See the
[CloudWatch Logs filter syntax docs](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html)
for the full grammar.

## Flow log format support

| Format | Parsed natively | Notes |
|---|---|---|
| **v2 (default)** | Yes — 14 space-separated fields | All top-level fields populated. Parser falls through silently on the optional v2 header line. |
| **v5 (custom layout, JSON)** | Yes via JSON parse | Top-level fields populated when the JSON keys match the v2 names; otherwise everything passes through on `raw_event`. |
| **v5 (custom layout, fixed columns)** | No | The full message is preserved on `raw_event.message`. Detection rules can still pattern-match on the raw line. |

The connector inspects `raw_event.record_format` so playbooks /
detections can branch on whether the record was parsed cleanly.

## Troubleshooting

**`Test connection` returns "log group … not found"** — the IAM
identity can `DescribeLogGroups` but the requested group either
does not exist or lives in a different region. Check the AWS
console under **CloudWatch → Log groups** in the region configured
on the connector.

**`AccessDenied` on `FilterLogEvents`** — the IAM user / role is
missing `logs:FilterLogEvents` on the specific log-group ARN.
Reattach the policy from step 2 with the correct ARN.

**Volume too high even with `?REJECT`** — your VPC is genuinely
seeing a lot of denied traffic (often a sign of misconfigured
security groups or active scanning). Tighten the filter pattern,
add a destination-IP exclusion, or downgrade the polling interval
to spread the load. The connector caps at 5,000 records per poll
regardless.

**Records arrive several minutes late** — CloudWatch Logs is
**eventually consistent**, and VPC Flow Logs are aggregated for up
to 1–10 minutes (depending on the **Maximum aggregation interval**
setting on the flow log itself) before publishing. Set the
aggregation to 1 minute for the lowest detection latency.

**`boto3 is required` at runtime** — boto3 is bundled with the
`services/connectors` Docker image. If you are running the service
outside Docker, install it: `pip install boto3`.

## Related

- [AWS GuardDuty](/docs/connectors/aws-guardduty) — ML-based
  threat detection layered on top of these flow logs (plus
  CloudTrail and DNS).
- [AWS CloudTrail](/docs/connectors/aws-cloudtrail) — management-plane
  audit events to cross-reference against suspicious flow records.
- [AWS Security Hub](/docs/connectors/aws-security-hub) —
  multi-source finding aggregator with `BLOCK_IP` / `ALLOW_IP`
  containment.
