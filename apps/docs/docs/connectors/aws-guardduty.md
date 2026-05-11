---
sidebar_position: 21
title: AWS GuardDuty
description: Native AWS GuardDuty findings — VPC flow, DNS, CloudTrail, EKS, S3, RDS, and Lambda threat detection without going through Security Hub.
---

# AWS GuardDuty

The AWS GuardDuty connector pulls **findings directly from the GuardDuty
API** — no Security Hub aggregation in between. This gives AiSOC the
**richest possible per-finding context** (network connection action,
runtime details, EKS audit, S3 access patterns) in exactly the shape
AWS publishes them.

Use this connector when you want first-class GuardDuty alerts. Use the
[AWS Security Hub](/docs/connectors/aws-security-hub) connector instead
(or in addition) when you want **one connector for many providers**.

## What you get

| Source | GuardDuty API | Notes |
|---|---|---|
| Active findings | `ListFindings` + `GetFindings` | All detector types — VPC, DNS, CloudTrail, EKS, S3, RDS, Lambda |

Events are normalized with `source: aws_guardduty` and the original
GuardDuty finding is preserved on `raw_event` for downstream playbooks
and detection content.

## Capabilities

| Capability | Backed by | Notes |
|---|---|---|
| `PULL_ALERTS` | `guardduty:GetFindings` | Default — every connector instance |

GuardDuty is read-only in this release. To **block** a malicious IP the
connector surfaces, route the alert through a playbook that uses the
[AWS Security Hub](/docs/connectors/aws-security-hub) connector's
`BLOCK_IP` capability or any other network-control connector.

## Prerequisites

- AWS GuardDuty **enabled** in the region you want to monitor (one
  connector instance per region).
- IAM permissions:
  - `guardduty:ListDetectors`
  - `guardduty:ListFindings`
  - `guardduty:GetFindings`
  - `sts:AssumeRole` (only if you target a role in another account)
- One of:
  - **Static access key** (`AccessKeyId` + `SecretAccessKey`) for a dedicated
    IAM user, **or**
  - **No credentials at all** — AiSOC falls back to the **runtime IAM role
    / instance profile** of the host running the `connectors` service.

The runtime-IAM-role path is strongly preferred for production deployments.

## Setup walkthrough

### 1. Enable GuardDuty (if not already)

In the AWS console, **GuardDuty → Get Started → Enable GuardDuty** in
the region you want to monitor. GuardDuty creates a single detector per
region. Repeat per region; each region needs its own AiSOC connector
instance.

### 2. (Optional) Create a least-privilege IAM user

If you cannot use an instance role, create a dedicated IAM user with
**only** the policy below, and capture an access key for it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AiSOCGuardDutyRead",
      "Effect": "Allow",
      "Action": [
        "guardduty:ListDetectors",
        "guardduty:ListFindings",
        "guardduty:GetFindings"
      ],
      "Resource": "*"
    }
  ]
}
```

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → AWS GuardDuty**.
2. Set **AWS Region** (e.g. `us-east-1`).
3. Leave **Access Key ID** and **Secret Access Key** **blank** to use the
   runtime IAM role. Otherwise paste the static credentials from step 2.
4. **Test connection** — AiSOC calls `ListDetectors` and confirms the
   call returns 200. The response also reports how many detectors were
   discovered (typically `1` per region).
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll:
  1. `ListDetectors` to discover every detector in the region.
  2. `ListFindings` per detector with criteria
     `updatedAt >= (now - 300s)` and `service.archived == false`, capped
     at **500 IDs per detector** to bound memory.
  3. `GetFindings` in batches of **50 IDs** (the GuardDuty hard limit).
- Archived findings are skipped — if you re-archive in the GuardDuty
  console, AiSOC stops surfacing them on the next poll.

## Severity mapping

GuardDuty publishes severity as a **float in the range 1.0–8.9**. AiSOC's
canonical ladder is `info | low | medium | high`. We bucket using AWS's
own published thresholds:

| GuardDuty score | AiSOC severity |
|---|---|
| `< 1.0` (rare — sample / test findings) | `info` |
| `1.0 – 3.9` | `low` |
| `4.0 – 6.9` | `medium` |
| `7.0 – 8.9` | `high` |

The original float severity is preserved on `raw_event.Severity`.

## Multi-account / multi-region

GuardDuty can be operated in a **delegated administrator** account that
aggregates member-account findings into a single detector. AiSOC supports
both topologies:

- **Aggregator account** — point one connector at the delegated admin's
  region and credentials. You'll see member-account findings via the
  `accountId` field on each finding.
- **Per-account** — one connector instance per account × region pair, each
  with its own IAM credentials.

For multi-region without a delegated admin, add **one connector per
region** (each region runs an independent GuardDuty detector).

## Troubleshooting

**`AccessDenied` on `ListDetectors`** — the IAM user / role is missing
`guardduty:ListDetectors`. Reattach the policy from step 2.

**`Test connection` succeeds with `detector_count: 0`** — GuardDuty is
not enabled in this region. Enable it in the AWS console; the next poll
will pick up the new detector automatically.

**No findings appear in AiSOC even though GuardDuty shows them** — by
default AiSOC filters out **archived** findings. Verify the findings
in question are still in the `unarchived` state.

**`boto3 is required` at runtime** — boto3 is bundled with the
`services/connectors` Docker image. If you are running the service
outside Docker, install it: `pip install boto3`.

## Related

- [AWS Security Hub](/docs/connectors/aws-security-hub) — aggregator
  alternative; covers GuardDuty + Inspector + Macie + third-party
  finding providers in one connector, plus inline `BLOCK_IP` /
  `ALLOW_IP` containment.
- [AWS CloudTrail](/docs/connectors/aws-cloudtrail) — high-signal API
  events for AWS-native detections.
- [AWS VPC Flow Logs](/docs/connectors/aws-vpc-flow) — raw network
  telemetry that GuardDuty itself analyses.
