---
sidebar_position: 17
title: AWS Security Hub
description: AWS Security Hub findings (GuardDuty, Inspector, Macie, third-party) with optional inline IP block / allow via EC2 security groups.
---

# AWS Security Hub

The AWS Security Hub connector pulls **findings from AWS Security Hub**
into AiSOC and unlocks **inline containment** by writing ingress / egress
rules onto an EC2 security group.

Security Hub aggregates findings from native AWS services
(**GuardDuty**, **Inspector**, **Macie**, **IAM Access Analyzer**,
**Config**) and from any **third-party finding provider** that publishes
to ASFF. One connector instance covers them all.

## What you get

| Source | Security Hub API | Notes |
|---|---|---|
| Active findings | `GetFindings` with `WorkflowStatus = NEW \| NOTIFIED` | All providers, deduped by Security Hub |

Events are normalized with `source: aws_security_hub` and the original
ASFF finding is preserved on `raw_event` for downstream playbooks.

## Capabilities

| Capability | Backed by | Notes |
|---|---|---|
| `PULL_ALERTS` | `securityhub:GetFindings` | Default — every connector instance |
| `BLOCK_IP` | `ec2:AuthorizeSecurityGroupIngress` via `services/actions/app/clients/aws_security_groups.py` | Requires playbook step that supplies an `aws_security_group_id` |
| `ALLOW_IP` | `ec2:RevokeSecurityGroupIngress` | Same playbook step, opposite direction |

The Security Hub connector itself only authenticates the **read** path;
the Block / Allow actions reuse the same credentials at action-execution
time via the actions service.

## Prerequisites

- AWS Security Hub **enabled** in at least one region.
- IAM permissions:
  - `securityhub:GetFindings` (required for `PULL_ALERTS`)
  - `ec2:AuthorizeSecurityGroupIngress` and
    `ec2:RevokeSecurityGroupIngress` (only if you want `BLOCK_IP` / `ALLOW_IP`)
  - `sts:AssumeRole` (only if you target a role in another account)
- One of:
  - **Static access key** (`AccessKeyId` + `SecretAccessKey`) for a dedicated
    IAM user, **or**
  - **No credentials at all** — AiSOC falls back to the **runtime IAM role
    / instance profile** of the host running the `connectors` service.

The runtime-IAM-role path is strongly preferred for production deployments.

## Setup walkthrough

### 1. Enable Security Hub (if not already)

In the AWS console, **Security Hub → Enable Security Hub** in the region
you want to monitor. Repeat per region; each region needs its own connector
instance.

### 2. (Optional) Create a least-privilege IAM user

If you cannot use an instance role, create a dedicated IAM user with
**only** the policy below, and capture an access key for it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AiSOCSecurityHubRead",
      "Effect": "Allow",
      "Action": ["securityhub:GetFindings"],
      "Resource": "*"
    },
    {
      "Sid": "AiSOCInlineContainment",
      "Effect": "Allow",
      "Action": [
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    }
  ]
}
```

Drop the `AiSOCInlineContainment` statement if you only want read.

### 3. Add the connector in AiSOC

1. **Connectors → Add connector → AWS Security Hub**.
2. Set **AWS Region** (e.g. `us-east-1`).
3. Leave **Access Key ID** and **Secret Access Key** **blank** to use the
   runtime IAM role. Otherwise paste the static credentials from step 2.
4. **Test connection** — AiSOC runs `GetFindings(MaxResults=1)` and
   confirms the call returns 200.
5. **Save**.

## Polling details

- Default interval: **300 seconds**.
- Each poll calls `GetFindings` with `WorkflowStatus IN [NEW, NOTIFIED]`
  to skip findings already triaged in Security Hub.
- Pagination is currently **single-page (100 findings)** — the most recent
  100 NEW/NOTIFIED findings per poll. Fine-grained windowing is on the
  v7.2 roadmap.

## Severity mapping

Security Hub uses the ASFF 4-tier ladder (`CRITICAL`, `HIGH`, `MEDIUM`,
`LOW`). AiSOC maps these directly:

| ASFF label | AiSOC severity |
|---|---|
| `CRITICAL` | `high` |
| `HIGH` | `high` |
| `MEDIUM` | `medium` |
| `LOW` | `low` |
| `INFORMATIONAL` (unmapped) | `info` |

The original ASFF severity is preserved on `raw_event.Severity.Label`.

## Containment via security groups

When an AiSOC playbook calls `BLOCK_IP` against an alert that came from
this connector, the actions service authorizes a **deny ingress rule** on
the configured security group:

- Default port range: `0–65535` (all ports), TCP only — override per-action
  via `aws_protocol`, `aws_from_port`, `aws_to_port`.
- Cross-account: pass `aws_assume_role_arn` and the actions service will
  STS:AssumeRole into the target account before authorizing.
- `ALLOW_IP` reverses the same rule via `RevokeSecurityGroupIngress`.

See [`services/actions/app/clients/aws_security_groups.py`](https://github.com/beenuar/AiSOC/tree/main/services/actions/app/clients/aws_security_groups.py)
for the full client.

## Troubleshooting

**`AccessDenied` on `GetFindings`** — the IAM user / role is missing
`securityhub:GetFindings`. Reattach the policy from step 2.

**`ResourceNotFoundException`** — Security Hub is not enabled in the
configured region. Enable it in the AWS console.

**`boto3 is required` at runtime** — boto3 is bundled with the
`services/connectors` Docker image. If you are running the service
outside Docker, install it: `pip install boto3`.

**`BLOCK_IP` returns success but the IP keeps connecting** — the playbook
step did not supply an `aws_security_group_id`, or the host is not
attached to that security group. Verify both.

## Related

- [AWS GuardDuty](/docs/connectors/aws-guardduty) — direct GuardDuty
  ingestion (skips Security Hub aggregation).
- [AWS CloudTrail](/docs/connectors/aws-cloudtrail) — high-signal API
  events for AWS-native detections.
- [Wiz](/docs/connectors/wiz) — multi-cloud CNAPP alternative.
