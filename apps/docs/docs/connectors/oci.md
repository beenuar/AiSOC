---
sidebar_position: 80
title: Oracle Cloud Infrastructure (OCI)
description: OCI Audit service events into AiSOC via the OCI Audit ListEvents API.
---

# Oracle Cloud Infrastructure (OCI)

The OCI connector polls the **OCI Audit service** (`ListEvents` in the
configured compartment) and emits one AiSOC alert per audit event
(IAM identity changes, security list / NSG edits, instance state
changes, IAM policy edits).

## What you get

| Source | OCI endpoint | Notes |
|---|---|---|
| Audit events | `GET /20190901/auditEvents` (audit service) | All compartment-scoped audit rows |

Events are normalised with `source: oci` and the original OCI envelope
is preserved on `raw_event` so detection rules can match on
`eventName`, `compartmentId`, or `source` (IAM, VirtualNetwork,
ComputeApi, …).

## Prerequisites

- An **OCI tenancy** with at least one **IAM user** authorised to
  read the audit service (the bundled `AuditAdmin` or `Administrator`
  policy works; least-privilege is a custom policy that grants
  `inspect audit-events` on the tenancy).
- An **API signing key**:
  - A 2048-bit RSA key pair (`openssl genrsa -out aisoc.pem 2048`).
  - The matching `.pub` uploaded to the IAM user's
    *API Keys* tab in the OCI console. The console reports a
    47-character **fingerprint** — record it.
- The **tenancy OCID**, **user OCID**, and **compartment OCID** to
  scope ingestion to.
- The **region identifier** (e.g. `us-ashburn-1`, `eu-frankfurt-1`).

## Setup walkthrough

1. In the OCI Console, **Identity → Users → (the AiSOC service user) →
   API Keys → Add API Key → Paste public key**.
2. Copy the **Fingerprint** the console displays — you'll need it
   exactly.
3. Note your **Tenancy OCID** (under your profile → Tenancy details)
   and your **User OCID**.
4. Choose a **Compartment OCID** to scope ingestion to (typically your
   root compartment; sub-compartments scope ingestion narrower).
5. In AiSOC: **Connectors → Add connector → Oracle Cloud Infrastructure**.
6. Fill in: Tenancy OCID, User OCID, Compartment OCID, Fingerprint,
   the **private key** PEM, and the **Region**.
7. Click **Test connection**. AiSOC issues a signed `GET /auditEvents?
   compartmentId=...&startTime=...&endTime=...&limit=1` and confirms a
   `200`.
8. Save.

## Severity mapping

The connector escalates OCI audit events by source + eventName:

| AiSOC severity | OCI event |
|---|---|
| `high`   | `iam.*.DeleteUser`, `iam.*.UpdateUserCapabilities`, `iam.*.CreatePolicy`, `network.*.UpdateSecurityList`, `network.*.UpdateNetworkSecurityGroup` |
| `medium` | `compute.*.LaunchInstance`, `compute.*.TerminateInstance`, `objectstorage.*.PutObject` on policy-marked buckets |
| `low`    | `iam.*.GetUser`, read-only `Get*` / `List*` calls |
| `info`   | everything else (read-only enumeration) |

## Capabilities

- `pull_audit` — passive polling of audit events.
- `read_audit_trail` — surface the API call lineage during investigation.
- `pivot_user` — given an OCI user OCID, return their recent audit
  activity.

## Polling details

- Poll interval: every 5 minutes by default (`since_seconds=300`).
- Pagination: opaque `opc-next-page` header — the connector follows up
  to 25 pages per poll cycle.
- The signature is computed via Oracle's request-signing v1 spec
  (HTTP Signatures over `(request-target)`, `host`, `date`, `x-content-sha256`).
- The connector swallows network and HTTP errors and returns `[]`
  rather than raising — the scheduler logs and retries on the next
  cycle.

## Troubleshooting

- **`401 NotAuthenticated`** — the most common failure. Usually means
  the **fingerprint** does not match the uploaded public key, or the
  private key PEM is missing a header / footer. The error body almost
  always cites which fact OCI disliked.
- **`401 NotAuthorizedOrNotFound`** — the IAM user lacks
  `inspect audit-events` on the target compartment. Attach an OCI
  policy granting it.
- **No events** — confirm there is recent activity in the compartment.
  Audit events for a brand-new tenancy are sparse for the first few
  hours.
