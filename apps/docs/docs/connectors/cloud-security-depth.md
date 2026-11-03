---
sidebar_position: 99
title: Cloud security connector depth
description: What each registered CNAPP connector reads, what its vendor's API also offers, and which of those gaps are open.
---

# Cloud security connector depth

AiSOC registers five cloud-security connectors. They differ a great deal in
how much of their vendor's API they actually read, and until this page
existed there was no way to tell which — every one of them looked equally
complete from the connector list, because the list shows a name and a
category and not a surface.

This is the depth check, recorded per connector: what the connector reads
today, what the vendor's API also offers, and whether the difference is a gap
worth closing or a deliberate decision. It is re-derived against the tree
rather than maintained by hand; where a row says a surface is unread, that is
a statement about this repository and not about the vendor.

## Where a finding goes, and why they are not all alerts

Three destinations, and which one a finding class lands in is the whole
design:

| Destination | What belongs there | Why |
|---|---|---|
| **The alert queue** | Findings the vendor has already correlated and decided are worth raising | An issue is the vendor's own judgement that something needs attention |
| **The vulnerability inventory** (`asset_vulnerabilities`) | Per-asset CVE state | It has a patch window, not a triage queue; the governed promotion sweep is the only path from there to an alert |
| **Cloud-posture context** (`posture_findings`) | Misconfigurations, exposed secrets, runtime detections | They describe the state a resource was already in. A verdict reads them when an alert touches that resource |

A CNAPP's standing backlog of misconfigurations is routinely tens of
thousands of findings. Pushing it into an analyst queue is the noise a CNAPP
exists to triage. Pushing it into a store a verdict can query turns it into
the thing it is actually good for: knowing that the bucket this anonymous
read just hit was already publicly readable three weeks ago.

## Per-connector depth

### Wiz

| Surface | Vendor query | Read today | Destination |
|---|---|---|---|
| Issues | `issues` | yes | Alerts |
| Vulnerability findings | `vulnerabilityFindings` | yes, opt-in | Vulnerability inventory |
| Configuration findings | `configurationFindings` | yes, opt-in | Posture context |
| Runtime detections | `detections` | yes, opt-in | Posture context |
| Audit log | `auditLogEntries` | **no** | — |
| Secrets | *no public query* | no — refused | — |

Two notes worth keeping.

**The runtime read must name both detection types explicitly.** Wiz applies
a default type filter of `GENERATED_THREAT` the moment any `filterBy` is
sent, which silently drops `MATCH_ONLY` detections: rule matches that did not
raise a threat issue, and exactly the weak signals this read exists to
supply. The connector names both, and a test asserts it on the *request*,
because no assertion on the response can see the difference — a tenant with
the filter missing still gets rows, just the wrong subset.

**Secrets are refused rather than guessed.** Wiz detects exposed secrets, but
no public reference documents a top-level secrets query the way it documents
the three above. Writing one from the product's marketing surface would be
inventing an endpoint. Secrets reach AiSOC as `issues` where Wiz raises them
as such.

### Orca

| Surface | Vendor endpoint | Read today | Destination |
|---|---|---|---|
| Alerts across every surface | `GET /api/alerts` | yes | Alerts |
| Per-asset inventory | `/api/assets` | **no** | — |
| Compliance frameworks | `/api/compliance` | **no** | — |

Orca unifies workload, container, configuration, identity and data-risk
findings onto one `/api/alerts` feed, so one read already covers the surfaces
that need four separate queries at Wiz. The depth gap is narrower here than
the row count suggests: what is missing is inventory and compliance posture,
not finding classes.

### Prisma Cloud

| Surface | Vendor endpoint | Read today | Destination |
|---|---|---|---|
| Aggregated alerts (CSPM, CWPP, CIEM, DSPM) | `POST /alert/v1/alert` | yes | Alerts |
| Compute runtime audits | `/api/v1/audits/*` on the Compute console | **no** | — |
| Vulnerability inventory | `/api/v1/images`, `/api/v1/hosts` | **no** | — |

The connector already accepts a separate Compute console URL and does not yet
use it for the Compute-only surfaces, which is the clearest next step for
this one.

### Lacework

| Surface | Vendor endpoint | Read today | Destination |
|---|---|---|---|
| Alerts | `GET /api/v2/Alerts` | yes | Alerts |
| Compliance evaluations | `POST /api/v2/Configs/ComplianceEvaluations/search` | yes | Alerts |
| Host and container vulnerabilities | `/api/v2/Vulnerabilities/Hosts`, `/Containers` | **no** | — |

Lacework is the only one besides Wiz that already reads a second surface. Its
compliance evaluations currently arrive as alerts; posture context is the
better destination for them and is the open item here.

### Sysdig

| Surface | Vendor endpoint | Read today | Destination |
|---|---|---|---|
| Runtime security events | `GET /api/v1/secureEvents` | yes | Alerts |
| Posture / compliance results | `/api/cspm/v1/compliance/*` | **no** | — |
| Vulnerability scan results | `/api/scanning/*` | **no** | — |

Sysdig's shipped read is runtime detections, which it raises as alerts. That
is defensible for a runtime tool — a Falco rule firing is a moment, not a
state — and is left as it is.

## Open gaps, stated plainly

| Gap | Connector | Status |
|---|---|---|
| Compliance evaluations arrive as alerts rather than posture context | Lacework | open |
| Compute-console surfaces unread despite the URL being collected | Prisma Cloud | open |
| Posture and vulnerability surfaces unread | Sysdig | open |
| Asset inventory and compliance unread | Orca | open |
| Audit log unread | Wiz | open |
| Secrets | Wiz | refused — no public query exists |

None of these is blocked on code. Each is blocked on the same thing: a
recorded payload from a real tenant of that vendor, so the read can be built
against a mock that answers the shape the vendor actually returns rather than
the shape the documentation implies. The Wiz reads above were built because
two independently maintained, shipped third-party integrations drive the same
queries, which is a corroborating reference the other four do not have.

## Related

- [Wiz](/docs/connectors/wiz)
- [Orca](/docs/connectors/orca)
- [Prisma Cloud](/docs/connectors/prisma-cloud)
- [Lacework](/docs/connectors/lacework)
- [Sysdig](/docs/connectors/sysdig)
