# Data handling by deployment mode

What leaves your perimeter, what is stored, and for how long — answered per
mode, because the answers genuinely differ and a single answer for all of them
would be wrong three times out of four.

[`docs/trust/data-flows.md`](../trust/data-flows.md) is the short version of
the egress question. This page is the whole data lifecycle.

## The four modes

| Mode | How it is started | Who runs the infrastructure | Who runs the model |
|---|---|---|---|
| **Self-hosted, bundled model** | `make up` | You | You — `ollama` in your own stack |
| **Self-hosted, hosted model** | `make up`, then configure a provider in the console | You | A third party you choose and contract with |
| **Air-gapped** | `infra/compose/docker-compose.airgap.yml` | You | You, with no route off the host |
| **Managed** | Operated for you | The maintainers | See [sub-processors](subprocessors.md) |

The default is the first. `make up` needs no account, no key and no GPU: it
ships `llama3.2:3b-instruct-q4_K_M` and triage produces a real verdict from a
real model with real token counts. That matters for this page because **the
default configuration makes no model call off your infrastructure at all.**

## Egress, per mode

### What never leaves, in every mode

- **No telemetry to the AiSOC project.** There is no phone-home and no
  "model improvement" callback. This is enforced, not asserted:
  `scripts/check_default_egress.py` reads every service's declared settings
  defaults and fails on a public host that no air-gap guard covers — 25 URL
  defaults across 11 settings modules, 23 private and 2 allow-listed with a
  reason. `tests/test_no_default_egress.py` puts a socket guard in front of
  each service's import and ASGI startup, because the static gate cannot see a
  URL built at run time.
- **Your stores.** Postgres, Kafka, Redis, and the optional ClickHouse, Neo4j
  and Qdrant are containers in your own stack. Nothing replicates them
  outward.

A third control covers what the first two structurally cannot: the static gate
is blind to run-time URLs and the socket guard is blind to paths startup does
not reach. [`container-egress.yml`](../../.github/workflows/container-egress.yml)
starts images built from the commit under test on a Docker network created
`--internal`, with a DNS sinkhole as their only resolver, and classifies every
name they ask for. It carries a canary — a container wired identically that
*must* be seen by the sinkhole — because zero observations is what a correct
run and a blind probe both look like.

### Self-hosted with the bundled model

Nothing leaves for triage. The model runs in the `ollama` container beside
everything else.

Two things still leave if you enable them, both on purpose and both yours to
turn off:

- **Connector polling** reaches the vendors you connected. That is the
  product.
- **Threat-intel feeds** you enable. The one that is on by default is the
  CISA Known Exploited Vulnerabilities catalog — a public, authoritative feed
  that needs no API key and receives nothing from you but the request.

### Self-hosted with a hosted model

Evidence reaches the provider you configured, **pseudonymized**.

This is the paragraph that was wrong for a long time, so it is worth being
exact about what changed. The reversible pseudonymizer
([`services/agents/app/privacy/redactor.py`](../../services/agents/app/privacy/redactor.py))
existed and was unit-tested, and **no LLM call site invoked it** — so the
documentation described a planned control as a shipped one. It is now applied
at the contract layer
([`services/agents/app/llm/contract.py`](../../services/agents/app/llm/contract.py)
calls `egress_privacy.open_session`), which is the one place all sixteen agent
call sites already pass through.

| What is replaced | With |
|---|---|
| Internal IPs, internal hostnames | `IP_3`, `HOST_2` |
| Usernames, email addresses | `USER_1` |
| File paths, secrets | opaque per-run tokens |
| **Public threat indicators** | **nothing — preserved deliberately**, or the agent cannot reason about them |

Tokens are per-run and in-memory. The model reasons over tokens; the ledger
and console re-hydrate real values locally.

The gate is [`test_egress_pseudonymization.py`](../../services/agents/tests/test_egress_pseudonymization.py),
and it is worth noting *how* it is written: it drives `safe_ainvoke` and
inspects what a fake provider actually received, rather than calling the
redactor directly. Testing the path rather than the function immediately found
a real gap the unit test could not — a bare username in prose
(`running as priya.raghavan`) went out in the clear, because usernames were
only redacted in the `DOMAIN\user` form or under a user-ish key.

**You can turn it off.** If you do, raw evidence reaches the provider. Use
that only under a signed zero-retention agreement.

### Air-gapped

`infra/compose/docker-compose.airgap.yml` ships the local model and expects no
route off the host. This is the only mode in which "no evidence leaves" is
unconditionally true, and it is the mode the container-egress job exercises.

### Managed

The maintainers operate the infrastructure. See
[sub-processors](subprocessors.md), which says plainly what this repository can
and cannot establish about that arrangement.

## What is stored, and where

| Data | Store | Notes |
|---|---|---|
| Alerts, cases, users, tenants | Postgres | Row-level security plus query-layer predicates |
| Connector credentials | Postgres, as ciphertext | Never in the clear; see [the vault](platform-threat-model.md) |
| Audit log | Postgres | Hash-chained, and a `BEFORE UPDATE OR DELETE` trigger ([migration 004](../../services/api/migrations/004_audit_log.sql)) refuses both |
| Investigation Ledger | Postgres | Every agent step, with the prompt and response |
| Raw events | ClickHouse | **Full profile only.** Absent on a default install |
| Entity graph | Neo4j | Full profile only |
| Embeddings | Qdrant | Full profile only |
| Cache, queues, rate limits | Redis | Tenant-prefixed keys |
| In-flight events | Kafka | Tenant in the envelope; retention is your broker's setting |

## Encryption

| | State | Where |
|---|---|---|
| Connector credentials | **Fernet AES-128-CBC + HMAC-SHA256** by default (`vault:v1:`), or envelope encryption with a KMS-held key (`vault:v2:`) | [`credential_vault.py`](../../services/api/app/security/credential_vault.py), [`envelope_cipher.py`](../../services/api/app/security/envelope_cipher.py) |
| Backups | **AES-256-GCM**, chunked with a per-chunk nonce and additional authenticated data binding the chunk index and the final flag, so a reordered or truncated archive is refused | [`scripts/backup_crypt.py`](../../scripts/backup_crypt.py) |
| Everything else at rest | Your disk encryption | A property of your infrastructure, not of this software |
| In transit, browser to edge | Your TLS terminator | Not shipped; the compose stack serves plain HTTP and expects a reverse proxy |
| In transit, service to service | **Plaintext inside the container network** on the default compose stack | Stated rather than implied. Deployments needing mutual TLS between services should supply it at the platform layer |

The backup row is specific because it used to be false: the script gzipped and
uploaded while the documentation claimed AES-256-GCM. Two things make the claim
real now. `openssl enc` **refuses AEAD ciphers**, which is why the encryption
is a Python script on `cryptography` rather than a shell one-liner. And
`Backup → destroy → restore (Postgres via S3)` is a **required** status check
that seeds real data, encrypts, destroys, restores, measures recovery time and
proves a bit-flipped archive is refused.

## Retention and deletion

- **Per-tenant retention** is implemented in
  [`services/api/app/services/retention.py`](../../services/api/app/services/retention.py).
  The purge worker ships **default off and dry-run first**, deliberately: a
  deletion job that starts deleting on upgrade is a worse failure than one
  that has to be switched on.
- **Tenant deletion** is
  [`services/api/app/services/tenant_deletion.py`](../../services/api/app/services/tenant_deletion.py).
  It exists because 14 tenant-scoped tables had no foreign-key cascade, so
  deleting a tenant orphaned institutional memory and compliance evidence
  rather than removing it.
- **Kafka retention** is your broker's configuration, not ours.
- **The audit log is append-only by design**, which is in tension with a
  deletion request and is the right tension to have. The hash chain is what
  makes the log evidence; a log that can be edited to satisfy a request is not
  one.

## Subject-access and portability

There is an audit export surface
([`services/api/app/services/audit_export.py`](../../services/api/app/services/audit_export.py))
producing CSV and HTML bundles, and a report builder for case material.

What does **not** exist is a dedicated data-subject-request endpoint.
[ADR-0002](../decisions/0002-compliance-claims.md) records the intent and its
open question; no such route is in the tree today, and
[the questionnaire](questionnaire.md#privacy-and-data-subject-rights) lists it
as a gap rather than describing it as a feature.
