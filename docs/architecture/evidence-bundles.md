# Evidence bundles

An auditor, a regulator or a customer's own security team asks the same
three things about an automated decision: *what did it decide, on what
evidence, and can I check that nobody edited the answer afterwards?*

The [Investigation Ledger](README.md) already holds the answer. A bundle
is that answer made portable and tamper-evident, exported from
`GET /api/v1/investigations/{run_id}/bundle` or the **⤓ Evidence bundle**
control on the investigation timeline.

Implementation: [`services/api/app/services/evidence_bundle.py`](../../services/api/app/services/evidence_bundle.py).

## Three properties, each a decision

### Byte-for-byte replayable

Two exports of the same run produce identical bytes. That is what lets
somebody who does not trust the exporter diff a bundle, re-hash it and
check the signature themselves.

It rules out everything that makes JSON non-deterministic:

- keys are sorted and separators fixed;
- timestamps are the ledger's own, never `now()`;
- nothing records the host that produced it;
- events are sorted by sequence, so a ledger read that returns rows in a
  different order cannot change the digest — otherwise the signature
  becomes a property of the query plan.

The route serves the bundle as a **download**, not as a JSON body,
because a client that re-serialised a parsed body would change the bytes
and the signature would stop matching for a reason nobody could see.

`verify_bundle()` recomputes both the digest and the signature from the
payload rather than comparing the two values already in the file — which
would pass for anyone who edited the payload and the digest together.

### Prompts travel as hashes, never as text

A prompt carries the alert, and an alert carries your hostnames, your
usernames and your addresses. A bundle is the artefact most likely to
leave your control, so the one thing it must not do is carry your estate
in clear text.

The digest still proves *which* prompt ran: re-hash the prompt and
compare. A step with no prompt gains no hash field at all, because a hash
of the empty string would quietly merge "there was no prompt" with "the
prompt hashed to something".

### Absent is not zero

A run with no cost telemetry exports `total_cost_usd: null`, not `0.0`,
and a `cost_provenance` field saying which it was. A zero says the run
was free; null says nobody measured. This repository has published the
first while meaning the second before.

## The OCSF mapping, and the version it declares

The bundle declares **OCSF 1.9.0**. That is deliberate, and it differs
from the 1.1.0 the ingest spine emits.

Each object was checked against the published schema before being used:

| Object / profile | 1.1.0 | 1.8.0 | 1.9.0 |
|---|---|---|---|
| `ai_agent` | absent | absent | present |
| `ai_operation` | absent | present | present |
| `record_integrity` | absent | — | present |

The ingest spine stays at 1.1.0 because that is the contract its
normalizer has with connectors, and nothing here changes it. But a
bundle is a different artefact with a different audience, and 1.9.0 is
the first version containing every object it uses. **Declaring 1.1.0
while emitting an `ai_agent` would be a false claim about a public
standard**, which is worse than not mapping at all.

Field names come from the schema rather than from invention: `ai_model`
nested inside `ai_agent`; `record_integrity` carrying an
`attestation_list` whose entries have `fingerprint` and `signatures`.

## What the signature is worth

HMAC-SHA256 over the canonical payload, keyed from the deployment's own
secret. The bundle says in its own `algorithm_note` that this is
**tamper-evidence, not non-repudiation**: anyone holding the signing key
can produce a valid signature, so it proves the bundle was not altered
after export, not that AiSOC and only AiSOC produced it.

An auditor who assumes a public-key signature from the word "signed" has
been misled by us rather than by the format, which is why the
qualification travels inside every bundle instead of living only here.

## Verifying one

```python
from app.services.evidence_bundle import verify_bundle

payload = verify_bundle(json.loads(raw_bytes), signing_key=key)
```

It raises `BundleVerificationError` with the specific reason — digest
mismatch, signature mismatch, or no payload — rather than returning
`False`.

## Tests

- [`services/api/tests/test_evidence_bundle.py`](../../services/api/tests/test_evidence_bundle.py)
  — the format: determinism, tampering, prompt hashing, the OCSF block.
- [`tests/isolation/test_evidence_bundle_live.py`](../../tests/isolation/test_evidence_bundle_live.py)
  — the route against real Postgres. UUIDs, timezone-aware datetimes,
  `Numeric` and `JSONB` all have reprs JSON cannot serialise, so a test
  that hands in dicts never finds out which way that goes.

Tenant scoping on the export was measured in both directions and the
result is worth knowing: removing the explicit `tenant_id` predicate
leaves the cross-tenant test **passing**, because the session runs as the
DML-only role and row-level security refuses the row anyway. Only
removing the predicate *and* connecting as the schema owner makes it
fail. The belt and braces are real — and a reader should not conclude
from a green run that the predicate alone is doing the work.
