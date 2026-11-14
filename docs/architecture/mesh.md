# Federated Threat Intel Mesh — threat model & design (v8 P1)

The mesh is opt-in gossip between self-hosted AiSOC instances via a lightweight,
open-source hub (the community hub runs at `mesh.tryaisoc.com`; you can run your
own). Its promise: **every install makes every other install smarter** — without
any instance revealing its data.

This is the one feature class a closed SaaS vendor structurally cannot copy
credibly, because trusting it requires reading the code. So the code is the
product: `services/mesh/`.

## What is shared

Exactly two artifact types, both aggregate and privacy-preserving:

1. **IOC sightings.** `SHA-256(normalized "<type>:<value>")` + a coarse type
   (`ip`/`domain`/`hash`/`url`) + severity + first/last-seen. **The raw IOC is
   never published.** A peer learns the value only if it already has it (it can
   compute the same hash) — a private-set-intersection style exchange: querying
   returns a reputation only for a hash you supply, and only once k-anonymity is
   met.
2. **Verdict signatures.** The institutional-memory signature key (category +
   connector + primary technique) plus a verdict distribution and mean
   confidence. **No tenant data, no entities, no free text.**

## What is never shared

Raw IOC values, entity names, hostnames, usernames, IPs, tenant identifiers,
alert descriptions, or any per-alert free text. `mesh preview` prints the exact
outbound payload before you enable anything.

## Privacy gates (defense-in-depth)

| Gate | Enforced | How |
|---|---|---|
| **k-anonymity** | hub-side + client | A signature/sighting's consensus is revealed only when `>= k` **distinct** instances report it (default `k=5`, `AISOC_MESH_K`). Below k, a query is indistinguishable from "unknown". |
| **Per-instance signing** | hub-side | Every artifact is Ed25519-signed; the hub verifies before counting. One actor can't inflate consensus with sock-puppet IDs — each distinct instance is a distinct verified public key (see `test_same_instance_cannot_inflate_consensus`). |
| **Opt-out** | client + hub | Tenant-level and rule-level opt-out on the client; the hub also honors a per-instance opt-out (refuses to accept or serve). |
| **Outbound audit** | client + hub | Every shared artifact is logged; the hub keeps a per-instance receipts log. |
| **Preview before enable** | client | `mesh preview` shows exactly what would be shared. |

## Consumption — the `mesh.py` verdict stage

The verdict engine gains a deterministic mesh stage
(`services/mesh/app/consensus.py:mesh_contribution`). Community consensus for an
alert's signature produces a **bounded** verdict delta capped at **±0.10** — the
mesh can nudge, never dominate, a local verdict. High community FP-rate pulls a
verdict toward benign; overwhelming TP confirmation nudges it up; below
k-anonymity it contributes nothing. The cap is unit-tested
(`test_mesh_contribution_is_bounded_and_directional`). The UI shows a community
consensus chip ("community: 41 instances saw this signature, 96% FP").

## Measuring the lift (honesty note)

The claim "the mesh reduces false positives" must be **measured**, not asserted.
The intended gate compares the eval harness with the mesh stage enabled vs.
disabled and publishes the delta on the benchmark page. Until that longitudinal
measurement is run on real multi-instance data, the benchmark page must present
any mesh lift as **synthetic/simulated** and labelled as such — never as a real
measured production number. (Same synthetic-vs-real rule as the rest of the eval
harness.)

## Trust posture

- The hub is open source and runs on your infrastructure if you don't trust the
  community hub.
- The hub only ever sees hashes and aggregates; it cannot reconstruct your
  environment.
- Public feed intel is intentionally global; the mesh targets tenant-private
  signal, which is why sharing is opt-in and gated.

See `SECURITY.md` for the mesh disclosure policy.
