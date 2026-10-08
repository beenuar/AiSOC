# Security pack

For a reviewer doing diligence on AiSOC. Six documents, in the order a
security questionnaire usually walks them.

| Document | Answers |
|---|---|
| [Architecture and data flow](architecture-and-data-flow.md) | What the components are, which trust boundaries they sit across, and where every class of data goes. |
| [Data handling by deployment mode](data-handling.md) | What leaves your perimeter under each of the four ways AiSOC can be run, and what is retained where. |
| [Platform threat model](platform-threat-model.md) | STRIDE over the platform, with the credential vault as the top asset. |
| [Agent and tool threat model](agent-threat-model.md) | STRIDE over the prompt and tool boundaries, both of which take attacker-influenced input. |
| [Connector least privilege](connector-least-privilege.md) | The minimum vendor scope each connector needs. |
| [Security questionnaire](questionnaire.md) | Standard control questions, answered, with the gap list stated rather than omitted. |
| [Sub-processors](subprocessors.md) | What this repository can and cannot establish about the hosted service. |

## The one rule these documents follow

**Every statement names the file or the CI job that makes it true, and where a
control is narrower than its heading sounds, the limit is in the same
paragraph.**

That rule exists because this project has broken it. Four security documents
once described controls that did not exist in the tree: AES-256-GCM backup
encryption where the script only gzipped and uploaded, envelope encryption
cited as the mitigation for a database dump while `EnvelopeCipher` had zero
callers, one unbroken distributed trace with neither end of the Kafka spine
instrumented, and per-tenant retention marked GATED by a test that asserted
only that the purge SQL parses. Each was corrected, and then implemented.

So a claim here without a link beside it is a bug in this pack, and
[reporting one](../../SECURITY.md) is welcome.

## Verifying any of this yourself

Nothing here asks to be taken on trust. The repository is the evidence:

```bash
git clone https://github.com/beenuar/AiSOC
cd AiSOC

# Which CI job proves which product claim — 293 rows, every one naming a gate.
python3 scripts/check_claim_gate_matrix.py

# The authorization surface, counted rather than described.
python3 scripts/check_route_auth.py        # every route authenticates, or is listed with a reason
python3 scripts/check_route_authz.py       # every state-changing route authorizes, or is listed
python3 scripts/check_one_permission_model.py --check

# Nothing is pointed at the internet by default.
python3 scripts/check_default_egress.py

# Every gate named in this pack is actually wired to a workflow.
python3 scripts/check_gate_coverage.py
```

[`docs/audit/CLAIM_TO_GATE_MATRIX.md`](../audit/CLAIM_TO_GATE_MATRIX.md) is the
long form: one row per published claim, each naming the job that fails when the
claim stops being true. Rows marked `PARTIAL` name their own gap.

## What this pack is not

- **Not an audit report.** No third-party audit has been commissioned against
  AiSOC. The reasoning, the trigger condition and the sequencing are recorded
  in [ADR-0002](../decisions/0002-compliance-claims.md).
  That ADR also asserts a CI check that **does not exist** — see
  [the questionnaire](questionnaire.md#governance-and-assurance), which states
  the real position. Surfacing that is this pack's own rule working: the
  sentence was written from the ADR and caught by
  `scripts/check_security_pack_links.py` before it shipped.
- **Not a penetration-test report.** None has been commissioned. What exists
  instead is a public advisory history: **16 advisories published** at the
  time of writing, covering findings from both external reports and internal
  audits, each with the fix and the regression guard. See
  [the questionnaire](questionnaire.md#vulnerability-management) and the
  [advisory list](https://github.com/beenuar/AiSOC/security/advisories).
- **Not a statement about a deployment you have not seen.** Most of these
  controls are properties of the software. Whether your operator configured
  them is a question about your deployment, and
  [the data-handling page](data-handling.md) says which is which.
