# The verdict corpus

A labelled set the scorer will accept, built so that **no constant answer can
score well on it**.

Depth plan 1.1. Everything else in `services/agents/tests/eval_data/` measures
MITRE mapping or response selection. Nothing in this tree could measure whether
the agent got the *verdict* right, because every labelled corpus here is
malicious by construction — `synthetic_incidents.json` and
`adversary_incidents.json` are 200 attacks each and carry no
`expected_disposition` at all. `scripts/score_replay_set.py` refuses both, and
it should keep refusing both. This file is the corpus it accepts instead.

---

## Honesty statement, first because it is the part that matters

**All 72 items are hand-authored. Zero are sourced from a recorded dataset.**

| | count |
|---|---|
| Items | 72 |
| Hand-authored, `is_synthetic: true` | **72 (100%)** |
| Drawn from a third-party dataset | **0** |

Every field value is invented. Every address is an RFC 5737 documentation
range and every name is an RFC 2606 reserved name. The field *names* follow
each vendor's published audit-log vocabulary so the items are shaped like real
telemetry, but no recorded event, from any dataset or any deployment, is
reproduced here. Nothing in this corpus may be described as real-world data.

The per-item `provenance` block says `"source": "hand-authored"` for all 72.
`scripts/check_verdict_corpus.py` refuses an item that is neither marked
synthetic nor carries a redistribution-permitting licence, so the moment a
sourced item is added it has to bring its licence with it.

### Why nothing was sourced

Not for want of looking. The register below is the honest answer, and the
licence is only the first filter — two of the five pass it.

| Candidate | Licence this repository records | Refused because |
|---|---|---|
| CICIDS-2017 (UNB) | research use; commercial use needs permission ([terms](https://www.unb.ca/cic/datasets/ids-2017.html)) | Not redistributable inside an MIT repository. Also network flows labelled `BENIGN`/attack, which is a traffic class and not an analyst disposition. |
| CTU-13 (Stratosphere Lab, CTU) | CC BY-NC-SA 4.0 | The non-commercial clause is incompatible with an MIT repository, and ShareAlike would relicense what it is combined with. |
| AIT Log Data Set V2 (AIT) | CC BY 4.0 — attribution required | **Licence is fine.** Refused on fit: Linux host and web-server logs from a simulated enterprise, no cloud, identity or SaaS control-plane events, labels mark attack phases rather than dispositions, and no benign case is paired to a malicious one on the same rule. |
| MITRE Engenuity ATT&CK Evaluations | attribution required; MITRE Engenuity states the evaluations do not rank vendors | **Licence is fine.** It publishes a detection category per procedure step, not telemetry. There is no verdict in it to label. |
| MITRE CAR (already imported under `detections/car-imports/`) | Apache-2.0 | Detection analytics, not events. No verdicts. |

The licence text above is quoted from this repository's own downloaders in
`scripts/datasets/`, which record the upstream terms. **None of these datasets
was fetched while building this corpus**, and none is redistributed here.

The structural problem is the one the fit column keeps pointing at. Item 1.1
needs three things at once: the four canonical dispositions an analyst closes
a finding as, cloud/identity/SaaS control-plane events, and a benign case
paired to a malicious one that differs *only* in the decisive evidence. No
public corpus carries any of the three, because public attack-telemetry
datasets are recordings of attacks — the benign half of a real queue is
exactly the part nobody publishes, since it is full of their own employees.
Pairing a recorded malicious event against a hand-authored benign twin would
also be worse than pairing two hand-authored ones: the two halves would differ
in field vocabulary, formatting and verbosity, and an agent could separate
them on that instead of on the evidence.

So: hand-authored, said plainly, with the gate ready for the day a suitable
licensed source appears.

---

## What is in it

72 items in **36 twin pairs**. Each pair is one non-malicious item and one
malicious item that fired **the same rule** with **the same severity** and
**the same title**, and differ in the evidence.

### Class balance

| Disposition | Items | Share | What a constant answer of this scores |
|---|---|---|---|
| `true_positive` | 36 | **50.0%** | 0.500 |
| `benign` | 18 | 25.0% | 0.250 |
| `benign_true_positive` | 10 | 13.9% | 0.139 |
| `false_positive` | 8 | 11.1% | 0.111 |

The plan's bar is that no class exceeds 60%, so that a constant answer cannot
score above 60%. The largest class holds 50.0% and that is exactly what
answering `true_positive` to all 72 scores — measured, not asserted, by
`services/agents/tests/test_verdict_corpus.py`. The smallest class holds 11.1%,
comfortably over the 5% floor `score_replay_set.assert_gradeable` enforces.

36 malicious items clears `MIN_MALICIOUS_FOR_HEADLINE = 30`, so a report over
this corpus prints a headline accuracy rather than withholding it.

### Source mix

**52 of 72 items (72.2%)** come from cloud, identity and SaaS sources — the
plan asks for at least half, because that is where this repository's corpus
was thinnest. All ten sources the plan names are present.

| Family | Items | Vendors |
|---|---|---|
| cloud | 20 | `aws_cloudtrail`, `aws_guardduty`, `gcp_audit`, `azure_activity`, `kubernetes_audit` |
| saas | 20 | `google_workspace`, `m365`, `github`, `slack` |
| identity | 12 | `entra_id`, `okta` |
| endpoint | 10 | `crowdstrike`, `windows_security`, `linux_auditd` |
| network | 6 | `palo_alto`, `zscaler`, `fortinet_vpn` |
| email | 2 | `email_security` |
| database | 2 | `postgres_audit` |

### The benign half is what a real queue is full of

Every non-malicious item carries a `benign_archetype`, and all six the plan
names are covered.

| Archetype | Items | Example |
|---|---|---|
| `admin_bulk_change` | 12 | 38 S3 bucket policies rewritten by the infrastructure pipeline — all of them *tightening* access |
| `ci_service_account` | 7 | the release bot force-pushing its own generated lockfile branch |
| `break_glass_with_ticket` | 6 | an on-call engineer in a payments pod under a 60-minute binding, incident id in the impersonation reason |
| `scanner_or_security_tooling` | 5 | 1,400 failed authentications from the booked vulnerability scanner |
| `travel_sign_in` | 3 | two countries 40 minutes apart, same device id, second address is the corporate VPN egress |
| `backup_job` | 3 | 180,000 files touched overnight, read-only, no extension changed, no shadow copy deleted |

### Severity carries no signal, deliberately

A corpus where the attacks are `critical` and the noise is `low` is separable
on severity alone, and would measure nothing. Because twins share their
severity and the pairing is strictly one to one, the two distributions are
**identical**: 19 high, 12 medium, 5 critical on each side. The gate asserts it.

---

## Fields

| Field | Meaning |
|---|---|
| `id`, `pair_id`, `twin_of` | identity and the pairing, reciprocal in both directions |
| `expected_disposition` | the analyst's label, one of the four in `GRADED_DISPOSITIONS` |
| `labelled` | always `true`; `score_replay` grades only labelled rows |
| `is_synthetic` | always `true` in this version |
| `family`, `vendor`, `rule_id` | the source slice; `score_replay` segments by `vendor` and `rule_id` |
| `title`, `severity` | the rule's own output, identical across a pair |
| `expected_techniques` | ATT&CK ids, for the MITRE axis |
| `benign_archetype` | non-malicious items only |
| `decisive_evidence` | the analyst's reason, in prose |
| `evidence` | the facts the agent is given |
| `provenance` | source, licence, and who authored it |

### Do not give the model `decisive_evidence`

It states the answer. Feeding it to the agent would make every number measured
on this corpus meaningless. The corpus declares the hold-out set in its own
header:

```json
"held_out_from_the_model": [
  "expected_disposition", "decisive_evidence", "benign_archetype",
  "twin_of", "pair_id"
]
```

A harness reading this corpus should pass `evidence`, `title`, `severity`,
`vendor` and `rule_id` to the agent, and nothing else.

---

## Running it

The corpus is shaped so `score_replay_set.py` reads it directly — the item list
is under `decisions` and every row carries `labelled: true`:

```bash
python3 scripts/score_replay_set.py \
  --decisions services/agents/tests/eval_data/verdict/verdict_corpus_v1.json \
  --model <model id> --dataset aisoc-verdict-v1 --synthetic
```

With no agent run attached, every item has no `verdict` and is scored as an
abstention, so the report reads 72 labelled, 0 answered, 100% abstained. That
is the correct reading of a corpus with no run against it, and it demonstrates
the thing 1.1 asks for: **the scorer accepts this corpus**. Attach an agent's
verdicts to each row to get a graded report.

Two existing behaviours this corpus must not disturb, both pinned by tests:

* `scripts/score_replay_set.py` still **refuses** `synthetic_incidents.json`
  and `adversary_incidents.json` — `scripts/tests/test_score_replay_set.py`.
* The benchmark corpus still separates four reference agents —
  `packages/aisoc-benchmark/tests/test_corpus_can_grade.py`.

## The gate

`scripts/check_verdict_corpus.py` runs on every pull request. It refuses:

1. a class above 60%, or a minority class below the scorer's 5% floor;
2. fewer than half the items from cloud, identity and SaaS, or any of the ten
   named sources missing;
3. a non-malicious item with no malicious twin, a twin that is not reciprocal,
   or a pair that differs in rule, vendor, family, severity or title rather
   than in its evidence;
4. an item with no provenance block, or one that is neither `is_synthetic` nor
   carrying a licence from the redistribution allowlist;
5. a routable address, or an email or link outside the RFC 2606 reserved names;
6. header counts that disagree with the body — so this document and the data
   cannot drift apart;
7. severity distributions that differ between the malicious and non-malicious
   halves.

`python3 scripts/check_verdict_corpus.py --self-test` injects one violation of
each rule into a copy of the real corpus and requires the gate to catch every
one, then proves the gate refuses a tree with no corpus in it at all.
