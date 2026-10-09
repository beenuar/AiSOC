# Sigma correlation rules

Correlation documents in the [Sigma correlations](https://github.com/SigmaHQ/sigma-specification)
format, compiled into the windowed engine by `scripts/sigma_correlation.py`
and exported into `services/fusion/app/data/windowed_ruleset.json` by
`scripts/export_windowed_ruleset.py`.

## These are first-party, not upstream imports

**No upstream SigmaHQ correlation rule is vendored here, and none was at the
time this directory was created** — `detections/sigma-imports/` holds 3,132
rule documents and not one carries a `correlation:` block, so the import path
had no corpus to run against and nothing would have exercised it. The rules
here are hand-authored under this repository's own licence, in the upstream
format, to give the compiler real input. Treat the figure they contribute as
first-party content, not as imported coverage.

Two consequences worth stating rather than discovering:

* **`group-by` names a field this platform normalizes**, not always the
  vendor's own spelling. Upstream would write `eventSource`; a rule that has
  to accumulate per principal needs `user_arn`, which is what the CloudTrail
  connector emits. `scripts/check_sigma_correlations.py` fails a rule whose
  `group-by` or selector names a field nothing emits, so this stays checkable
  rather than aspirational.
* **A correlation is not replayed through its connector's `normalize()`.**
  The stateless Sigma imports are (`scripts/compile_sigma_ruleset.py` runs an
  out-of-process worker per rule); these are replayed through the real
  windowed engine instead, in
  `services/fusion/tests/test_sigma_correlation_replay.py`. That proves the
  compiled rule fires on an event of the shape its selector describes. It
  does not prove a given vendor populates those fields on a given event.

## Layout

One file per correlation, multi-document YAML as the specification describes:
the base rules first, each with a `name:`, then the correlation document
referencing them.

## Refusals are part of the corpus

Files under `_refused/` are correlations the engine cannot express. They are
kept, not deleted, because a refusal with a reason is the useful artefact —
and because the compiler's taxonomy needs real inputs to be worth anything.
`scripts/check_sigma_correlations.py --report` prints which, and why.
