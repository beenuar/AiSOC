---
title: Windowed detections
description: Threshold rules over a sliding window, for behaviour no single event reveals.
---

# Windowed detections

Most detection rules answer a question about one event: does this process
name match, is this hash known bad, is this port unusual. Some of the most
useful questions are not about one event at all.

Five failed logins are noise. Five hundred failed logins against five hundred
accounts from one address in ninety seconds is a password spray, and no
individual event in it is remarkable. The signal is entirely in the shape of
the set.

The windowed engine (`services/fusion/app/services/windowed_detection.py`)
evaluates threshold rules over a sliding window, keyed on an entity, with
state in Redis so it survives a fusion restart and works across replicas.

## What it detects today

**72 rules**, in `services/fusion/app/data/windowed_ruleset.json`. That file is
the authority; the breakdown below is re-derivable from it and nothing else
restates the list, because a hand-maintained table of rule names is the thing
that goes stale first. This section used to name five — the original hardcoded
set, long after the corpus had grown past it.

| Category | Rules | Examples |
|---|---:|---|
| Identity | 27 | MFA fatigue (repeated push denials for one account), many distinct source IPs authenticating one account |
| Cloud | 20 | Access-key minting bursts, one principal across many regions, role grant followed by lock removal |
| Network | 11 | Connection fan-out from one source |
| Application | 6 | An AI agent repeatedly denied a tool call, or calling an unusual number of distinct models |
| Endpoint | 5 | Process-spawn bursts keyed on image or parent image |
| Data exfil | 3 | Read volume against one host ahead of an outbound transfer |

Windows run from **60 seconds to 24 hours**, and a rule is keyed on whichever
entity its question is about — `actor`, `src_ip`, `user`, `user_arn`,
`agent_id`, `hostname`, a Windows `SubjectUserName`, a Kubernetes `k8s_user`
and others.

68 of the 72 carry a `wd-` prefix: they were derived from stateless `det-*`
rules that named a threshold the stateless engine cannot compute, and each was
replayed through the real windowed engine and watched to fire. That translation
is also why the published *stateless* executable figure went **down** — those
rules had been counted as executable while being unable to fire. The remaining
four are `aisoc-corr-*`, compiled from Sigma correlation rules under
`detections/sigma-correlations/`.

## Why it is a separate engine

The stateless corpus is a pure function of one normalised event, which is
what makes it cheap, replayable and testable against a fixture. Windowed
rules need per-entity state, a clock and eviction — properties that would
make every stateless rule slower and harder to reason about if the two shared
an evaluator.

Keeping them separate has one consequence worth stating: the executable
detection count in the [truth table](https://github.com/beenuar/AiSOC/blob/main/docs/detections/truth-table.md)
covers the stateless corpus. Windowed rules are counted separately, because
folding them in would make a number that means "rules the stateless engine
loaded" quietly mean something else.

## The bug this engine was born with

The matcher read fields with a flat `event.get()`, while connectors nest the
vendor payload under `raw_event`. Any rule matching on a nested field
therefore matched nothing — silently, because a rule that never fires and a
rule with nothing to fire on look identical from outside.

The fix flattens `raw_event` into the match namespace once, in the engine,
rather than hoisting fields per-connector. That is worth knowing if you are
writing a rule: match on the flat field name, and the engine finds it whether
the connector nested it or not.

## Operating notes

- **State is Redis-backed** and keyed `tenant:{id}:window:{rule}:{entity}`.
  Losing Redis loses in-flight windows, which means a spray already in
  progress may not fire. It does not mean the rule is off.
- **Windows are per tenant.** A shared source address seen by two tenants
  accumulates two independent counters, which is correct — one tenant's
  threshold is not evidence about another's.
- **Eviction is by window, not by count.** The longest window in the corpus is
  24 hours (`wd-ident-ad-machine-account-quota-abuse`, keyed on user) and the
  shortest is 60 seconds; a long window over a high-cardinality key holds far
  more state than a short one. That is the dimension to watch if Redis memory
  grows.

## Adding a rule

Rules are compiled from Python specs to `windowed_ruleset.json` by
`scripts/export_windowed_ruleset.py`, and `validate-detections.yml` runs it
with `--check`, so a spec change that is not exported fails the build rather
than shipping a ruleset that disagrees with its source.

Each rule needs a positive and a negative fixture. The negative matters more:
a threshold rule with no negative fixture passes its test by firing on
everything.

## See also

- [Detection content](./detections.md)
- [Truth table](https://github.com/beenuar/AiSOC/blob/main/docs/detections/truth-table.md)
