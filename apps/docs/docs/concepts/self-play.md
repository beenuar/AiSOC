---
title: Self-play purple team
sidebar_label: Self-play
---

# The SOC that attacks itself

Self-play turns the purple-team service from a test runner into a **continuous
adversary**: an LLM-planned campaign engine composes multi-stage attack chains
from the Atomic Red Team + Caldera inventory, runs them in a closed loop against
the live defense, scores detected/missed per technique, and auto-files
Detection-as-Code proposals for every miss.

Try the canned campaign — deterministic, offline, ~seconds:

```bash
pnpm aisoc:selfplay
```

```
── AiSOC self-play campaign (canned, offline) ──
  [1] initial-access         T1566.001    ✗ MISSED    Spearphishing Attachment
  [2] execution              T1059.001    ✓ DETECTED (12.0s)  PowerShell
  [3] persistence            T1547.001    ✗ MISSED    Registry Run Keys / Startup Folder
  [4] privilege-escalation   T1055        ✓ DETECTED (12.0s)  Process Injection
  [5] exfiltration           T1048        ✓ DETECTED (12.0s)  Exfiltration Over Alternative Protocol

  3/5 techniques detected (60%) · MTTV 12.0s
  Auto-filed 2 Detection-as-Code proposal(s) for the misses (eval-gated review)
```

## The hard scope guard (safety, not a prompt)

The single most important property: a SOC that attacks itself must **never**
touch a production asset. This is enforced in code, not asked of a model.
`services/purple-team/app/adversary/scope_guard.py` hard-fails
(`ScopeViolation`) before any step runs unless **every** target carries an
allowlisted lab tag (`lab`/`sandbox`/`range`/…) **and** carries no forbidden
production tag (`production`/`crown-jewel`/`pci`/…). There is no force flag. The
guard has adversarial tests: production assets, untagged assets, empty target
sets, and a `lab`+`crown-jewel` laundering attempt all hard-fail.

## The closed loop

1. **Plan** — `planner.py` composes an ordered chain (initial-access → execution
   → persistence → privesc → exfil), selecting only techniques whose platform
   actually exists among the lab targets ("attack what exists").
2. **Run** — each step emits telemetry (into Kafka on the live path); the
   defense responds normally.
3. **Score** — a detection oracle reports detected/missed per technique;
   `campaign.py` computes detection rate + mean time to verdict.
4. **Improve** — `dac.py` files one eval-gated Detection-as-Code proposal per
   miss (status `proposed`, low confidence — a scaffold pending eval + human
   review). Self-play can only *propose*, never silently merge.

## The scoreboard

Each campaign appends a row to
[`apps/docs/static/data/selfplay-scoreboard.json`](https://github.com/beenuar/AiSOC/blob/main/apps/docs/static/data/selfplay-scoreboard.json)
(techniques attempted/detected, detection rate, MTTV, new detections filed).
Every row carries an explicit `synthetic` flag: the canned demo campaign is
`synthetic: true`; a nightly live run against the seeded range is
`synthetic: false`. **A synthetic row is never presented as measured live
performance** — the same honesty rule as the rest of the eval harness.

## Status

The planner, hard scope guard, closed-loop scorer, DAC auto-filer, and the
canned campaign are implemented and tested. Wiring the nightly *live* campaign
(Kafka emitter + alert-store oracle + `HttpDacFiler` posting to
`POST /api/v1/detection-proposals`) into the full-profile scheduler is the
remaining live-integration step.
