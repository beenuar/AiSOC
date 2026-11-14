---
title: Compounding Memory
sidebar_label: Compounding memory
---

# Compounding Memory — verdicts that measurably improve

The longer an AiSOC instance runs, the more accurate it gets — and we publish
the curve. A nightly distillation job compresses analyst overrides + verdict
history into institutional memory that feeds every future verdict.

> "It gets smarter the longer you run it, and we publish the curve" — a claim no
> closed vendor makes with evidence you can reproduce.

## Distillation

`services/fusion/app/memory/distill.py` turns override rows into two versioned,
ledger-referenceable outputs:

1. **Per-signature priors** — for each alert signature (category + connector +
   primary technique), how it has historically resolved (FP rate + a prior in
   `[0, 1]`), consumed by the deterministic memory verdict stage.
2. **A few-shot exemplar bank** — the top-N most-evidenced resolved cases per
   category, injected into the LLM band prompt.

The pack `version` is a content hash, so a verdict can cite exactly which memory
version informed it.

## The `memory` verdict stage

`stage.py` produces a **bounded** verdict adjustment (capped at ±0.10, like the
mesh stage — memory nudges, never dominates). A signature analysts have
repeatedly corrected to benign pulls new alerts of that signature down; one they
repeatedly confirm nudges up; an unknown signature contributes nothing. The cap
and direction are unit-tested.

## Improvement telemetry

`improvement.py` computes verdict precision over time from a chronological
history, and the lift from the first window to the latest ("your AiSOC is N%
more accurate than at install"). On a simulated 90-day override history the
distilled memory raises precision measurably (e.g. 0.60 → 0.90 in the test
fixture). The aggregate anonymized improvement curve is shared opt-in via the
mesh plumbing and published on the benchmark page.

> **Honesty:** the 90-day history in the test is **synthetic** and clearly
> labelled; it demonstrates the mechanism, not a measured production number.

## Portable, signed memory packs

`aisoc memory export` (`pnpm aisoc:memory:export -- --demo`) distills and
**Ed25519-signs** a memory pack so an MSSP can bootstrap a new child tenant from
a curated baseline. Import verifies the signature and rejects a tampered pack (a
bootstrap baseline can't be forged), and can pin the publisher's key. The pack
format (`aisoc-memory-pack`) is the marketplace memory-pack artifact type. A
round-trip + tamper-rejection test gates the format.

## Status

Distillation, the bounded memory verdict stage, signed export/import (with
round-trip + tamper tests), and the improvement-curve computation are
implemented and tested (`services/fusion/tests/test_memory.py`). Wiring the
nightly distill job into the scheduler, the per-tenant improvement chart on the
SOC metrics dashboard, and reading the memory stage on the live verdict path are
the documented remaining integration steps.
