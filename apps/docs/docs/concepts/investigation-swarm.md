---
title: Investigation Swarm
sidebar_label: Investigation swarm
---

# Investigation Swarm — parallel hypothesis agents

For hard cases, one agent pursuing one theory leaves blind spots. The swarm fans
out **3–5 competing hypothesis agents in parallel**, each independently gathering
evidence with its own cost budget, then a **debate node** scores the hypotheses
on explicit criteria and emits a ranked list.

## When it fires

The swarm is gated on complexity (`app/swarm/complexity.py`): it only fires when
a case has enough distinct entities and/or a broad enough technique spread that
competing explanations are plausible (defaults: ≥3 entities or ≥3 techniques).
Simple alerts stay on the cheaper single-agent path. It's behind a tenant flag,
on by default in the demo.

## The hypotheses

Each agent owns a hypothesis — e.g. **ransomware staging**, **insider
exfiltration**, **lateral movement**, **C2 beacon**, or **false positive
(backup/maintenance job)** — with supporting/contradicting signal and
corroborating MITRE techniques (`app/swarm/hypotheses.py`). Agents run
concurrently (`asyncio.gather`); each is capped by a per-agent token budget, so
the swarm's total spend is bounded and predictable.

## The debate node

`app/swarm/debate.py` scores each hypothesis on explicit criteria — **evidence
coverage**, **contradiction count**, and an **institutional-memory prior** (how
this signature historically resolved) — and produces a ranked list with a
margin-based confidence (clamped to [0.05, 0.95]). The debate is recorded in the
ledger as a first-class `debate` step type; the [public replay](../console/public-replay.md)
UI renders it as a split-screen of competing hypotheses and their scores.

## The eval gate

`services/agents/tests/test_swarm_vs_single.py` runs the swarm vs. single-agent
mode on a synthetic multi-hypothesis incident set and **publishes both numbers**,
asserting the swarm beats single-agent on the investigation-completeness macro by
≥ 10% while staying under a configurable cost ceiling.

> **Honesty:** `investigation_completeness` is a **substrate self-consistency**
> macro — the fraction of an incident's relevant hypotheses that were considered.
> A single agent pursues only its top prior; the swarm considers up to five, so on
> multi-hypothesis incidents its completeness is structurally higher. This is not
> a live-LLM accuracy claim, and the incident set is labelled synthetic — the same
> framing as the rest of the [eval harness](../benchmark.md).
