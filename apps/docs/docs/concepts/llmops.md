# LLMOps

AiSOC treats the LLM as a governed dependency, not a black box. Four small,
dependency-light pieces in `services/agents/app/llm/` make LLM behaviour
versioned, bounded, cached, and fail-closed.

## Prompt registry (versioned + hash-pinned)

Every production prompt is a **named, versioned, content-hashed artifact** in
`prompt_registry.py`. The committed `prompts.lock.json` pins each prompt's
version → sha256. The CI lint job runs `scripts/check_prompt_lock.py --check`,
which **fails if a prompt's text changed without a version bump**.

Why it matters: `AGENTS.md` requires that any change to agent prompts re-grade
the eval harness. That rule is only enforceable if prompt edits are visible —
the lock makes a silent one-word tweak impossible. To change a prompt you must
bump its version and regenerate the lock, which is exactly the moment to
re-run the eval.

## Model pins + provider fallback

`model_pins.py` pins each logical role (triage, recon, summary) to a concrete
model and an ordered fallback chain. Primaries are overridable per operator via
`AISOC_MODEL_PIN_<ROLE>`, but **every chain is gate-enforced to terminate in the
deterministic tier** — so there is always a defined, non-silent floor when a
provider is unavailable. This replaces the scattered `os.getenv(..., "gpt-4o-mini")`
defaults that could drift per module.

## Content-addressed response cache

`response_cache.py` keys responses on `sha256(model + prompt + input)` with
field separation and LRU eviction. It complements the cost governor: the
governor dedups identical *alerts*; the cache dedups identical *LLM calls*. A
cache hit is byte-identical to the model's original reply, so it is safe under
the determinism contract.

## Fail-closed structured-output validation

`structured_output.py` is the single parser for LLM structured replies. It
strips ``` fences and prose, parses JSON, and validates against a caller-supplied
schema. On **any** failure it returns a deterministic fallback rather than a
half-parsed object — because feeding a partially-parsed structured output into
an autonomy decision or a ledger entry is worse than failing.

## Gate

`services/agents/tests/test_llm_ops.py` proves the lock catches un-versioned
prompt edits, structured-output parsing fails closed, every model-pin chain has
a deterministic floor, and the response cache is content-addressed with correct
eviction.
