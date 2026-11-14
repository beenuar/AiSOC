"""How long an investigator agent's reply is allowed to get.

Every LLM call in the four-agent investigator pipeline was placed with no
completion bound, so a model that failed to stop generated until it hit the
context window. That is not theoretical: dispatching the pipeline against
``qwen2.5:0.5b`` on a GitHub-hosted runner produced

    completion_tokens=40960  latency_ms=1208829.8  step=recon

— the model's whole context, twenty minutes, for one call, twice in the same
investigation. The identical call on a developer machine returned 200 tokens
in two seconds. Greedy decoding is only deterministic *for a fixed kernel*,
and a small quantised model that diverges by one token can fall into a
repetition loop that nothing downstream interrupts.

Unbounded is the wrong default wherever this runs. Against a hosted provider
it is a 41,000-token bill per degenerate call and an investigation that never
returns, and the reply is unusable either way: the four agents parse JSON, and
a reply that ran past the schema was never going to parse.

The bound is deliberately well clear of what the agents legitimately produce.
Measured over the pipeline's calls on the eval corpus, the largest legitimate
completion was 876 tokens (the report writer, which writes the longest
output); recon, forensic and responder sit between 200 and 400. 2048 leaves
more than double the headroom over the longest real reply, so it truncates
nothing the agents actually emit and stops a runaway inside a few seconds.

Override with ``AISOC_INVESTIGATOR_MAX_COMPLETION_TOKENS`` for a deployment
running a model whose replies are genuinely longer. Zero or negative removes
the bound, which is the pre-existing behaviour and has to stay reachable —
but it is now a decision somebody makes rather than the default.
"""

from __future__ import annotations

import os

#: Headroom over the longest legitimate reply measured on the eval corpus.
DEFAULT_MAX_COMPLETION_TOKENS = 2048

_ENV_VAR = "AISOC_INVESTIGATOR_MAX_COMPLETION_TOKENS"


def max_completion_tokens() -> int | None:
    """The completion bound, or ``None`` when an operator has removed it."""
    raw = os.getenv(_ENV_VAR)
    if raw is None or not raw.strip():
        return DEFAULT_MAX_COMPLETION_TOKENS
    try:
        value = int(raw)
    except ValueError:
        # A typo must not silently restore the unbounded behaviour this
        # module exists to end, so it falls back to the bound, not past it.
        return DEFAULT_MAX_COMPLETION_TOKENS
    return value if value > 0 else None
