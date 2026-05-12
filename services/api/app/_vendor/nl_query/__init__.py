"""Natural language → query translation for AiSOC.

This module ships a deterministic, offline-friendly translator that converts
plain-English security questions into ES|QL (OpenSearch / Elasticsearch),
KQL (Microsoft Sentinel / Kusto-style), and SPL (Splunk) dialects. It also
exposes a grammar validator so consumers can refuse to execute syntactically
invalid output.

Design notes:

- The translator runs **without** an LLM by default. This is what allows the
  air-gapped deployment story to keep working and lets the eval harness give
  reproducible numbers in CI.
- An optional LLM enhancement path is exposed via :func:`enhance_with_llm` for
  callers that already have credentials available; if it fails for any reason
  we fall back to the deterministic translation.
- Every emitted query goes through grammar validation before being returned,
  and the API layer also re-validates before execution.
"""

from .grammar import (
    GrammarError,
    validate_esql,
    validate_kql,
    validate_spl,
)
from .translator import (
    NLQuery,
    QueryIntents,
    TranslatedQuery,
    Translator,
    enhance_with_llm,
    parse_intents,
    translate,
)

__all__ = [
    "NLQuery",
    "QueryIntents",
    "TranslatedQuery",
    "Translator",
    "translate",
    "parse_intents",
    "enhance_with_llm",
    "GrammarError",
    "validate_esql",
    "validate_kql",
    "validate_spl",
]
