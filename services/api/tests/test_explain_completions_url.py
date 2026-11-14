"""`/explain` must not append a version segment the base already carries.

Both explain paths built their URL by hand:

    base = llm_config.base_url.rstrip("/")
    url = f"{base}/v1/chat/completions"

`docker-compose.yml` sets ``LLM_GATEWAY_URL=http://litellm:4000/v1``, and the
resolver falls back to it whenever no BYOK base is configured — which is the
default install. So the URL came out as

    http://litellm:4000/v1/v1/chat/completions

Measured against a running CORE stack that is a 404, and `/explain` answered
200 with ``llm_used: false`` and this in ``llm_reason``:

    Client error '404 Not Found' for url 'http://litellm:4000/v1/v1/chat/completions'

The deterministic template it served instead is honest, which is why nothing
caught it: the feature reported that no model answered, and the model was
running in the next container.

They could not use ``chat_completions_url``, which resolves the base from the
environment — explain's base is layered per tenant, so a BYOK value wins and
only the caller knows which applied. The answer is not to duplicate the
suffix rule but to decide it from the base: a version segment already there
is not added again, and a bare host still gets one so BYOK keeps working.

Both services are covered from here because both copies must agree; a fix to
one and not the other is the drift this repository keeps finding.
"""

from __future__ import annotations

import pathlib

import pytest
from app.services.model_aliases import completions_url_for_base

#: The compose default, which is the case that was broken.
GATEWAY = "http://litellm:4000/v1"


class TestTheVersionSegmentIsNotDoubled:
    def test_the_bundled_gateway_base(self) -> None:
        assert completions_url_for_base(GATEWAY) == "http://litellm:4000/v1/chat/completions"

    def test_a_trailing_slash_does_not_change_the_answer(self) -> None:
        assert completions_url_for_base("http://litellm:4000/v1/") == "http://litellm:4000/v1/chat/completions"

    @pytest.mark.parametrize("base", [GATEWAY, "http://litellm:4000/v1/", "https://api.openai.com/v1"])
    def test_no_result_contains_a_doubled_version(self, base: str) -> None:
        assert "/v1/v1/" not in completions_url_for_base(base)


class TestABareHostStillGetsOne:
    """BYOK values are entered by hand and often omit it."""

    @pytest.mark.parametrize(
        ("base", "expected"),
        [
            ("https://api.openai.com", "https://api.openai.com/v1/chat/completions"),
            ("https://api.openai.com/", "https://api.openai.com/v1/chat/completions"),
            ("http://vllm.internal:8000", "http://vllm.internal:8000/v1/chat/completions"),
        ],
    )
    def test_version_is_appended(self, base: str, expected: str) -> None:
        assert completions_url_for_base(base) == expected


class TestOtherShapes:
    def test_a_v2_base_is_treated_the_same_way(self) -> None:
        """Written as a rule rather than a literal, so a provider that moves
        on does not reintroduce the bug."""
        assert completions_url_for_base("https://provider.test/v2") == "https://provider.test/v2/chat/completions"

    def test_a_full_endpoint_is_passed_through(self) -> None:
        full = "https://provider.test/v1/chat/completions"
        assert completions_url_for_base(full) == full

    def test_an_empty_base_falls_back_to_the_provider_default(self) -> None:
        assert completions_url_for_base("") == "https://api.openai.com/v1/chat/completions"
        assert completions_url_for_base("   ") == "https://api.openai.com/v1/chat/completions"


def test_neither_explain_path_builds_the_url_by_hand() -> None:
    """The regression is a string literal, so the gate can look for it.

    Two files had the same hand-rolled suffix. Pinning the helper alone would
    let either of them grow a third copy.
    """
    repo = pathlib.Path(__file__).resolve().parents[3]
    offenders = []
    for rel in ("services/api/app/services/alert_explain.py", "services/agents/app/api/explain.py"):
        text = (repo / rel).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if "/v1/chat/completions" in line and "completions_url_for_base" not in line and not line.lstrip().startswith(("#", "*")):
                offenders.append(f"{rel}:{lineno}: {line.strip()}")
    assert not offenders, "these build the completions URL by hand again:\n  " + "\n  ".join(offenders)
