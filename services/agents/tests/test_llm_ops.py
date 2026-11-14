"""Phase 8 — LLMOps gates: prompt registry, structured output, pins, cache."""

from __future__ import annotations

from app.llm.model_pins import DETERMINISTIC, all_roles, get_pin, verify_pins
from app.llm.prompt_registry import PromptRegistry, default_registry, load_lock
from app.llm.response_cache import InMemoryResponseCache, ResponseCache, cache_key
from app.llm.structured_output import parse_structured, validate_or_fallback

# ── Prompt registry + lock drift gate ────────────────────────────────────────


def test_committed_prompt_lock_matches_registry():
    """The gate: production prompts must match the committed lock. If this
    fails, a prompt changed without a version bump + lock regeneration."""
    reg = default_registry()
    drifts = reg.verify_against_lock(load_lock())
    assert drifts == [], f"prompt lock drift: {drifts}"


def test_text_change_without_version_bump_is_detected():
    reg = PromptRegistry()
    reg.register("p", "1", "original text")
    lock = reg.as_lock()
    # Simulate an edit that kept the version.
    reg2 = PromptRegistry()
    reg2.register("p", "1", "EDITED text")
    drifts = reg2.verify_against_lock(lock)
    assert any("WITHOUT a version bump" in d for d in drifts)


def test_version_bump_is_flagged_for_lock_regen():
    reg = PromptRegistry()
    reg.register("p", "1", "text")
    lock = reg.as_lock()
    reg2 = PromptRegistry()
    reg2.register("p", "2", "text")
    drifts = reg2.verify_against_lock(lock)
    assert any("regenerate the lock" in d for d in drifts)


def test_duplicate_registration_rejected():
    reg = PromptRegistry()
    reg.register("p", "1", "a")
    try:
        reg.register("p", "1", "b")
        raise AssertionError("expected ValueError on duplicate registration")
    except ValueError:
        pass


# ── Structured-output validation (fail-closed) ───────────────────────────────


def test_parse_strips_fences_and_prose():
    text = 'Here is the result:\n```json\n{"verdict": "true_positive", "confidence": 90}\n```'
    result = parse_structured(text)
    assert result.ok
    assert result.value["verdict"] == "true_positive"


def test_invalid_json_fails_closed():
    result = parse_structured("not json at all")
    assert not result.ok
    assert "invalid JSON" in result.error


def test_schema_validation_failure_fails_closed():
    def validator(obj):
        if "verdict" not in obj:
            raise ValueError("missing verdict")
        return obj

    result = parse_structured('{"confidence": 50}', validator)
    assert not result.ok
    assert "schema validation failed" in result.error


def test_validate_or_fallback_returns_deterministic_default_on_failure():
    fallback = {"verdict": "needs_review", "confidence": 0}
    value, used_fallback = validate_or_fallback("garbage {{{", fallback)
    assert used_fallback is True
    assert value == fallback


def test_validate_or_fallback_passes_through_valid():
    value, used_fallback = validate_or_fallback('{"ok": true}', {"ok": False})
    assert used_fallback is False
    assert value == {"ok": True}


# ── Model pins + provider fallback ───────────────────────────────────────────


def test_every_pin_chain_terminates_in_deterministic():
    assert verify_pins() == []
    for role in all_roles():
        chain = get_pin(role).resolved_chain()
        assert chain[-1] == DETERMINISTIC, f"{role} chain must end deterministic: {chain}"


def test_unknown_role_falls_back_to_deterministic_only():
    pin = get_pin("does-not-exist")
    assert pin.resolved_chain() == [DETERMINISTIC]


def test_env_override_pins_primary(monkeypatch):
    monkeypatch.setenv("AISOC_MODEL_PIN_TRIAGE", "my-local-model")
    pin = get_pin("triage")
    assert pin.primary_model == "my-local-model"
    assert pin.resolved_chain()[-1] == DETERMINISTIC  # floor preserved


# ── Response cache (content-addressed) ───────────────────────────────────────


def test_cache_key_is_field_separated():
    # a||b must not collide with different splits of the same concatenation.
    k1 = cache_key(model="m", prompt="ab", user_input="c")
    k2 = cache_key(model="m", prompt="a", user_input="bc")
    assert k1 != k2


def test_response_cache_hit_and_miss():
    cache = ResponseCache()
    assert cache.lookup(model="m", prompt="p", user_input="i") is None
    cache.store(model="m", prompt="p", user_input="i", response="RESP")
    assert cache.lookup(model="m", prompt="p", user_input="i") == "RESP"


def test_in_memory_cache_evicts_oldest():
    backend = InMemoryResponseCache(max_entries=2)
    backend.set("a", "1")
    backend.set("b", "2")
    backend.set("c", "3")  # evicts "a"
    assert backend.get("a") is None
    assert backend.get("b") == "2"
    assert backend.get("c") == "3"
    assert backend.hits >= 2
