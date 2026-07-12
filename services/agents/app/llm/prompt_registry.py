"""Versioned, hash-pinned prompt registry (Phase 8 — LLMOps).

`AGENTS.md` requires that any change to agent prompts re-grade the eval harness.
That rule is only enforceable if prompt changes are *visible and deliberate* —
but before this, prompts were inline string constants scattered across the
agent modules, so a one-word tweak could ship without anyone (or any gate)
noticing it changed the model's behaviour.

This registry makes every production prompt a **named, versioned, content-hashed
artifact**. The committed lock file (`prompts.lock.json`) pins each prompt's
version → sha256. `verify_against_lock` (and `scripts/check_prompt_lock.py
--check`, wired into CI) fails when a prompt's text changes without a version
bump — so editing a prompt forces a conscious version bump + lock regeneration,
which is exactly the signal that should trigger the eval re-grade.

The registry is the source of truth for prompt text; agents should read via
`get(name)` rather than redeclaring constants. Migration of the existing inline
prompts is tracked as 8b; this seeds the registry + gate with the canonical
triage/summary prompts.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

LOCK_PATH = Path(__file__).resolve().parent / "prompts.lock.json"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Prompt:
    name: str
    version: str
    text: str

    @property
    def sha256(self) -> str:
        return _sha256(self.text)


class PromptRegistry:
    """In-process registry of versioned prompts."""

    def __init__(self) -> None:
        self._prompts: dict[str, Prompt] = {}

    def register(self, name: str, version: str, text: str) -> Prompt:
        if name in self._prompts:
            raise ValueError(f"prompt '{name}' already registered")
        prompt = Prompt(name=name, version=version, text=text.strip())
        self._prompts[name] = prompt
        return prompt

    def get(self, name: str) -> Prompt:
        if name not in self._prompts:
            raise KeyError(f"prompt '{name}' is not registered")
        return self._prompts[name]

    def names(self) -> list[str]:
        return sorted(self._prompts)

    def as_lock(self) -> dict[str, dict[str, str]]:
        """Serialise to the lock shape: {name: {version, sha256}}."""
        return {name: {"version": p.version, "sha256": p.sha256} for name, p in sorted(self._prompts.items())}

    def verify_against_lock(self, lock: dict[str, dict[str, str]]) -> list[str]:
        """Return a list of drift descriptions; empty means the lock is current.

        Fails on: a registered prompt missing from the lock, a lock entry with
        no registered prompt, a content hash that changed while the version
        stayed the same (the dangerous case), or a version that moved without a
        lock update.
        """
        drifts: list[str] = []
        current = self.as_lock()
        for name, entry in current.items():
            locked = lock.get(name)
            if locked is None:
                drifts.append(f"prompt '{name}' is registered but missing from the lock")
                continue
            if entry["version"] != locked.get("version"):
                drifts.append(f"prompt '{name}' version {locked.get('version')} → {entry['version']} — regenerate the lock")
            elif entry["sha256"] != locked.get("sha256"):
                drifts.append(
                    f"prompt '{name}' text changed WITHOUT a version bump "
                    f"(v{entry['version']}). Bump the version and re-grade the eval harness, then regenerate the lock."
                )
        for name in lock:
            if name not in current:
                drifts.append(f"lock has prompt '{name}' that is no longer registered")
        return drifts


# ── Canonical production prompts (source of truth) ───────────────────────────

_TRIAGE_SYSTEM = """
You are a SOC alert triage analyst. Classify the alert as one of:
true_positive, false_positive, or benign. Return strict JSON:
{"verdict": "...", "confidence": 0-100, "rationale": "..."}.
Reason only over the structured summary provided; never request raw logs.
"""

_SUMMARY_SYSTEM = """
You are a SOC incident summariser. Given a structured investigation bundle,
produce a concise analyst-facing summary. Do not invent evidence; cite only
fields present in the bundle. Return markdown, no preamble.
"""


def default_registry() -> PromptRegistry:
    """The registry as shipped. Bump a version when you change a prompt."""
    reg = PromptRegistry()
    reg.register("triage.system", "1", _TRIAGE_SYSTEM)
    reg.register("summary.system", "1", _SUMMARY_SYSTEM)
    return reg


def load_lock() -> dict[str, dict[str, str]]:
    if not LOCK_PATH.exists():
        return {}
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def write_lock(registry: PromptRegistry) -> None:
    LOCK_PATH.write_text(json.dumps(registry.as_lock(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
