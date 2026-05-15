"""Static regression gate for the LLM input contract (T2.3).

Rule: nothing in ``services/agents/app/`` may call ``.ainvoke(...)`` or
``.astream(...)`` directly on an LLM. All LLM calls MUST go through
:func:`app.llm.contract.safe_ainvoke`, :func:`app.llm.contract.safe_astream`,
or :func:`app.llm.contract.make_safe_chat_model`.

The check is intentionally textual-AST (not type-aware) because LangChain
chat models are not nominally typed. We rely on a *receiver allowlist*:
calls like ``self._graph.ainvoke(...)`` and ``investigation_graph.ainvoke(...)``
are LangGraph control-flow primitives, not LLM invocations, and are listed
explicitly so a reviewer notices when the allowlist grows.

To add a new permitted receiver name, append to ``_ALLOWED_RECEIVERS`` with
a short justification comment. To exempt an entire file (because the file
itself implements the wrapper), append to ``_ALLOWED_FILES``.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_AGENTS_APP = Path(__file__).resolve().parent.parent / "app"

# Receivers that are NOT chat models. Each entry MUST be explained.
_ALLOWED_RECEIVERS: frozenset[str] = frozenset(
    {
        # LangGraph compiled graph — control-flow, not an LLM. Used in
        # services/agents/app/investigator/orchestrator.py via self._graph.
        "_graph",
        # Module-level LangGraph handle in services/agents/app/api/router.py.
        "investigation_graph",
        # Generic LangGraph handles. If someone wires a graph elsewhere we
        # still don't want to flag it. Keep tight — add new names only when
        # the call site is reviewed as control-flow, not an LLM call.
        "graph",
    }
)

# Files where direct ``llm.ainvoke``/``llm.astream`` IS the implementation of
# the safe wrapper itself. The wrapper validates messages first, then
# delegates — so these calls are by construction safe.
_ALLOWED_FILES: frozenset[Path] = frozenset(
    {
        _AGENTS_APP / "llm" / "contract.py",
    }
)

_METHODS = {"ainvoke", "astream"}


def _receiver_name(node: ast.Attribute) -> str:
    """Best-effort receiver identifier for ``X.method(...)``.

    For ``self._graph.ainvoke(...)`` → ``_graph``.
    For ``investigation_graph.ainvoke(...)`` → ``investigation_graph``.
    For ``some_func().ainvoke(...)`` → ``<call>`` (we treat as unknown and flag).
    """
    value = node.value
    if isinstance(value, ast.Attribute):
        return value.attr
    if isinstance(value, ast.Name):
        return value.id
    return f"<{type(value).__name__}>"


def _find_bypasses(path: Path) -> list[tuple[int, str, str]]:
    """Return (lineno, receiver, method) tuples for forbidden calls in ``path``."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    findings: list[tuple[int, str, str]] = []

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute):
            continue
        if func.attr not in _METHODS:
            continue
        receiver = _receiver_name(func)
        if receiver in _ALLOWED_RECEIVERS:
            continue
        findings.append((node.lineno, receiver, func.attr))
    return findings


def _python_sources() -> list[Path]:
    return [
        p
        for p in _AGENTS_APP.rglob("*.py")
        if "__pycache__" not in p.parts and p not in _ALLOWED_FILES
    ]


def test_no_direct_ainvoke_or_astream_bypass() -> None:
    """No file under services/agents/app/ may call .ainvoke/.astream directly on an LLM."""
    violations: list[str] = []
    for path in _python_sources():
        for lineno, receiver, method in _find_bypasses(path):
            rel = path.relative_to(_AGENTS_APP.parent)
            violations.append(f"{rel}:{lineno}  {receiver}.{method}(...)")

    assert not violations, (
        "Direct LLM `.ainvoke`/`.astream` call detected — route through "
        "app.llm.contract.safe_ainvoke / safe_astream / make_safe_chat_model. "
        "If the receiver is genuinely not an LLM (e.g. a LangGraph compiled "
        "graph), add its name to _ALLOWED_RECEIVERS in this test with a "
        "justification comment.\n  "
        + "\n  ".join(violations)
    )


def test_gate_detects_synthetic_bypass(tmp_path: Path) -> None:
    """Sanity-check the AST walker: a fake bypass file must trip the detector."""
    fake = tmp_path / "fake_agent.py"
    fake.write_text(
        "class Foo:\n"
        "    async def run(self, llm):\n"
        "        return await llm.ainvoke([{'role': 'user', 'content': 'hi'}])\n",
        encoding="utf-8",
    )
    findings = _find_bypasses(fake)
    assert findings, "AST walker failed to flag a synthetic llm.ainvoke bypass"
    assert findings[0][1] == "llm"
    assert findings[0][2] == "ainvoke"


def test_gate_respects_receiver_allowlist(tmp_path: Path) -> None:
    """Calls on whitelisted receivers (e.g. _graph) must NOT be flagged."""
    fake = tmp_path / "fake_graph.py"
    fake.write_text(
        "class Orch:\n"
        "    def __init__(self):\n"
        "        self._graph = object()\n"
        "    async def run(self):\n"
        "        return await self._graph.ainvoke({'x': 1})\n",
        encoding="utf-8",
    )
    findings = _find_bypasses(fake)
    assert findings == [], f"allowlisted receiver should not trip the gate; got {findings}"
