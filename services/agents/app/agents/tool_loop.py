"""Re-export of the tool-calling loop, which now lives in ``app.llm``.

Kept so existing imports keep working. The implementation moved because
importing it from here executes ``app/agents/__init__.py``, which imports
every agent module — so an agent that wanted the loop imported itself.
"""

from __future__ import annotations

from app.llm.tool_loop import _content, run_with_tools

# Deliberately only the public callables. Re-exporting module internals
# such as ``safe_ainvoke`` would let a test monkey-patch this name and
# pass while patching nothing, since the loop resolves it from its own
# module. Patch app.llm.tool_loop instead.
__all__ = ["run_with_tools", "_content"]
