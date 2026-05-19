"""Line-oriented serialization for LLM prompts (T2.1 / T2.3).

Avoid ``json.dumps`` of alert-shaped dicts in user-visible prompt text:
``classify_message`` treats the final string and can false-positive on
OCSF-like patterns. Prefer shallow key–value lines and blocked-key redaction.
"""

from __future__ import annotations

from typing import Any

from app.llm.contract import CONTRACT_DICT_KEY_BLOCKLIST


def _format_primitive(v: Any) -> str:
    if v is None:
        return "(null)"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int | float):
        return str(v)
    s = str(v).replace("\r", " ").replace("\n", " ")
    if len(s) > 400:
        return s[:400] + "…"
    return s


def format_extra_fields_for_llm(
    extra: dict[str, Any],
    *,
    max_keys: int = 12,
    max_depth: int = 2,
) -> str:
    """Format a flat-ish dict as newline-separated ``key: value`` lines."""
    if not extra:
        return "(none)"
    lines: list[str] = []
    keys = sorted(extra.keys(), key=str)
    omitted = 0
    for k in keys:
        if len(lines) >= max_keys:
            omitted = len(keys) - len(lines)
            break
        if str(k) in CONTRACT_DICT_KEY_BLOCKLIST:
            lines.append(f"{k}: <redacted: contract key>")
            continue
        v = extra[k]
        if isinstance(v, dict):
            lines.append(f"{k}:\n{summarize_structure_for_llm(v, label=str(k), max_lines=10, max_depth=max_depth)}")
        elif isinstance(v, list | tuple):
            lines.append(f"{k}:\n{summarize_structure_for_llm(list(v), label=str(k), max_lines=10, max_depth=max_depth)}")
        else:
            lines.append(f"{k}: {_format_primitive(v)}")
    if omitted > 0:
        lines.append(f"… and {omitted} more keys omitted")
    return "\n".join(lines)


def summarize_structure_for_llm(
    obj: Any,
    *,
    label: str = "data",
    max_lines: int = 40,
    max_depth: int = 2,
) -> str:
    """Summarize nested dict/list structures without emitting raw OCSF JSON."""
    out: list[str] = []

    def add(line: str) -> None:
        if len(out) < max_lines:
            out.append(line)

    def visit(node: Any, path: str, depth: int) -> None:
        if len(out) >= max_lines:
            return
        if depth > max_depth:
            add(f"{path}: <nested, depth cap>")
            return
        if isinstance(node, dict):
            keys = [k for k in node if str(k) not in CONTRACT_DICT_KEY_BLOCKLIST]
            if not keys:
                add(f"{path}: <dict (keys redacted)>")
                return
            for k in sorted(keys, key=str)[:30]:
                if len(out) >= max_lines:
                    break
                v = node[k]
                sub = f"{path}.{k}" if path else str(k)
                if isinstance(v, dict):
                    nk = len([x for x in v if str(x) not in CONTRACT_DICT_KEY_BLOCKLIST])
                    add(f"{sub}: dict({nk} keys)")
                    if depth < max_depth and nk <= 12:
                        visit(v, sub, depth + 1)
                elif isinstance(v, list | tuple):
                    add(f"{sub}: list[{len(v)} items]")
                    if depth < max_depth:
                        cap = min(5, len(v))
                        for i in range(cap):
                            visit(v[i], f"{sub}[{i}]", depth + 1)
                        if len(v) > cap:
                            add(f"{sub}: … {len(v) - cap} more items omitted")
                else:
                    add(f"{sub}: {_format_primitive(v)}")
        elif isinstance(node, list | tuple):
            add(f"{path}: list[{len(node)}]")
            if depth < max_depth:
                for i, it in enumerate(node[:6]):
                    visit(it, f"{path}[{i}]", depth + 1)
                if len(node) > 6:
                    add(f"{path}: … {len(node) - 6} more items omitted")
        else:
            add(f"{path}: {_format_primitive(node)}")

    visit(obj, label, 0)
    return "\n".join(out) if out else "(empty)"
