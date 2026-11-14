"""Multi-backend translator: Sigma rule -> SPL / KQL / Lucene / Chronicle.

Every translator emits a *single search expression* — not a complete
query — so the caller can layer time windows, index selection, and
post-processing (stats/eval/project) on top.

Design notes:

- We translate from the SigmaRule's parsed AST, not from raw YAML.
  That means modifiers, wildcards, and condition logic are already
  validated.
- Field names are passed through unchanged. Vendor-specific field
  mapping (e.g. ``Image -> process_image``) is the job of an outer
  pipeline mapping config — not this layer. Keeping translators
  field-agnostic is what lets the same Sigma rule ship to a Splunk
  customer with CIM-normalized fields and a Sentinel customer with
  ASim-normalized fields, simply by swapping the mapping.
- Unsupported constructs (regex against KQL has good support, but
  base64offset doesn't translate cleanly anywhere) raise
  `BackendError` so the GitOps detection pipeline catches them
  before publishing the rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable

from .sigma import (
    SigmaRule,
    _AndNode,
    _FieldTest,
    _ListOfDictsTest,
    _NotNode,
    _OrNode,
    _QuantNode,
    _RefNode,
    _Selection,
)


class BackendError(ValueError):
    """Raised when a rule cannot be translated to a target backend."""


# --------------------------------------------------------------------------- #
# Splunk SPL
# --------------------------------------------------------------------------- #


def translate_splunk(rule: SigmaRule) -> str:
    """Translate a SigmaRule into a Splunk SPL search expression."""
    return _SplunkTranslator().translate(rule)


class _SplunkTranslator:
    def translate(self, rule: SigmaRule) -> str:
        sel_exprs = {name: self._selection(sel) for name, sel in rule.selections.items()}
        return self._condition(rule.condition, sel_exprs)

    # --- selections -----------------------------------------------------

    def _selection(self, sel: _Selection) -> str:
        if sel.keywords:
            return " OR ".join(_spl_quote(str(k)) for k in sel.keywords)
        clauses = [self._test(t) for t in sel.tests]
        if not clauses:
            return "true()"
        return " ".join(f"({c})" for c in clauses) if len(clauses) > 1 else clauses[0]

    def _test(self, t: _FieldTest) -> str:
        if isinstance(t, _ListOfDictsTest):
            parts = [self._selection(_subselection(t, i)) for i in t.items]
            return " OR ".join(f"({p})" for p in parts)

        field = t.field
        if "exists" in t.modifiers:
            present = bool(t.values[0]) if t.values else True
            return f"{field}=*" if present else f"NOT {field}=*"

        if "re" in t.modifiers:
            parts = [f"match({field}, {_spl_quote(str(v))})" for v in t.values]
            joiner = " AND " if "all" in t.modifiers else " OR "
            return "(" + joiner.join(f"| where {p}" for p in parts) + ")" if False else (
                joiner.join(parts)
            )

        if "cidr" in t.modifiers:
            parts = [f"cidrmatch({_spl_quote(str(v))}, {field})" for v in t.values]
            joiner = " AND " if "all" in t.modifiers else " OR "
            return joiner.join(parts)

        if any(m in t.modifiers for m in ("gt", "gte", "lt", "lte")):
            op = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[
                next(m for m in t.modifiers if m in ("gt", "gte", "lt", "lte"))
            ]
            joiner = " AND " if "all" in t.modifiers else " OR "
            return joiner.join(f"{field}{op}{_spl_lit(v)}" for v in t.values)

        # String / equality / wildcard / contains.
        parts: list[str] = []
        for v in t.values:
            if v is None:
                parts.append(f"NOT {field}=*")
                continue
            if not isinstance(v, str):
                parts.append(f"{field}={_spl_lit(v)}")
                continue
            sv = v
            if "contains" in t.modifiers:
                sv = "*" + sv + "*"
            elif "startswith" in t.modifiers:
                sv = sv + "*"
            elif "endswith" in t.modifiers:
                sv = "*" + sv
            parts.append(f"{field}={_spl_quote(sv)}")
        joiner = " AND " if "all" in t.modifiers else " OR "
        return joiner.join(parts) if parts else "false()"

    # --- condition AST --------------------------------------------------

    def _condition(self, node: Any, sels: dict[str, str]) -> str:
        if isinstance(node, _RefNode):
            return f"({sels[node.name]})"
        if isinstance(node, _NotNode):
            return f"NOT ({self._condition(node.inner, sels)})"
        if isinstance(node, _AndNode):
            return "(" + " AND ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _OrNode):
            return "(" + " OR ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _QuantNode):
            joiner = " AND " if node.quantifier == "all" else " OR "
            return "(" + joiner.join(f"({sels[t]})" for t in node.targets) + ")"
        raise BackendError(f"splunk: unsupported condition node {type(node).__name__}")


def _spl_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _spl_lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return _spl_quote(str(v))


# --------------------------------------------------------------------------- #
# Microsoft Sentinel KQL
# --------------------------------------------------------------------------- #


def translate_kql(rule: SigmaRule) -> str:
    """Translate a SigmaRule into a KQL ``where`` predicate expression."""
    return _KQLTranslator().translate(rule)


class _KQLTranslator:
    def translate(self, rule: SigmaRule) -> str:
        sel_exprs = {name: self._selection(sel) for name, sel in rule.selections.items()}
        return self._condition(rule.condition, sel_exprs)

    def _selection(self, sel: _Selection) -> str:
        if sel.keywords:
            return " or ".join(
                f'(* contains "{_kql_esc(str(k))}")' for k in sel.keywords
            )
        clauses = [self._test(t) for t in sel.tests]
        if not clauses:
            return "true"
        return " and ".join(f"({c})" for c in clauses)

    def _test(self, t: _FieldTest) -> str:
        if isinstance(t, _ListOfDictsTest):
            parts = [self._selection(_subselection(t, i)) for i in t.items]
            return " or ".join(f"({p})" for p in parts)

        field = t.field

        if "exists" in t.modifiers:
            present = bool(t.values[0]) if t.values else True
            return f"isnotempty({field})" if present else f"isempty({field})"

        if "re" in t.modifiers:
            parts = [f'{field} matches regex "{_kql_esc(str(v))}"' for v in t.values]
        elif "cidr" in t.modifiers:
            parts = [f'ipv4_is_in_range({field}, "{_kql_esc(str(v))}")' for v in t.values]
        elif any(m in t.modifiers for m in ("gt", "gte", "lt", "lte")):
            op = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[
                next(m for m in t.modifiers if m in ("gt", "gte", "lt", "lte"))
            ]
            parts = [f"{field} {op} {_kql_lit(v)}" for v in t.values]
        else:
            parts = []
            for v in t.values:
                if v is None:
                    parts.append(f"isnull({field})")
                    continue
                if isinstance(v, str):
                    if "contains" in t.modifiers:
                        parts.append(f'{field} contains "{_kql_esc(v)}"')
                    elif "startswith" in t.modifiers:
                        parts.append(f'{field} startswith "{_kql_esc(v)}"')
                    elif "endswith" in t.modifiers:
                        parts.append(f'{field} endswith "{_kql_esc(v)}"')
                    elif any(ch in v for ch in "*?"):
                        # Translate Sigma wildcards to KQL `matches regex`.
                        parts.append(
                            f'{field} matches regex "{_kql_esc(_wildcard_to_regex_str(v))}"'
                        )
                    else:
                        parts.append(f'{field} =~ "{_kql_esc(v)}"')
                else:
                    parts.append(f"{field} == {_kql_lit(v)}")
        joiner = " and " if "all" in t.modifiers else " or "
        return joiner.join(parts) if parts else "false"

    def _condition(self, node: Any, sels: dict[str, str]) -> str:
        if isinstance(node, _RefNode):
            return f"({sels[node.name]})"
        if isinstance(node, _NotNode):
            return f"not ({self._condition(node.inner, sels)})"
        if isinstance(node, _AndNode):
            return "(" + " and ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _OrNode):
            return "(" + " or ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _QuantNode):
            joiner = " and " if node.quantifier == "all" else " or "
            return "(" + joiner.join(f"({sels[t]})" for t in node.targets) + ")"
        raise BackendError(f"kql: unsupported node {type(node).__name__}")


def _kql_esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _kql_lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return f'"{_kql_esc(str(v))}"'


# --------------------------------------------------------------------------- #
# Elastic Lucene
# --------------------------------------------------------------------------- #


def translate_lucene(rule: SigmaRule) -> str:
    """Translate a SigmaRule to an Elastic Lucene query string."""
    return _LuceneTranslator().translate(rule)


class _LuceneTranslator:
    def translate(self, rule: SigmaRule) -> str:
        sel_exprs = {name: self._selection(sel) for name, sel in rule.selections.items()}
        return self._condition(rule.condition, sel_exprs)

    def _selection(self, sel: _Selection) -> str:
        if sel.keywords:
            return " OR ".join(_lucene_quote(str(k)) for k in sel.keywords)
        clauses = [self._test(t) for t in sel.tests]
        if not clauses:
            return "*"
        return " AND ".join(f"({c})" for c in clauses)

    def _test(self, t: _FieldTest) -> str:
        if isinstance(t, _ListOfDictsTest):
            parts = [self._selection(_subselection(t, i)) for i in t.items]
            return " OR ".join(f"({p})" for p in parts)

        field = t.field
        if "exists" in t.modifiers:
            present = bool(t.values[0]) if t.values else True
            return f"_exists_:{field}" if present else f"NOT _exists_:{field}"

        if "re" in t.modifiers:
            parts = [f"{field}:/{_lucene_regex_esc(str(v))}/" for v in t.values]
            joiner = " AND " if "all" in t.modifiers else " OR "
            return joiner.join(parts)

        if "cidr" in t.modifiers:
            # Elastic supports CIDR via term query on ip fields, which in
            # Lucene syntax is just `field:"CIDR"`.
            parts = [f"{field}:{_lucene_quote(str(v))}" for v in t.values]
            joiner = " AND " if "all" in t.modifiers else " OR "
            return joiner.join(parts)

        if any(m in t.modifiers for m in ("gt", "gte", "lt", "lte")):
            mod = next(m for m in t.modifiers if m in ("gt", "gte", "lt", "lte"))
            parts: list[str] = []
            for v in t.values:
                lit = _lucene_lit(v)
                if mod == "gt":
                    parts.append(f"{field}:>{lit}")
                elif mod == "gte":
                    parts.append(f"{field}:>={lit}")
                elif mod == "lt":
                    parts.append(f"{field}:<{lit}")
                else:
                    parts.append(f"{field}:<={lit}")
            joiner = " AND " if "all" in t.modifiers else " OR "
            return joiner.join(parts)

        parts = []
        for v in t.values:
            if v is None:
                parts.append(f"NOT _exists_:{field}")
                continue
            if not isinstance(v, str):
                parts.append(f"{field}:{_lucene_lit(v)}")
                continue
            sv = v
            if "contains" in t.modifiers:
                sv = "*" + sv + "*"
            elif "startswith" in t.modifiers:
                sv = sv + "*"
            elif "endswith" in t.modifiers:
                sv = "*" + sv
            parts.append(f"{field}:{_lucene_value(sv)}")
        joiner = " AND " if "all" in t.modifiers else " OR "
        return joiner.join(parts) if parts else "(NOT *:*)"

    def _condition(self, node: Any, sels: dict[str, str]) -> str:
        if isinstance(node, _RefNode):
            return f"({sels[node.name]})"
        if isinstance(node, _NotNode):
            return f"NOT ({self._condition(node.inner, sels)})"
        if isinstance(node, _AndNode):
            return "(" + " AND ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _OrNode):
            return "(" + " OR ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _QuantNode):
            joiner = " AND " if node.quantifier == "all" else " OR "
            return "(" + joiner.join(f"({sels[t]})" for t in node.targets) + ")"
        raise BackendError(f"lucene: unsupported node {type(node).__name__}")


_LUCENE_RESERVED = r'+-=&|><!(){}[]^"~:\/'


def _lucene_value(s: str) -> str:
    # Wildcards (*, ?) must be preserved unescaped to retain meaning.
    out: list[str] = []
    for ch in s:
        if ch in ("*", "?"):
            out.append(ch)
        elif ch in _LUCENE_RESERVED or ch.isspace():
            out.append("\\" + ch)
        else:
            out.append(ch)
    return "".join(out)


def _lucene_quote(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _lucene_lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return _lucene_quote(str(v))


def _lucene_regex_esc(s: str) -> str:
    return s.replace("/", "\\/")


# --------------------------------------------------------------------------- #
# Google Chronicle (YARA-L 2.0 / UDM Search)
# --------------------------------------------------------------------------- #
#
# We emit a Chronicle UDM Search predicate expression. The same expression
# is also valid as the body of a YARA-L 2.0 ``events:`` block when each
# field reference is prefixed with the event variable (e.g. ``$e.``).
#
# Field references are emitted bare — the caller's mapping layer is
# responsible for prefixing the event variable when wrapping the
# expression in a YARA-L rule (see ``translate_chronicle_yaral`` for the
# helper that does this and wraps the rule body).


def translate_chronicle(rule: SigmaRule) -> str:
    """Translate a SigmaRule into a Chronicle UDM Search expression."""
    return _ChronicleTranslator().translate(rule)


def translate_chronicle_yaral(rule: SigmaRule, event_var: str = "e") -> str:
    """Translate a SigmaRule into a complete YARA-L 2.0 rule.

    The rule wraps the UDM Search predicate as a YARA-L ``events:``
    block, prefixing every field reference with ``$<event_var>.``. This
    is the form Chronicle Detection Engine expects when publishing a
    rule via the Backstory API.
    """
    body = _ChronicleTranslator(event_var=event_var).translate(rule)
    rule_name = _yaral_rule_name(rule.id, rule.title)
    severity_label = rule.severity.value.upper()
    tags_csv = ", ".join(f'"{_chronicle_str_esc(t)}"' for t in rule.tags) or '""'
    return (
        f"rule {rule_name} {{\n"
        f"  meta:\n"
        f'    author = "aisoc"\n'
        f'    description = "{_chronicle_str_esc(rule.title)}"\n'
        f'    severity = "{severity_label}"\n'
        f'    rule_id = "{_chronicle_str_esc(rule.id)}"\n'
        f"    tags = {tags_csv}\n"
        f"  events:\n"
        f"    {body}\n"
        f"  condition:\n"
        f"    ${event_var}\n"
        f"}}"
    )


class _ChronicleTranslator:
    """Emit a Chronicle UDM Search predicate from a parsed Sigma rule.

    When ``event_var`` is non-empty, field references are prefixed with
    ``$<event_var>.`` so the output can drop directly into a YARA-L 2.0
    ``events:`` block.
    """

    def __init__(self, event_var: str = "") -> None:
        self._prefix = f"${event_var}." if event_var else ""

    def translate(self, rule: SigmaRule) -> str:
        sel_exprs = {name: self._selection(sel) for name, sel in rule.selections.items()}
        return self._condition(rule.condition, sel_exprs)

    # --- selections -----------------------------------------------------

    def _selection(self, sel: _Selection) -> str:
        if sel.keywords:
            # UDM Search keyword form: `_raw_ = /kw/ nocase`. We use the
            # special bare-keyword form supported by Chronicle search:
            # quoted strings without a field do a full-event substring
            # match.
            return " or ".join(
                f'"{_chronicle_str_esc(str(k))}"' for k in sel.keywords
            )
        clauses = [self._test(t) for t in sel.tests]
        if not clauses:
            return "true"
        return " and ".join(f"({c})" for c in clauses)

    def _test(self, t: _FieldTest) -> str:
        if isinstance(t, _ListOfDictsTest):
            parts = [self._selection(_subselection(t, i)) for i in t.items]
            return " or ".join(f"({p})" for p in parts)

        field = f"{self._prefix}{t.field}"

        if "exists" in t.modifiers:
            present = bool(t.values[0]) if t.values else True
            return f'{field} != ""' if present else f'{field} = ""'

        if "re" in t.modifiers:
            parts = [
                f"{field} = /{_chronicle_regex_esc(str(v))}/ nocase" for v in t.values
            ]
            joiner = " and " if "all" in t.modifiers else " or "
            return joiner.join(parts)

        if "cidr" in t.modifiers:
            parts = [
                f'net.ip_in_range_cidr({field}, "{_chronicle_str_esc(str(v))}")'
                for v in t.values
            ]
            joiner = " and " if "all" in t.modifiers else " or "
            return joiner.join(parts)

        if any(m in t.modifiers for m in ("gt", "gte", "lt", "lte")):
            op = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[
                next(m for m in t.modifiers if m in ("gt", "gte", "lt", "lte"))
            ]
            parts = [f"{field} {op} {_chronicle_lit(v)}" for v in t.values]
            joiner = " and " if "all" in t.modifiers else " or "
            return joiner.join(parts)

        parts: list[str] = []
        for v in t.values:
            if v is None:
                parts.append(f'{field} = ""')
                continue
            if not isinstance(v, str):
                parts.append(f"{field} = {_chronicle_lit(v)}")
                continue
            sv = v
            if "contains" in t.modifiers:
                sv = "*" + sv + "*"
            elif "startswith" in t.modifiers:
                sv = sv + "*"
            elif "endswith" in t.modifiers:
                sv = "*" + sv
            if any(ch in sv for ch in "*?"):
                # Chronicle UDM Search expresses wildcard match via a
                # regex literal — wildcards inside quoted strings are
                # treated as literal characters in many surfaces, so we
                # compile to an anchored regex to guarantee correctness.
                parts.append(
                    f"{field} = /{_chronicle_regex_esc(_wildcard_to_regex_str(sv))}/ nocase"
                )
            else:
                parts.append(f'{field} = "{_chronicle_str_esc(sv)}" nocase')
        joiner = " and " if "all" in t.modifiers else " or "
        return joiner.join(parts) if parts else "false"

    def _condition(self, node: Any, sels: dict[str, str]) -> str:
        if isinstance(node, _RefNode):
            return f"({sels[node.name]})"
        if isinstance(node, _NotNode):
            return f"not ({self._condition(node.inner, sels)})"
        if isinstance(node, _AndNode):
            return "(" + " and ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _OrNode):
            return "(" + " or ".join(self._condition(p, sels) for p in node.parts) + ")"
        if isinstance(node, _QuantNode):
            joiner = " and " if node.quantifier == "all" else " or "
            return "(" + joiner.join(f"({sels[t]})" for t in node.targets) + ")"
        raise BackendError(f"chronicle: unsupported node {type(node).__name__}")


def _chronicle_str_esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _chronicle_regex_esc(s: str) -> str:
    return s.replace("/", "\\/")


def _chronicle_lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return f'"{_chronicle_str_esc(str(v))}"'


_YARAL_NAME_BAD = re.compile(r"[^A-Za-z0-9_]+")


def _yaral_rule_name(rule_id: str, title: str) -> str:
    """Build a YARA-L 2.0 rule identifier.

    YARA-L identifiers must match ``[A-Za-z_][A-Za-z0-9_]*``. We prefer
    the rule id when it's clean, and fall back to a slugged title.
    """
    candidate = _YARAL_NAME_BAD.sub("_", rule_id or "").strip("_")
    if not candidate or not candidate[0].isalpha():
        candidate = "rule_" + (_YARAL_NAME_BAD.sub("_", title).strip("_") or "anon")
    return candidate[:200]


# --------------------------------------------------------------------------- #
# Shared helpers
# --------------------------------------------------------------------------- #


def _wildcard_to_regex_str(s: str) -> str:
    """Convert a Sigma wildcard pattern to an anchored regex source."""
    out: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s) and s[i + 1] in ("*", "?"):
            out.append(re.escape(s[i + 1]))
            i += 2
            continue
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
        i += 1
    return "^" + "".join(out) + "$"


def _subselection(t: _ListOfDictsTest, item: dict[str, Any]) -> _Selection:
    """Build a _Selection from one entry of a list-of-dicts selection.

    Used by translators to emit OR'd alternatives in the target query
    language without re-parsing the YAML.
    """
    from .sigma import _parse_selection

    return _parse_selection(t.name, item, source=t.source or "<translate>")


# --------------------------------------------------------------------------- #
# Front door
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class TranslatedRule:
    """A rule translated to one or more backends.

    Includes the rule metadata so a downstream "publish to Splunk ES /
    Sentinel Analytics Rules" job has everything it needs to render a
    proper alert object.
    """

    rule_id: str
    title: str
    severity: str
    tags: tuple[str, ...]
    spl: str
    kql: str
    lucene: str
    chronicle: str
    chronicle_yaral: str


def translate(rule: SigmaRule) -> TranslatedRule:
    """Translate a rule to all supported backends.

    Backends that fail to translate raise BackendError immediately —
    the caller (typically `app/detections/__init__.py` consumers or a
    GitOps publishing job) decides whether to swallow that or fail the
    build.
    """
    return TranslatedRule(
        rule_id=rule.id,
        title=rule.title,
        severity=rule.severity.value,
        tags=rule.tags,
        spl=translate_splunk(rule),
        kql=translate_kql(rule),
        lucene=translate_lucene(rule),
        chronicle=translate_chronicle(rule),
        chronicle_yaral=translate_chronicle_yaral(rule),
    )


__all__ = [
    "translate",
    "translate_splunk",
    "translate_kql",
    "translate_lucene",
    "translate_chronicle",
    "translate_chronicle_yaral",
    "TranslatedRule",
    "BackendError",
]


# Tell the linter we use `Iterable`.
_ = Iterable
