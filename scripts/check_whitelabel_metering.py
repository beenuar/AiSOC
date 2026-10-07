#!/usr/bin/env python3
"""Two claims that decay quietly: a sanitiser's allowlist, and a meter's honesty.

Why an allowlist needs a gate
------------------------------
`ALLOWED_ELEMENTS` in the SVG sanitiser is one line away from being useless.
The pressure on it is real and sympathetic: an operator's logo does not render
the way it did in their graphics program, somebody traces it to a dropped
element, and the smallest change that fixes the complaint is to add that
element to the list. If the element is `foreignObject`, `use`, `style` or
`script`, the sanitiser is now a function that returns its input.

The unit tests cover the payloads somebody thought of. This covers the
*shape*: no element or attribute that can execute, fetch or reference another
document may enter the allowlist, whatever the reason.

Why a meter needs a gate
-------------------------
Two of this repository's console figures were wrong on real data while their
tests passed, because each test compared a producer against a copy of itself.
The metering tests avoid that by counting rows independently. What they cannot
see is a *new* meter added later with the tenant formatted into its SQL, or a
meter that quietly starts doing arithmetic on a price.

So this reads the declarations:

* every meter binds the tenant as a parameter and never formats one in;
* no meter carries pricing vocabulary, because 13.3 says metering and the
  commercial question belongs elsewhere;
* a meter that cannot be measured on this deployment is named with a reason
  and is *not* also declared as a meter, so it can never be reported as zero.

Run:  python3 scripts/check_whitelabel_metering.py [--self-test]
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

REPO_ROOT = repo_root()

SANITIZER = REPO_ROOT / "services/api/app/services/branding/svg_sanitizer.py"
RESOLVER = REPO_ROOT / "services/api/app/services/branding/resolver.py"
METERING = REPO_ROOT / "services/api/app/services/usage_metering.py"

#: Elements that execute, embed foreign content, or reference another
#: document. None may ever be allowed, whatever a rendering complaint says.
FORBIDDEN_ELEMENTS: frozenset[str] = frozenset(
    {
        "script",
        "foreignObject",
        "foreignobject",
        "use",
        "image",
        "style",
        "a",
        "animate",
        "animateTransform",
        "animateMotion",
        "set",
        "handler",
        "iframe",
        "embed",
        "object",
        "audio",
        "video",
        "feImage",
    }
)

#: Attributes that name a URL or carry behaviour. Event handlers are excluded
#: by shape (anything starting `on`) rather than by enumeration, because the
#: list of them grows.
FORBIDDEN_ATTRIBUTES: frozenset[str] = frozenset({"href", "xlink:href", "style", "filter", "from", "to", "values", "begin"})

#: Words that mean somebody started computing what usage is worth.
PRICING_WORDS: frozenset[str] = frozenset({"price", "rate_card", "invoice", "unit_cost", "plan_cost", "billing_amount"})


def _module_constant(tree: ast.Module, name: str) -> object | None:
    for node in tree.body:
        targets: list[str] = []
        value: ast.expr | None = None
        if isinstance(node, ast.Assign):
            targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            targets = [node.target.id]
            value = node.value
        if name not in targets or value is None:
            continue
        # `frozenset({...})` and `tuple(...)` wrap the literal this needs.
        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in {"frozenset", "tuple", "set"}:
            value = value.args[0] if value.args else value
        try:
            return ast.literal_eval(value)
        except (ValueError, TypeError, SyntaxError):
            return None
    return None


def _meters(tree: ast.Module, name: str) -> list[dict[str, str]]:
    """Every ``Meter(...)`` in one module-level tuple, as field dicts."""
    found: list[dict[str, str]] = []
    for node in tree.body:
        target = None
        value: ast.expr | None = None
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target.id, node.value
        elif isinstance(node, ast.Assign):
            names = [t.id for t in node.targets if isinstance(t, ast.Name)]
            target, value = (names[0] if names else None), node.value
        if target != name or value is None:
            continue
        for call in ast.walk(value):
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Name) or call.func.id != "Meter":
                continue
            fields: dict[str, str] = {}
            for index, arg in enumerate(call.args):
                key = ("key", "label", "description", "source", "sql")[index] if index < 5 else str(index)
                # A constant that is not a string goes through `_join` rather
                # than into a `dict[str, str]`; the fields this reads are
                # string literals, and a number here means the file changed
                # shape, not that the gate should carry a non-string.
                fields[key] = arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else _join(arg)
            for kw in call.keywords:
                if kw.arg:
                    fields[kw.arg] = (
                        kw.value.value if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str) else _join(kw.value)
                    )
            found.append(fields)
    return found


def _join(node: ast.expr) -> str:
    """Flatten an implicitly concatenated string literal."""
    parts: list[str] = []
    for inner in ast.walk(node):
        if isinstance(inner, ast.Constant) and isinstance(inner.value, str):
            parts.append(inner.value)
    return " ".join(parts)


def audit(root: Path) -> tuple[list[str], dict[str, int]]:
    problems: list[str] = []
    counts = {"allowed_elements": 0, "allowed_attributes": 0, "meters": 0}

    sanitizer = root / SANITIZER.relative_to(REPO_ROOT)
    resolver = root / RESOLVER.relative_to(REPO_ROOT)
    metering = root / METERING.relative_to(REPO_ROOT)

    missing = [p for p in (sanitizer, resolver, metering) if not p.is_file()]
    if missing:
        problems.append("white-label or metering modules are absent: " + ", ".join(str(p.relative_to(root)) for p in missing))
        return problems, counts

    # --- the SVG allowlist has not been widened -------------------------
    sanitizer_tree = ast.parse(sanitizer.read_text(encoding="utf-8"))
    elements = _module_constant(sanitizer_tree, "ALLOWED_ELEMENTS")
    attributes = _module_constant(sanitizer_tree, "ALLOWED_ATTRIBUTES")

    if not isinstance(elements, (set, frozenset, list, tuple)) or not isinstance(attributes, (set, frozenset, list, tuple)):
        problems.append("the SVG allowlists are no longer literals this gate can read")
    else:
        counts["allowed_elements"] = len(elements)
        counts["allowed_attributes"] = len(attributes)
        for element in sorted(set(elements) & FORBIDDEN_ELEMENTS):
            problems.append(
                f"ALLOWED_ELEMENTS contains {element!r}, which can execute, embed foreign content or reference "
                "another document. An uploaded logo renders in the console and inside PDF reports other people open."
            )
        for attribute in sorted(set(attributes) & FORBIDDEN_ATTRIBUTES):
            problems.append(f"ALLOWED_ATTRIBUTES contains {attribute!r}, which names a URL or carries behaviour")
        for attribute in sorted(a for a in attributes if isinstance(a, str) and a.lower().startswith("on")):
            problems.append(f"ALLOWED_ATTRIBUTES contains the event handler {attribute!r}")

    # --- a brand asset is never a remote reference ----------------------
    resolver_source = resolver.read_text(encoding="utf-8")
    for line_number, line in enumerate(resolver_source.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") or "logo" not in stripped.lower():
            continue
        if "http://" in stripped or "https://" in stripped:
            problems.append(
                f"{RESOLVER.name}:{line_number} builds a logo reference containing a remote scheme. "
                "A remote logo is an outbound request made by the console and by the server-side PDF renderer."
            )

    # --- the meters stay honest ----------------------------------------
    metering_tree = ast.parse(metering.read_text(encoding="utf-8"))
    meters = _meters(metering_tree, "METERS") + _meters(metering_tree, "POINT_IN_TIME_METERS")
    counts["meters"] = len(meters)

    for meter in meters:
        key = meter.get("key", "<unnamed>")
        sql = meter.get("sql", "")
        if ":tenant_id" not in sql and ":tenant_text" not in sql:
            problems.append(f"meter {key!r} does not bind a tenant parameter, so it counts every tenant's rows")
        if "%s" in sql or ".format(" in sql or 'f"' in sql:
            problems.append(f"meter {key!r} formats a value into its SQL instead of binding it")
        # Key, label and SQL only. `description` is prose, and the honest
        # description of `llm_cost_usd` has to be able to say "not a price"
        # — a gate that forbids the word forbids the disclaimer with it.
        # Pricing logic would live in a column name or a computation, which
        # is what these three fields hold.
        haystack = f"{key} {meter.get('label', '')} {sql}".lower()
        for word in sorted(PRICING_WORDS):
            if word in haystack:
                problems.append(f"meter {key!r} mentions {word!r}; 13.3 is metering, and pricing belongs elsewhere")

    # The meters a deployment may be unable to take. `events_ingested` is a
    # ClickHouse count, so it is a meter on the `full` profile and a named
    # gap without it — never a zero either way.
    unmeasured = _module_constant(metering_tree, "UNMEASURABLE_WITHOUT")
    if isinstance(unmeasured, dict):
        declared = {m.get("key") for m in meters}
        for key, reason in unmeasured.items():
            if key in declared:
                problems.append(
                    f"{key!r} is declared both as a Postgres meter and as possibly unmeasured. One of the two will "
                    "report a number from the wrong store, and a reader cannot tell which."
                )
            if not reason:
                problems.append(f"{key!r} is unmeasured with no reason, so a reader cannot tell a gap from a zero")
    else:
        problems.append("UNMEASURABLE_WITHOUT is no longer a literal this gate can read")

    return problems, counts


def _self_test_cases() -> list[tuple[str, bool]]:
    import shutil
    import tempfile

    cases: list[tuple[str, bool]] = []
    clean, _ = audit(REPO_ROOT)
    cases.append(("the real tree passes", not clean))

    mutations = [
        (
            "widening the allowlist to a script-capable element is reported",
            SANITIZER,
            '        "svg",\n',
            '        "svg",\n        "foreignObject",\n',
        ),
        ("allowing an event handler attribute is reported", SANITIZER, '        "id",\n', '        "id",\n        "onload",\n'),
        (
            "a meter with no tenant binding is reported",
            METERING,
            '"SELECT count(*) FROM alerts WHERE tenant_id = :tenant_id AND created_at >= :start AND created_at < :end"',
            '"SELECT count(*) FROM alerts WHERE created_at >= :start AND created_at < :end"',
        ),
        (
            "a remote logo reference is reported",
            RESOLVER,
            'logo_url = f"/api/v1/branding/assets/{asset[0]}" if asset else None',
            'logo_url = f"https://cdn.example/logos/{asset[0]}" if asset else None',
        ),
    ]

    for description, target, old, new in mutations:
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "tree"
            for source in {SANITIZER, RESOLVER, METERING}:
                destination = tree / source.relative_to(REPO_ROOT)
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, destination)
            patched = tree / target.relative_to(REPO_ROOT)
            text = patched.read_text(encoding="utf-8")
            if old not in text:
                cases.append((f"{description} (self-test anchor missing; case did not run)", False))
                continue
            patched.write_text(text.replace(old, new, 1), encoding="utf-8")
            problems, _ = audit(tree)
            cases.append((description, bool(problems)))

    return cases


def main() -> int:
    if SELF_TEST_FLAG in sys.argv[1:]:
        return self_test_main(Path(__file__).name, extra=_self_test_cases())

    problems, counts = audit(REPO_ROOT)
    print(
        f"check_whitelabel_metering: read {counts['allowed_elements']} allowed SVG element(s), "
        f"{counts['allowed_attributes']} allowed attribute(s) and {counts['meters']} meter(s)"
    )

    if counts["allowed_elements"] == 0 or counts["meters"] == 0:
        print(
            "\nFAIL: the allowlist or the meter set read as empty. A clean result over nothing is indistinguishable from a wrong root.",
            file=sys.stderr,
        )
        return 2

    if problems:
        print(f"\nFAIL: {len(problems)} finding(s).", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print("OK: the SVG allowlist admits nothing executable, assets stay local, and every meter binds its tenant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
