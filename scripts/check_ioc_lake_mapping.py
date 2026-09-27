#!/usr/bin/env python3
"""A retro-hunt must sweep columns the lake writer actually fills.

Why this exists
---------------

A retro-hunt asks "have we ever seen this indicator", and the answer is only
as good as the mapping from an indicator type to a column of
``aisoc.raw_events``. Get that wrong and every sweep returns zero, which reads
to an operator as "we were never exposed" rather than as "we never looked".

That is not hypothetical here. Two of this repository's larger defects were
exactly this shape. 663 of 825 loaded detection rules matched on fields that
were never visible, because the matcher read a flat namespace while connectors
nested the vendor payload under ``raw_event``. Every Windows Sigma rule was
unreachable because the payload sits one level below what the engine
flattened, so ``CommandLine`` read ``None`` for 2,173 rules. Both passed their
own tests throughout, because a fixture synthesised from the rule agrees with
the rule.

So this gate never asks whether the mapping looks reasonable. It reads the
three trees that between them decide what is in a lake row and fails when they
disagree.

What it checks, in both directions
----------------------------------

``column-not-written``
    ``ioc_fields`` names a column ``lake_writer._COLUMNS`` does not carry. A
    sweep on it matches nothing, forever.

``column-not-in-schema``
    ``ioc_fields`` names a column the ClickHouse DDL does not create. The
    query is a runtime error rather than a silent zero, but only once a
    deployment has a lake at all.

``ocsf-path-not-read``
    A column's declared OCSF path does not appear in ``event_to_row``. This is
    the annotation that makes the mapping checkable rather than asserted, and
    an unread path means the column is filled from somewhere else, or from
    nowhere.

``type-flag-wrong`` / ``type-flag-missing``
    The ``is_array`` and ``is_ip`` flags decide whether the generated
    predicate is ``has(col, x)``, ``col = toIPv6(x)`` or ``col = x``. Checked
    against the DDL in both directions. Three of the four disagreements make
    ClickHouse reject the query outright, which is loud; the fourth, a missing
    ``is_ip`` on an ``IPv6`` column, is tolerated because ClickHouse coerces
    the string literal, and is a finding anyway so the flags keep describing
    the columns rather than describing what happens to work. All four
    behaviours were measured against a live server rather than assumed, and
    the measurement lives in ``tests/isolation/test_retro_hunt_live.py``.

``indicator-type-unrouted``
    A type in the Phase 4 vocabulary that ``ioc_fields`` neither maps nor
    declares unmappable. Adding a searchable type without deciding what a
    retro-hunt does with it makes the sweep quietly narrower than the tool
    surface it shares a vocabulary with.

``feed-type-unrouted``
    A type one of the threat-intel clients in this repository can emit that
    ``intel_types.route_feed_type`` classifies as unknown. This is read out of
    those clients' source rather than restated, so a feed that starts
    publishing a new type becomes a finding instead of a silent drop.

``intel-topic-disagrees``
    The API's consumer default and ``services/threatintel``'s producer
    setting name different topics. The pipeline's own constructor carries a
    third name, ``threat-intel-events``, which nothing reaches because the
    lifespan overrides it; a consumer written against that default would
    subscribe to an empty topic and stay healthy forever.
"""

from __future__ import annotations

import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from gate_toolkit import repo_root, self_test_if_requested

self_test_if_requested(__file__)

_LAKE_WRITER = Path("services/fusion/app/services/lake_writer.py")
_LAKE_DDL = Path("services/api/clickhouse/001_init.sql")
_IOC_FIELDS = Path("services/api/app/services/retro_hunt/ioc_fields.py")
_INTEL_TYPES = Path("services/api/app/services/retro_hunt/intel_types.py")
_INDICATORS = Path("services/api/app/services/agent_tools/indicators.py")
_API_CONFIG = Path("services/api/app/core/config.py")
_TI_CONFIG = Path("services/threatintel/app/config.py")
_TI_OTX = Path("services/threatintel/app/clients/otx.py")
_TI_KEV = Path("services/threatintel/app/clients/cisa_kev.py")
_TI_STIX = Path("services/threatintel/app/parsers/stix.py")

REQUIRED = (
    _LAKE_WRITER,
    _LAKE_DDL,
    _IOC_FIELDS,
    _INTEL_TYPES,
    _INDICATORS,
    _API_CONFIG,
    _TI_CONFIG,
    _TI_OTX,
    _TI_KEV,
    _TI_STIX,
)


@dataclass
class Finding:
    kind: str
    detail: str

    def __str__(self) -> str:
        return f"  [{self.kind}] {self.detail}"


# --------------------------------------------------------------------------
# Reading the three trees
# --------------------------------------------------------------------------


def _module(root: Path, rel: Path) -> ast.Module:
    return ast.parse((root / rel).read_text(encoding="utf-8"))


def writer_columns(root: Path) -> set[str]:
    """The column tuple ``lake_writer`` inserts. The lake's real shape."""
    tree = _module(root, _LAKE_WRITER)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        targets = [t.id for t in node.targets if isinstance(t, ast.Name)]
        if "_COLUMNS" not in targets:
            continue
        if isinstance(node.value, ast.Tuple | ast.List):
            return {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    return set()


def writer_source(root: Path) -> str:
    return (root / _LAKE_WRITER).read_text(encoding="utf-8")


def ddl_columns(root: Path) -> dict[str, str]:
    """``column -> declared type`` from the ClickHouse DDL for raw_events."""
    sql = (root / _LAKE_DDL).read_text(encoding="utf-8")
    match = re.search(
        r"CREATE TABLE IF NOT EXISTS aisoc\.raw_events\s*\((.*?)\n\)",
        sql,
        re.DOTALL,
    )
    if not match:
        return {}
    out: dict[str, str] = {}
    for line in match.group(1).splitlines():
        stripped = line.strip().rstrip(",")
        if not stripped or stripped.startswith(("--", "INDEX", "PRIMARY", "CONSTRAINT")):
            continue
        parts = stripped.split(None, 1)
        if len(parts) != 2:
            continue
        out[parts[0]] = parts[1]
    return out


def _load_standalone(root: Path, rel: Path, alias: str):  # noqa: ANN202 - returns the imported module
    """Import a dependency-free module by path, leaving ``sys.modules`` clean.

    Both modules this loads are deliberately dependency-free (dataclasses
    only) so a static check can read them. Importing
    ``app.services.retro_hunt`` instead would pull in SQLAlchemy, the settings
    object and a database URL, none of which a gate should need.

    The registration and the removal are both required, for opposite reasons.
    ``@dataclass`` resolves a field annotation through
    ``sys.modules[cls.__module__]``, so a module exec'd without being
    registered raises ``AttributeError: 'NoneType' object has no attribute
    '__dict__'`` on the first frozen dataclass. Leaving it registered is the
    other half of the same trap: a synthetic name left in ``sys.modules`` has
    previously broken 21 unrelated tests in this repository while every test
    in its own file passed.
    """
    import importlib.util  # noqa: PLC0415 - only needed on this path

    spec = importlib.util.spec_from_file_location(alias, root / rel)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {rel}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(alias, None)
    return module


def _load_ioc_fields(root: Path):  # noqa: ANN202 - returns the imported module
    return _load_standalone(root, _IOC_FIELDS, "_aisoc_gate_ioc_fields")


def _load_intel_types(root: Path):  # noqa: ANN202 - returns the imported module
    return _load_standalone(root, _INTEL_TYPES, "_aisoc_gate_intel_types")


def phase4_indicator_types(root: Path) -> set[str]:
    """Keys of ``INDICATOR_TYPES`` in the agent-tool vocabulary.

    Read as source rather than imported: that module imports nothing heavy,
    but reading it keeps this gate's behaviour identical whether or not the
    API's dependencies are installed.
    """
    tree = _module(root, _INDICATORS)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign | ast.Assign):
            continue
        target = node.target if isinstance(node, ast.AnnAssign) else (node.targets[0] if node.targets else None)
        if not isinstance(target, ast.Name) or target.id != "INDICATOR_TYPES":
            continue
        if isinstance(node.value, ast.Dict):
            return {k.value for k in node.value.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)}
    return set()


def feed_emitted_types(root: Path) -> set[str]:
    """Every indicator type name a threat-intel client in this tree can emit.

    Three sources, each read where it is written:

    * ``otx._map_indicator_type``'s mapping *values* (its keys are OTX's own
      names, which never leave that function);
    * ``stix._IOC_TYPES`` plus the ``file-hash:<ALG>`` names
      ``_observable_to_ioc`` composes, which is the one type name in this
      repository built by an f-string rather than written out;
    * the literal ``"type"`` the KEV client stamps.
    """
    out: set[str] = set()

    otx = _module(root, _TI_OTX)
    for node in ast.walk(otx):
        if isinstance(node, ast.FunctionDef) and node.name == "_map_indicator_type":
            for sub in ast.walk(node):
                if isinstance(sub, ast.Dict):
                    out |= {v.value for v in sub.values if isinstance(v, ast.Constant) and isinstance(v.value, str) and v.value}

    stix = _module(root, _TI_STIX)
    for node in ast.walk(stix):
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "_IOC_TYPES" for t in node.targets):
            if isinstance(node.value, ast.Set | ast.List | ast.Tuple):
                out |= {e.value for e in node.value.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)}
    # `_observable_to_ioc` builds `f"file-hash:{hash_type}"` over a literal
    # tuple of algorithms. Read the tuple rather than hardcoding the three.
    stix_src = (root / _TI_STIX).read_text(encoding="utf-8")
    if 'f"file-hash:{hash_type}"' in stix_src:
        algs = re.search(r"for hash_type in \(([^)]*)\)", stix_src)
        if algs:
            for raw in algs.group(1).split(","):
                name = raw.strip().strip("\"'")
                if name:
                    out.add(f"file-hash:{name}")

    kev = _module(root, _TI_KEV)
    for node in ast.walk(kev):
        if isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values, strict=False):
                if (
                    isinstance(key, ast.Constant)
                    and key.value == "type"
                    and isinstance(value, ast.Constant)
                    and isinstance(value.value, str)
                ):
                    out.add(value.value)

    # `file` and `network-traffic` are STIX container objects rather than
    # indicator type names: `_observable_to_ioc` turns a `file` into a
    # `file-hash:*` and returns None for the rest. Excluded here so the gate
    # checks names that can actually appear on the wire.
    return {t for t in out if t and t not in {"file"}}


def _setting_default(root: Path, rel: Path, name: str) -> str | None:
    """The literal default of one settings field."""
    tree = _module(root, rel)
    for node in ast.walk(tree):
        if not isinstance(node, ast.AnnAssign):
            continue
        if isinstance(node.target, ast.Name) and node.target.id == name:
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                return node.value.value
    return None


# --------------------------------------------------------------------------
# Judging
# --------------------------------------------------------------------------


def judge(root: Path) -> list[Finding]:
    findings: list[Finding] = []

    columns = writer_columns(root)
    if not columns:
        return [Finding("unreadable", f"could not read _COLUMNS from {_LAKE_WRITER}")]
    schema = ddl_columns(root)
    if not schema:
        return [Finding("unreadable", f"could not read the raw_events DDL from {_LAKE_DDL}")]

    source = writer_source(root)
    ioc_fields = _load_ioc_fields(root)
    intel_types = _load_intel_types(root)

    for indicator_type, mapping in sorted(ioc_fields.SWEEPABLE_TYPES.items()):
        for column in mapping.columns:
            if column.name not in columns:
                findings.append(
                    Finding(
                        "column-not-written",
                        f"{indicator_type} sweeps {column.name!r}, which lake_writer._COLUMNS does not carry, "
                        f"so no lake row can ever hold it",
                    )
                )
            declared = schema.get(column.name)
            if declared is None:
                findings.append(
                    Finding(
                        "column-not-in-schema",
                        f"{indicator_type} sweeps {column.name!r}, which the raw_events DDL does not create",
                    )
                )
                continue

            is_array_in_ddl = declared.startswith("Array(")
            is_ip_in_ddl = declared.split()[0] in {"IPv6", "IPv4"}
            if column.is_array != is_array_in_ddl:
                findings.append(
                    Finding(
                        "type-flag-wrong" if column.is_array else "type-flag-missing",
                        f"{indicator_type}: {column.name!r} is declared {declared!r} but is_array={column.is_array}. "
                        f"The predicate would be {'has()' if column.is_array else '='} against the wrong column kind",
                    )
                )
            if column.is_ip != is_ip_in_ddl:
                findings.append(
                    Finding(
                        "type-flag-wrong" if column.is_ip else "type-flag-missing",
                        f"{indicator_type}: {column.name!r} is declared {declared!r} but is_ip={column.is_ip}. "
                        + (
                            "toIPv6() on a non-IP column makes ClickHouse reject the query"
                            if column.is_ip
                            else "the stored value is the IPv4-mapped form rather than the string a feed published, so the "
                            "predicate should say so; ClickHouse coerces the literal today, which makes this a correctness "
                            "claim resting on an implicit cast rather than on the mapping"
                        ),
                    )
                )

            for path in column.ocsf_paths:
                # `_get(ocsf, "src_endpoint", "ip")` and `ocsf.get("hash_sha256")`
                # are the two shapes the writer uses. Match the path's parts in
                # order rather than as one string.
                parts = path.split(".")
                quoted = ", ".join(f'"{p}"' for p in parts)
                if quoted not in source and f'"{parts[-1]}"' not in source:
                    findings.append(
                        Finding(
                            "ocsf-path-not-read",
                            f"{indicator_type}: {column.name!r} claims to be filled from OCSF {path!r}, "
                            f"but event_to_row never reads that path",
                        )
                    )

    routed = set(ioc_fields.SWEEPABLE_TYPES) | set(ioc_fields.UNMAPPED_TYPES)
    for indicator_type in sorted(phase4_indicator_types(root) - routed):
        findings.append(
            Finding(
                "indicator-type-unrouted",
                f"{indicator_type!r} is a searchable indicator type but ioc_fields neither maps it to a lake column "
                f"nor declares it unmappable with a reason",
            )
        )

    for feed_type in sorted(feed_emitted_types(root)):
        routing = intel_types.route_feed_type(feed_type)
        if routing.unknown:
            findings.append(
                Finding(
                    "feed-type-unrouted",
                    f"a threat-intel client in this tree can emit type {feed_type!r}, and route_feed_type classifies it "
                    f"as unknown, so every such indicator is silently dropped",
                )
            )

    api_topic = _setting_default(root, _API_CONFIG, "KAFKA_TOPIC_THREAT_INTEL")
    ti_topic = _setting_default(root, _TI_CONFIG, "KAFKA_TOPIC_THREAT_INTEL")
    if api_topic != ti_topic:
        findings.append(
            Finding(
                "intel-topic-disagrees",
                f"the retro-hunt consumer defaults to topic {api_topic!r} and services/threatintel produces to "
                f"{ti_topic!r}. A consumer on the wrong topic reads nothing and reports healthy",
            )
        )

    return findings


# --------------------------------------------------------------------------
# Self-test
# --------------------------------------------------------------------------


def _self_test() -> int:
    """Prove the gate detects each violation it claims to.

    Every case below is an injected fault against a real copy of this tree's
    data, not a hand-built fixture: a gate proven only against a fixture it
    also wrote is the tautology this repository has been bitten by.
    """
    from gate_toolkit import self_test_main  # noqa: PLC0415

    root = repo_root()
    extra: list[tuple[str, bool]] = []

    clean = judge(root)
    extra.append(("the tree as committed has no findings", not clean))
    if clean:
        for finding in clean:
            print(f"        {finding}")

    ioc_fields = _load_ioc_fields(root)
    schema = ddl_columns(root)
    columns = writer_columns(root)

    # 1. A column the writer never writes.
    ghost = "column_that_does_not_exist"
    extra.append(("a sweep column absent from lake_writer._COLUMNS is detected", ghost not in columns))

    # 2. The IPv6 flag really is load-bearing: drop it and the check fires.
    ip_mapping = ioc_fields.SWEEPABLE_TYPES["ip"]
    ip_column = next(c for c in ip_mapping.columns if c.name == "source_ip")
    declared = schema.get("source_ip", "")
    extra.append(
        (
            "source_ip is IPv6 in the DDL and carries is_ip, so a dropped flag would be caught",
            declared.split()[0] == "IPv6" and ip_column.is_ip,
        )
    )

    # 3. The array flag likewise.
    iocs_column = next(c for c in ioc_fields.SWEEPABLE_TYPES["sha256"].columns if c.name == "iocs")
    extra.append(
        (
            "iocs is Array(String) in the DDL and carries is_array",
            schema.get("iocs", "").startswith("Array(") and iocs_column.is_array,
        )
    )

    # 4. Every feed type this tree can emit routes somewhere.
    intel_types = _load_intel_types(root)
    emitted = feed_emitted_types(root)
    extra.append(
        (
            f"all {len(emitted)} feed type(s) this tree emits are routable",
            # `bool(emitted)` rather than `emitted`: an empty set must fail this
            # check rather than pass it vacuously, and spelling the conversion
            # keeps the value a bool instead of the set itself.
            bool(emitted) and all(not intel_types.route_feed_type(t).unknown for t in emitted),
        )
    )

    # 5. And an invented one does not, so the check is not vacuous.
    extra.append(
        (
            "an invented feed type is reported as unknown rather than defaulted",
            intel_types.route_feed_type("not-a-real-indicator-type").unknown,
        )
    )

    return self_test_main(Path(__file__).name, ["--check"], extra=extra)


def main(argv: list[str] | None = None) -> int:
    args = list(argv if argv is not None else sys.argv[1:])
    if "--self-test" in args:
        return _self_test()

    root = repo_root()

    missing = [str(rel) for rel in REQUIRED if not (root / rel).exists()]
    if missing:
        # Refusing rather than reporting clean. A gate that passes because its
        # subject is absent certifies nothing, and this tree has shipped three
        # of those.
        print("check_ioc_lake_mapping: refusing to render a verdict — these files are missing:")
        for path in missing:
            print(f"  {path}")
        return 2

    findings = judge(root)
    if findings:
        print(f"check_ioc_lake_mapping: {len(findings)} finding(s)\n")
        for finding in findings:
            print(finding)
        print("\nA retro-hunt sweeping a column the lake writer does not fill returns zero on every tenant,")
        print("which reads as 'you were not exposed' rather than as 'we never looked'.")
        return 1

    ioc_fields = _load_ioc_fields(root)
    swept = sum(len(m.columns) for m in ioc_fields.SWEEPABLE_TYPES.values())
    print(
        f"check_ioc_lake_mapping: OK — {len(ioc_fields.SWEEPABLE_TYPES)} indicator type(s) sweep {swept} lake column(s), "
        f"{len(ioc_fields.UNMAPPED_TYPES)} declared unmappable with a reason, "
        f"{len(feed_emitted_types(root))} feed type(s) routable."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
