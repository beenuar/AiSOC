#!/usr/bin/env python3
"""Gate: the published playbook schema and the engine that runs playbooks
must describe the same product.

``schemas/playbook.schema.json`` is the contract authors are told to trust.
When it drifts from ``services/agents/app/playbook/``, a playbook validates
and then fails at runtime — the worst shape for a schema to have, because the
failure lands on the person who did exactly what the documentation said.

Before this gate the two had drifted in every available direction at once:

  * two schema files existed with different step vocabularies (15 types and
    9 types) against an engine with 22, and the drafter silently fell back
    from one to the other;
  * 11 step types were declared by a schema and implemented nowhere;
  * 13 step types were accepted by the engine and declared by no schema;
  * 12 of those had no handler and the engine reported them ``SUCCESS``,
    including ``approval`` — a human gate that auto-passed;
  * 32 of 64 shipped playbooks failed the published schema, while the lint
    job printed ``2/2 passed`` because it only ever looked at two files.

Every comparison here runs in **both** directions. A check that only asks
"does the schema declare something the engine lacks" passes forever while
drift accumulates in the direction things actually change — the engine grows
a verb and nobody tells the schema. That is how a sibling gate in this repo
reported "OK" on a YAML file declaring 17 labels against Go code with 28.

Run:
    python3 scripts/check_playbook_schema_parity.py
    python3 scripts/check_playbook_schema_parity.py --self-test
"""

from __future__ import annotations

import argparse
import inspect
import json
import re
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path

#: Playbook-level keys the schema declares that the runtime model does not
#: bind. Both are authored documentation rather than engine inputs, and the
#: schema says so in their ``description``. This list is a named exemption,
#: not a silent pass: anything else appearing in one and not the other is an
#: error. Keep it empty-by-default in spirit — an entry here is a promise
#: that the key is inert, and the schema text must say the same.
INERT_AUTHORED_KEYS: frozenset[str] = frozenset({"inputs", "dry_run_support"})

#: Execution classes usable in the schema's ``x-aisoc-execution`` map.
#:
#: ``governed`` means the step is handed to the action registry in
#: ``services/actions``, which grades it against the capability contract and
#: the tenant's autonomy policy before anything reaches a vendor. It is in
#: ``_RUNS`` because a handler exists and makes a real outbound call — what
#: it does *not* claim is that a vendor was necessarily touched, which the
#: step's own ``executed`` field answers per run.
#:
#: ``simulated`` is retained in the vocabulary deliberately. It is the class
#: for a handler that answers from inside the engine without reaching an
#: executor, which is what ``block_ip`` and ``isolate_host`` used to do, and
#: dropping the word would make that state unspellable rather than absent.
_RUNS = frozenset({"executed", "governed", "simulated"})
_EXECUTION_CLASSES = _RUNS | {"unimplemented"}

#: Verbs the engine dispatches through the action registry. Compared against
#: ``engine.RESPONSE_STEP_TYPES`` in both directions, because a step marked
#: ``governed`` that the engine answers locally would be the old defect with
#: a new label on it.
_GOVERNED = "governed"


class GateError(RuntimeError):
    """The gate could not inspect what it is supposed to inspect.

    Raised instead of returning "no problems found", because a gate that
    cannot read its inputs and prints OK is worse than no gate at all.
    """


@dataclass(frozen=True)
class Registries:
    """Every declaration of the playbook vocabulary, read from its source."""

    schema_step_types: frozenset[str]
    model_step_types: frozenset[str]
    handler_step_types: frozenset[str]
    inline_step_types: frozenset[str]
    #: Verbs the engine routes to the action registry rather than answering
    #: locally (``engine.RESPONSE_STEP_TYPES``).
    response_step_types: frozenset[str]
    #: The ``StepType`` union published in ``packages/types``.
    typescript_step_types: frozenset[str]
    execution: dict[str, str]
    schema_timeout_max: int
    schema_timeout_min: int
    schema_retry_max: int
    engine_timeout_max: int
    engine_timeout_min: int
    engine_retry_max: int
    schema_triggers: frozenset[str]
    validator_triggers: frozenset[str]
    schema_playbook_keys: frozenset[str]
    model_playbook_keys: frozenset[str]
    schema_files: tuple[str, ...] = ()
    scanned_playbooks: tuple[str, ...] = field(default=())

    @property
    def runnable(self) -> frozenset[str]:
        """Step types the engine can actually act on."""
        return self.handler_step_types | self.inline_step_types


# ---------------------------------------------------------------------------
# Collection — read each registry from the file that owns it
# ---------------------------------------------------------------------------


def _find_repo_root(explicit: str | None) -> Path:
    """Resolve the tree to inspect, and prove it is the right one.

    Resolving from ``__file__`` alone is how a gate ends up confidently
    reporting OK about a tree it never opened: copy the script somewhere, or
    run it from an installed package, and it grades whatever happens to sit
    two directories up. Every marker below must exist or we refuse to run.
    """
    root = Path(explicit).resolve() if explicit else Path(__file__).resolve().parent.parent
    markers = (
        Path("schemas/playbook.schema.json"),
        Path("services/agents/app/playbook/engine.py"),
        Path("services/agents/app/playbook/models.py"),
        Path("scripts/validate_playbooks.py"),
    )
    missing = [str(m) for m in markers if not (root / m).exists()]
    if missing:
        raise GateError(
            f"{root} does not look like the AiSOC repository — missing: "
            f"{', '.join(missing)}. Pass --repo-root to point at the tree to check."
        )
    return root


def _load_schema(root: Path) -> dict:
    return json.loads((root / "schemas" / "playbook.schema.json").read_text())


def _schema_step_types(schema: dict) -> frozenset[str]:
    try:
        enum = schema["definitions"]["PlaybookStep"]["properties"]["type"]["enum"]
    except (KeyError, TypeError) as exc:
        raise GateError(f"schema step-type enum not found at the expected path: {exc}") from exc
    if not enum:
        raise GateError("schema step-type enum is empty; refusing to compare against nothing")
    return frozenset(enum)


def _schema_execution(schema: dict) -> dict[str, str]:
    raw = schema.get("x-aisoc-execution")
    if not isinstance(raw, dict):
        raise GateError("schema has no `x-aisoc-execution` map; the engine's behaviour would be undeclared")
    mapping = {k: v for k, v in raw.items() if k != "description"}
    if not mapping:
        raise GateError("`x-aisoc-execution` is empty; refusing to compare against nothing")
    return mapping


def _schema_step_bounds(schema: dict) -> tuple[int, int, int]:
    try:
        props = schema["definitions"]["PlaybookStep"]["properties"]
        return (
            int(props["timeout_seconds"]["maximum"]),
            int(props["timeout_seconds"]["minimum"]),
            int(props["retry_max"]["maximum"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise GateError(f"schema step bounds not found at the expected path: {exc}") from exc


def _import_engine(root: Path):
    """Import the real engine module rather than parsing it.

    Parsing would let a handler table that is built at import time disagree
    with what the parser sees. The import is cheap: the engine documents
    "zero external dependencies beyond httpx + stdlib".
    """
    agents = str(root / "services" / "agents")
    if agents not in sys.path:
        sys.path.insert(0, agents)
    try:
        from app.playbook import bounds, engine, models  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001 — surfaced, never swallowed
        raise GateError(
            f"could not import the playbook engine from {agents}: {type(exc).__name__}: {exc}. "
            "Install httpx and pydantic, or the gate is grading nothing."
        ) from exc
    return engine, models, bounds


def _inline_step_types(engine_mod, models_mod) -> frozenset[str]:
    """Step types handled inside the run loop rather than via ``_HANDLERS``.

    ``condition`` never reaches the handler table — it branches in the loop
    body. Reading the source keeps that visible to the gate; if someone
    deletes the branch, the type stops counting as runnable here too.
    """
    try:
        source = inspect.getsource(engine_mod.PlaybookEngine.run)
    except (OSError, TypeError, AttributeError) as exc:
        raise GateError(f"could not read PlaybookEngine.run source to find inline step handling: {exc}") from exc
    found = {st.value for st in models_mod.StepType if f"StepType.{st.name}" in source}
    return frozenset(found)


def _model_playbook_keys(models_mod) -> frozenset[str]:
    return frozenset(models_mod.Playbook.model_fields.keys())


#: ``| "value"`` members of a TypeScript string-literal union.
_TS_UNION_MEMBER = re.compile(r'^\s*\|\s*"([a-z_]+)"', re.MULTILINE)


def _typescript_step_types(root: Path) -> frozenset[str]:
    """The ``StepType`` union published in ``packages/types``.

    A fourth vocabulary lived here undetected because nothing imports the
    package: 28 members (``notify_email``, ``create_ticket_jira``,
    ``collect_forensics`` …) matching neither the schema nor the engine. An
    unimported wrong contract is still a wrong contract — it is what the next
    person to import it will build against.

    Parsed rather than transpiled so the gate needs no Node toolchain, which
    is why the union is written one ``| "member"`` per line.
    """
    path = root / "packages" / "types" / "src" / "playbook.ts"
    if not path.is_file():
        raise GateError(f"{path} is missing; the published TypeScript vocabulary cannot be compared")
    text = path.read_text()
    marker = "export type StepType ="
    start = text.find(marker)
    if start == -1:
        raise GateError(f"{path} declares no `export type StepType` union to compare against the engine")
    end = text.find(";", start)
    members = frozenset(_TS_UNION_MEMBER.findall(text[start:end]))
    if not members:
        raise GateError(f"{path} declares a StepType union the gate could not parse; refusing to compare against nothing")
    return members


def _validator_triggers(root: Path) -> frozenset[str]:
    """``scripts/validate_playbooks.py`` keeps its own trigger allow-list."""
    scripts = str(root / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    try:
        import validate_playbooks  # type: ignore[import-not-found]
    except Exception as exc:  # noqa: BLE001
        raise GateError(f"could not import scripts/validate_playbooks.py: {type(exc).__name__}: {exc}") from exc
    triggers = getattr(validate_playbooks, "SUPPORTED_TRIGGERS", None)
    if not triggers:
        raise GateError("validate_playbooks.SUPPORTED_TRIGGERS is missing or empty")
    return frozenset(triggers)


def _schema_files(root: Path) -> tuple[str, ...]:
    hits = [
        p
        for p in root.rglob("playbook.schema.json")
        if "node_modules" not in p.parts and ".git" not in p.parts and ".venv-gate" not in p.parts
    ]
    return tuple(sorted(str(p.relative_to(root)) for p in hits))


def _playbook_files(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.playbook.json") if "node_modules" not in p.parts and ".git" not in p.parts)


def collect(root: Path) -> Registries:
    schema = _load_schema(root)
    engine_mod, models_mod, bounds_mod = _import_engine(root)
    s_tmax, s_tmin, s_rmax = _schema_step_bounds(schema)
    return Registries(
        schema_step_types=_schema_step_types(schema),
        model_step_types=frozenset(st.value for st in models_mod.StepType),
        handler_step_types=frozenset(st.value for st in engine_mod._HANDLERS),
        inline_step_types=_inline_step_types(engine_mod, models_mod),
        response_step_types=frozenset(st.value for st in engine_mod.RESPONSE_STEP_TYPES),
        typescript_step_types=_typescript_step_types(root),
        execution=_schema_execution(schema),
        schema_timeout_max=s_tmax,
        schema_timeout_min=s_tmin,
        schema_retry_max=s_rmax,
        engine_timeout_max=bounds_mod.ABSOLUTE_MAX_TIMEOUT_SECONDS,
        engine_timeout_min=bounds_mod.MIN_TIMEOUT_SECONDS,
        engine_retry_max=bounds_mod.ABSOLUTE_MAX_RETRIES,
        schema_triggers=frozenset(schema["properties"]["trigger"]["properties"]["on"]["enum"]),
        validator_triggers=_validator_triggers(root),
        schema_playbook_keys=frozenset(schema["properties"].keys()),
        model_playbook_keys=_model_playbook_keys(models_mod),
        schema_files=_schema_files(root),
    )


# ---------------------------------------------------------------------------
# Comparison — pure, so the self-test can perturb it
# ---------------------------------------------------------------------------


def compare(reg: Registries) -> list[str]:
    """Every check, in both directions. Returns human-readable failures."""
    errors: list[str] = []

    if not reg.schema_step_types or not reg.model_step_types:
        # Defence against a future refactor making the whole gate vacuous.
        return ["one of the step-type registries is empty; the comparison would pass on nothing"]

    # 1. schema enum <-> StepType, both ways.
    for missing in sorted(reg.schema_step_types - reg.model_step_types):
        errors.append(
            f"schema declares step type {missing!r} that StepType does not implement — "
            f"a playbook using it validates and then fails to parse at runtime. "
            f"Build it or remove it from the schema."
        )
    for missing in sorted(reg.model_step_types - reg.schema_step_types):
        errors.append(
            f"StepType implements {missing!r} and the schema does not declare it — "
            f"an author following the published contract cannot use it, and the "
            f"drafter has to collapse it onto some other verb. Declare it or delete it."
        )

    # 2. execution map <-> schema enum, both ways.
    exec_keys = frozenset(reg.execution)
    for missing in sorted(reg.schema_step_types - exec_keys):
        errors.append(f"step type {missing!r} is declared but `x-aisoc-execution` does not say what the engine does with it")
    for extra in sorted(exec_keys - reg.schema_step_types):
        errors.append(f"`x-aisoc-execution` describes {extra!r}, which the schema does not declare as a step type")

    bad = {k: v for k, v in reg.execution.items() if v not in _EXECUTION_CLASSES}
    for k, v in sorted(bad.items()):
        errors.append(f"`x-aisoc-execution[{k}]` is {v!r}; expected one of {sorted(_EXECUTION_CLASSES)}")

    # 3. execution claims <-> the engine's real handler table, both ways.
    claims_to_run = frozenset(k for k, v in reg.execution.items() if v in _RUNS)
    for k in sorted(claims_to_run - reg.runnable):
        errors.append(
            f"`x-aisoc-execution` claims {k!r} runs, but the engine has no handler for it — "
            f"this is the claim the schema exists to make true."
        )
    for k in sorted(reg.runnable - claims_to_run):
        errors.append(
            f"the engine has a handler for {k!r} but `x-aisoc-execution` marks it "
            f"{reg.execution.get(k, '(absent)')!r} — the schema is understating what the product does."
        )

    # 2b. the published TypeScript vocabulary <-> StepType, both ways.
    #     `packages/types` is what an integrator builds against, and it had
    #     drifted into an entirely separate 28-member vocabulary that nothing
    #     imported and nothing checked.
    for missing in sorted(reg.model_step_types - reg.typescript_step_types):
        errors.append(
            f"`StepType` implements {missing!r} and `packages/types/src/playbook.ts` does not publish it — "
            f"an integrator typing against the package cannot express a step the engine runs."
        )
    for extra in sorted(reg.typescript_step_types - reg.model_step_types):
        errors.append(
            f"`packages/types/src/playbook.ts` publishes step type {extra!r}, which `StepType` does not implement — "
            f"code that type-checks against the package would be rejected by the server."
        )

    # 3b. `governed` claims <-> the engine's response-verb set, both ways.
    #     A step labelled `governed` that the engine answers from inside its
    #     own process is the exact defect this label replaced: `block_ip` used
    #     to return `{"simulated": true}` and reach no executor. And a verb the
    #     engine routes to the registry while the schema calls it something
    #     else understates the governance an author is relying on.
    claims_governed = frozenset(k for k, v in reg.execution.items() if v == _GOVERNED)
    for k in sorted(claims_governed - reg.response_step_types):
        errors.append(
            f"`x-aisoc-execution` marks {k!r} governed, but the engine does not route it "
            f"through the action registry — a local answer wearing the label of a dispatched one."
        )
    for k in sorted(reg.response_step_types - claims_governed):
        errors.append(
            f"the engine dispatches {k!r} through the action registry but `x-aisoc-execution` "
            f"marks it {reg.execution.get(k, '(absent)')!r}."
        )

    # 4. bounds, both ways (a schema ceiling below the engine's rejects valid
    #    playbooks; above it promises headroom Pydantic will refuse).
    if reg.schema_timeout_max != reg.engine_timeout_max:
        errors.append(
            f"step timeout ceiling disagrees: schema {reg.schema_timeout_max} vs "
            f"bounds.ABSOLUTE_MAX_TIMEOUT_SECONDS {reg.engine_timeout_max}"
        )
    if reg.schema_timeout_min != reg.engine_timeout_min:
        errors.append(
            f"step timeout floor disagrees: schema {reg.schema_timeout_min} vs bounds.MIN_TIMEOUT_SECONDS {reg.engine_timeout_min}"
        )
    if reg.schema_retry_max != reg.engine_retry_max:
        errors.append(f"retry ceiling disagrees: schema {reg.schema_retry_max} vs bounds.ABSOLUTE_MAX_RETRIES {reg.engine_retry_max}")

    # 5. trigger vocabulary <-> the pack validator's allow-list, both ways.
    for missing in sorted(reg.schema_triggers - reg.validator_triggers):
        errors.append(f"schema allows trigger.on={missing!r} that validate_playbooks.py rejects")
    for missing in sorted(reg.validator_triggers - reg.schema_triggers):
        errors.append(f"validate_playbooks.py allows trigger.on={missing!r} that the schema rejects")

    # 6. playbook-level keys <-> Playbook model fields, both ways.
    for missing in sorted(reg.schema_playbook_keys - reg.model_playbook_keys - INERT_AUTHORED_KEYS):
        errors.append(
            f"schema declares playbook key {missing!r} that the Playbook model drops on load — "
            f"add the field, remove the key, or list it in INERT_AUTHORED_KEYS and say so in its description"
        )
    for missing in sorted(reg.model_playbook_keys - reg.schema_playbook_keys):
        errors.append(f"Playbook model has field {missing!r} that the schema does not declare, so `additionalProperties: false` rejects it")

    # 7. exactly one schema file. Two is how the vocabularies diverged.
    if len(reg.schema_files) > 1:
        errors.append(
            f"more than one playbook.schema.json in the tree ({', '.join(reg.schema_files)}) — "
            f"a second copy is a second source of truth and the drafter silently fell back to it once already"
        )

    return errors


# ---------------------------------------------------------------------------
# Content check — the contract must be true of what ships
# ---------------------------------------------------------------------------


def validate_shipped_playbooks(root: Path) -> tuple[list[str], list[Path]]:
    try:
        import jsonschema
    except ImportError as exc:
        raise GateError("jsonschema is not installed; the content half of this gate cannot run") from exc

    schema = _load_schema(root)
    validator = jsonschema.Draft7Validator(schema)
    files = _playbook_files(root)
    if not files:
        raise GateError("no *.playbook.json found; refusing to report success having validated nothing")

    errors: list[str] = []
    for path in files:
        rel = path.relative_to(root)
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            errors.append(f"{rel}: JSON parse error: {exc}")
            continue
        for err in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            loc = ".".join(str(p) for p in err.path) or "(root)"
            errors.append(f"{rel}: {loc}: {err.message}")
    return errors, files


# ---------------------------------------------------------------------------
# Self-test — prove the gate fires, in each direction
# ---------------------------------------------------------------------------


def self_test(reg: Registries) -> list[str]:
    """Inject drift in each direction and assert the gate notices.

    A gate nobody has seen fail is indistinguishable from a gate that cannot.
    """
    failures: list[str] = []

    def expect(label: str, perturbed: Registries, needle: str) -> None:
        errs = compare(perturbed)
        if not any(needle in e for e in errs):
            failures.append(f"self-test: {label}: injected drift was NOT detected (needle {needle!r}); got {errs or 'no errors'}")

    baseline = compare(reg)
    if baseline:
        failures.append(f"self-test: the unperturbed tree already fails, so a pass proves nothing: {baseline}")

    victim = sorted(reg.schema_step_types)[0]
    absent = "step_type_that_exists_nowhere"

    expect(
        "schema declares a type the engine lacks",
        replace(
            reg,
            schema_step_types=reg.schema_step_types | {absent},
            execution={**reg.execution, absent: "unimplemented"},
        ),
        "does not implement",
    )
    expect(
        "engine implements a type the schema lacks",
        replace(reg, model_step_types=reg.model_step_types | {absent}),
        "the schema does not declare it",
    )
    expect(
        "the published TypeScript union lost a verb the engine runs",
        replace(reg, typescript_step_types=reg.typescript_step_types - {victim}),
        "does not publish it",
    )
    expect(
        # The shape the file was actually in: a vocabulary of its own.
        "the published TypeScript union invented a verb",
        replace(reg, typescript_step_types=reg.typescript_step_types | {"create_ticket_jira"}),
        "which `StepType` does not implement",
    )
    expect(
        "declared type with no execution annotation",
        replace(reg, execution={k: v for k, v in reg.execution.items() if k != victim}),
        "does not say what the engine does with it",
    )
    expect(
        "execution annotation for an undeclared type",
        replace(reg, execution={**reg.execution, absent: "executed"}),
        "which the schema does not declare",
    )
    runs_now = sorted(k for k, v in reg.execution.items() if v in _RUNS)
    if not runs_now:
        failures.append("self-test: no step type is annotated as running; cannot test the handler directions")
    else:
        running = runs_now[0]
        expect(
            "annotation claims execution the engine cannot deliver",
            replace(reg, handler_step_types=reg.handler_step_types - {running}, inline_step_types=reg.inline_step_types - {running}),
            "the engine has no handler for it",
        )
        expect(
            "engine gained a handler the annotation calls unimplemented",
            replace(reg, execution={**reg.execution, running: "unimplemented"}),
            "understating what the product does",
        )

    governed_now = sorted(k for k, v in reg.execution.items() if v == _GOVERNED)
    if not governed_now:
        failures.append("self-test: no step type is annotated governed; cannot test the registry directions")
    else:
        dispatched = governed_now[0]
        expect(
            # The precise shape of the bug this label replaced: a verb that
            # says it goes through the action registry and is answered inside
            # the engine instead.
            "annotation claims governed dispatch the engine does not do",
            replace(reg, response_step_types=reg.response_step_types - {dispatched}),
            "a local answer wearing the label of a dispatched one",
        )
        expect(
            "engine dispatches a verb the annotation calls merely executed",
            replace(reg, execution={**reg.execution, dispatched: "executed"}),
            "through the action registry but `x-aisoc-execution`",
        )
    expect("timeout ceiling drift", replace(reg, schema_timeout_max=reg.engine_timeout_max + 1), "timeout ceiling disagrees")
    expect("retry ceiling drift", replace(reg, schema_retry_max=reg.engine_retry_max + 1), "retry ceiling disagrees")
    expect(
        "schema allows a trigger the validator rejects",
        replace(reg, schema_triggers=reg.schema_triggers | {"webhook"}),
        "that validate_playbooks.py rejects",
    )
    expect(
        "validator allows a trigger the schema rejects",
        replace(reg, validator_triggers=reg.validator_triggers | {"webhook"}),
        "that the schema rejects",
    )
    expect("schema key the model drops", replace(reg, schema_playbook_keys=reg.schema_playbook_keys | {"ghost_key"}), "drops on load")
    expect(
        "model field the schema rejects", replace(reg, model_playbook_keys=reg.model_playbook_keys | {"ghost_field"}), "does not declare"
    )
    expect(
        "a second schema file reappears", replace(reg, schema_files=(*reg.schema_files, "playbook.schema.json")), "second source of truth"
    )

    return failures


# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", default=None, help="Tree to inspect (default: the repo this script lives in)")
    parser.add_argument("--self-test", action="store_true", help="Prove the gate detects injected drift in each direction")
    args = parser.parse_args()

    try:
        root = _find_repo_root(args.repo_root)
        reg = collect(root)
        content_errors, scanned = validate_shipped_playbooks(root)
    except GateError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 2

    # Name what was inspected. A gate that does not say what it read cannot
    # be distinguished from one that read nothing.
    print(f"repo root          {root}")
    print(f"schema             {', '.join(reg.schema_files) or '(none)'}")
    print("engine             services/agents/app/playbook/engine.py")
    print(
        f"step types         schema {len(reg.schema_step_types)} | StepType {len(reg.model_step_types)} "
        f"| runnable {len(reg.runnable)} | packages/types {len(reg.typescript_step_types)}"
    )
    counts = {c: sum(1 for v in reg.execution.values() if v == c) for c in sorted(_EXECUTION_CLASSES)}
    print("execution          " + " | ".join(f"{k} {v}" for k, v in counts.items()))
    print(f"bounds             timeout {reg.schema_timeout_min}..{reg.schema_timeout_max}s | retries <={reg.schema_retry_max}")
    print(f"playbooks scanned  {len(scanned)}")
    print()

    errors = compare(reg)

    if args.self_test:
        st = self_test(reg)
        if st:
            print("SELF-TEST FAILED")
            for f in st:
                print(f"  {f}")
            return 1
        print("self-test OK — every direction detected its injected drift, and the clean tree passed")
        print()

    if content_errors:
        print(f"{len(content_errors)} shipped playbook(s) do not match the published schema:")
        for e in content_errors[:40]:
            print(f"  {e}")
        if len(content_errors) > 40:
            print(f"  ... and {len(content_errors) - 40} more")

    if errors:
        print(f"{len(errors)} schema/engine disagreement(s):")
        for e in errors:
            print(f"  {e}")

    if errors or content_errors:
        return 1

    print("OK — schema and engine agree in both directions, and every shipped playbook matches the schema.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
