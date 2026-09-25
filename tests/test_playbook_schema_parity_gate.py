"""Tests for the playbook schema/engine parity gate.

The property worth asserting is not "does the tree happen to agree today" but
"would this gate still notice if it stopped agreeing" — and, specifically,
would it notice in *both* directions. A check that only asks whether the
schema declares something the engine lacks passes forever while the engine
grows verbs nobody tells the schema about, which is exactly how this drift
reached 13 undeclared step types. A sibling gate in this repo compared a YAML
file declaring 17 graph labels against Go code with 28 and printed "OK".

So the assertions are paired: the gate must catch a schema-only step type
*and* an engine-only one; a bound raised on one side *and* the other; a
shipped playbook that stops matching *and* a clean tree passing. The
`--self-test` flag exists so the same proof runs in CI as part of the gate
rather than only here.

The last test is about the gate's own footing: it must refuse to grade a tree
it cannot read rather than print a confident OK about files it never opened.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
_SCRIPT = _REPO / "scripts" / "check_playbook_schema_parity.py"

pytest.importorskip("jsonschema")
pytest.importorskip("httpx")


def _load_gate():
    spec = importlib.util.spec_from_file_location("check_playbook_schema_parity", _SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load_gate()


@pytest.fixture(scope="module")
def registries(gate):
    return gate.collect(gate._find_repo_root(None))


# ---------------------------------------------------------------------------
# The tree is actually clean
# ---------------------------------------------------------------------------


def test_the_repository_passes(registries, gate):
    assert gate.compare(registries) == []


def test_every_shipped_playbook_matches_the_published_schema(gate):
    errors, scanned = gate.validate_shipped_playbooks(gate._find_repo_root(None))
    assert errors == []
    # The lint job used to scan two files and report "2/2 passed" while 62
    # playbooks under playbooks/packs/v1 went unvalidated, 32 of which did
    # not match. A count assertion is the cheapest guard against that
    # regressing into a gate that passes because it looked at nothing.
    assert len(scanned) > 60, f"only {len(scanned)} playbooks scanned; the glob has probably stopped matching"


# ---------------------------------------------------------------------------
# ...and the gate would notice if it stopped being clean, in each direction
# ---------------------------------------------------------------------------


def test_the_bundled_self_test_passes(registries, gate):
    """The gate ships its own drift injection. If this fails, one of the
    directions below has stopped being checked."""
    assert gate.self_test(registries) == []


def _perturb(registries, **kwargs):
    return dataclasses.replace(registries, **kwargs)


def test_catches_a_step_type_the_schema_declares_and_the_engine_lacks(registries, gate):
    """The `run_playbook` shape: valid on paper, unparseable at runtime."""
    broken = _perturb(
        registries,
        schema_step_types=registries.schema_step_types | {"run_playbook"},
        execution={**registries.execution, "run_playbook": "unimplemented"},
    )
    assert any("does not implement" in e for e in gate.compare(broken))


def test_catches_a_step_type_the_engine_accepts_and_the_schema_lacks(registries, gate):
    """The direction things actually drift, and the one a single-sided check
    misses: someone adds a verb to StepType and the published contract never
    hears about it."""
    broken = _perturb(registries, model_step_types=registries.model_step_types | {"quarantine_mailbox"})
    assert any("the schema does not declare it" in e for e in gate.compare(broken))


def test_catches_an_execution_claim_the_engine_cannot_deliver(registries, gate):
    """`x-aisoc-execution` is the schema telling an author what will happen.
    It has to be checked against the handler table or it is just a promise."""
    running = sorted(k for k, v in registries.execution.items() if v in gate._RUNS)
    victim = running[0]
    broken = _perturb(
        registries,
        handler_step_types=registries.handler_step_types - {victim},
        inline_step_types=registries.inline_step_types - {victim},
    )
    assert any("the engine has no handler for it" in e for e in gate.compare(broken))


def test_catches_the_schema_understating_what_the_engine_does(registries, gate):
    """The mirror: a handler exists and the annotation says unimplemented."""
    running = sorted(k for k, v in registries.execution.items() if v in gate._RUNS)
    broken = _perturb(registries, execution={**registries.execution, running[0]: "unimplemented"})
    assert any("understating what the product does" in e for e in gate.compare(broken))


@pytest.mark.parametrize(
    ("field", "needle"),
    [
        ("schema_timeout_max", "timeout ceiling disagrees"),
        ("schema_retry_max", "retry ceiling disagrees"),
    ],
)
def test_catches_bound_drift(registries, gate, field: str, needle: str):
    """A schema ceiling below the engine's rejects playbooks that would run;
    above it promises headroom Pydantic refuses. Five shipped playbooks
    declared a 620s timeout against a schema maximum of 600."""
    broken = _perturb(registries, **{field: getattr(registries, field) + 1})
    assert any(needle in e for e in gate.compare(broken))


def test_catches_trigger_vocabulary_drift_in_both_directions(registries, gate):
    schema_wider = _perturb(registries, schema_triggers=registries.schema_triggers | {"webhook"})
    assert any("validate_playbooks.py rejects" in e for e in gate.compare(schema_wider))

    validator_wider = _perturb(registries, validator_triggers=registries.validator_triggers | {"webhook"})
    assert any("the schema rejects" in e for e in gate.compare(validator_wider))


def test_catches_a_second_schema_file(registries, gate):
    """Two schemas is how the vocabularies diverged to 15 and 9 against an
    engine with 22, and the drafter silently fell back from one to the other."""
    broken = _perturb(registries, schema_files=(*registries.schema_files, "playbook.schema.json"))
    assert any("second source of truth" in e for e in gate.compare(broken))


def test_catches_playbook_level_key_drift_in_both_directions(registries, gate):
    schema_only = _perturb(registries, schema_playbook_keys=registries.schema_playbook_keys | {"ghost_key"})
    assert any("drops on load" in e for e in gate.compare(schema_only))

    model_only = _perturb(registries, model_playbook_keys=registries.model_playbook_keys | {"ghost_field"})
    assert any("does not declare" in e for e in gate.compare(model_only))


# ---------------------------------------------------------------------------
# The TypeScript scan: every declaration of the vocabulary, wherever it is
# ---------------------------------------------------------------------------


def test_the_scan_finds_the_editors_registry_and_the_published_union(registries):
    """The gate used to know one TypeScript file by name and it was not the
    one an operator clicked. The scan has to reach both."""
    found = {v.path for v in registries.ts_vocabularies}
    assert "packages/types/src/playbook.ts" in found
    assert any(path.startswith("apps/web/") for path in found), (
        "no declaration of the step vocabulary was found under apps/web; the editor's form registry "
        f"is meant to be there. Found: {sorted(found)}"
    )


def test_every_declaration_it_found_matches_the_engine(registries):
    for vocabulary in registries.ts_vocabularies:
        assert vocabulary.members == registries.model_step_types, (
            f"{vocabulary.ref} declares {len(vocabulary.members)} step types against the engine's {len(registries.model_step_types)}"
        )


def test_the_editor_declares_an_execution_class_for_every_step_type(registries):
    """A surface that offers a step has to say what will happen when it runs,
    and say the same thing the schema does."""
    annotated = [v for v in registries.ts_vocabularies if v.execution]
    assert annotated, "no TypeScript surface annotates execution; the editor is supposed to"
    for vocabulary in annotated:
        assert vocabulary.execution == registries.execution, f"{vocabulary.ref} disagrees with `x-aisoc-execution`"


def test_catches_a_web_surface_that_declares_fewer_step_types(registries, gate):
    """The exact defect: a nine-member union satisfying `Record<StepType, …>`
    against itself while the engine ran twenty-two."""
    sample = registries.ts_vocabularies[0]
    victim = sorted(sample.members)[0]
    shrunk = dataclasses.replace(sample, members=sample.members - {victim})
    broken = _perturb(registries, ts_vocabularies=(shrunk, *registries.ts_vocabularies[1:]))
    assert any("omits step type" in e for e in gate.compare(broken))


def test_catches_a_web_surface_that_invents_a_step_type(registries, gate):
    sample = registries.ts_vocabularies[0]
    grown = dataclasses.replace(sample, members=sample.members | {"quarantine_mailbox"})
    broken = _perturb(registries, ts_vocabularies=(grown, *registries.ts_vocabularies[1:]))
    assert any("does not implement" in e for e in gate.compare(broken))


def test_catches_a_surface_promising_an_execution_the_schema_denies(registries, gate):
    annotated = next(v for v in registries.ts_vocabularies if v.execution)
    member = next(k for k, v in annotated.execution.items() if v == "unimplemented")
    lying = dataclasses.replace(annotated, execution={**annotated.execution, member: "executed"})
    broken = _perturb(
        registries,
        ts_vocabularies=tuple(lying if v.ref == annotated.ref else v for v in registries.ts_vocabularies),
    )
    assert any("the surface and the contract disagree" in e for e in gate.compare(broken))


def test_refuses_to_pass_having_found_no_declaration(registries, gate):
    """Found nothing and scanned nothing print the same word."""
    assert any("would pass on nothing" in e for e in gate.compare(_perturb(registries, ts_vocabularies=())))


def test_the_recorded_subset_ratchet_works_in_both_directions(registries, gate):
    sample = registries.ts_vocabularies[0]
    victim = sorted(sample.members)[0]
    shrunk = dataclasses.replace(sample, members=sample.members - {victim})
    partial = _perturb(registries, ts_vocabularies=(shrunk, *registries.ts_vocabularies[1:]))

    excused = gate.compare(partial, recorded_subsets={shrunk.ref: "recorded for the test"})
    assert not any("omits step type" in e for e in excused), "a recorded subset was not excused"

    stale = gate.compare(registries, recorded_subsets={sample.ref: "recorded for the test"})
    assert any("remove the entry" in e for e in stale), "an exemption that stopped being needed was not reported"

    ghost = gate.compare(registries, recorded_subsets={"nowhere.ts::Ghost": "recorded for the test"})
    assert any("which the scan did not find" in e for e in ghost)


def test_the_recorded_subset_list_is_empty_on_this_tree(gate):
    """Every entry is a place somebody has to be told "yes, on purpose". The
    list exists so an exception must be written down, not so it gets used."""
    assert gate.RECORDED_TS_SUBSETS == {}


# ---------------------------------------------------------------------------
# The reader, which is where a scan silently loses a file
# ---------------------------------------------------------------------------


def test_the_reader_survives_a_template_literal_with_nested_backticks(gate):
    """The first version of the reader treated a backtick as a plain quote, so
    an interpolation containing another template desynchronised it and every
    declaration after that point in the file was invisible. The scan reported
    agreement having never seen the registry."""
    source = "const A = ['enrich'];\nconst h = `x ${xs.map((k) => `\\`${k}\\``).join(', ')} y`;\nconst B = ['notify'];\n"
    masked, _strings, unreadable = gate._mask_ts(source)
    assert unreadable == "", unreadable
    assert "const B" in masked, "the reader stopped before the end of the file"


@pytest.mark.parametrize(
    "source",
    [
        "const a = /couldn\\'t load the envelope/i;\nconst B = ['enrich', 'notify'];\n",
        "const el = <p>Don't</p>;\nconst B = ['enrich', 'notify'];\n",
    ],
    ids=["apostrophe-in-a-regex", "apostrophe-in-jsx-text"],
)
def test_a_lone_apostrophe_does_not_swallow_the_rest_of_the_file(gate, source: str):
    """A quoted string cannot contain a raw newline, so a quote with no
    partner on its line is not opening one."""
    masked, _strings, unreadable = gate._mask_ts(source)
    assert unreadable == ""
    assert "const B" in masked


def test_a_file_the_reader_cannot_finish_is_never_silently_skipped(gate, tmp_path: Path):
    """Skipping is only safe when the file provably holds no vocabulary, and a
    vocabulary needs at least two step-type literals in the raw bytes."""
    path = tmp_path / "broken.tsx"
    path.write_text("const t = `unterminated\nconst M = { isolate_host: 1, block_ip: 2, disable_user: 3 };\n")
    with pytest.raises(gate.GateError) as exc:
        gate._scan_ts_file(path, "broken.tsx", frozenset({"isolate_host", "block_ip", "disable_user"}))
    assert "could not parse the file to the end" in str(exc.value)


def test_a_file_the_reader_cannot_finish_and_that_mentions_nothing_is_skipped(gate, tmp_path: Path):
    path = tmp_path / "prose.tsx"
    path.write_text("const t = `unterminated\nconst greeting = 'hello';\n")
    found, unreadable = gate._scan_ts_file(path, "prose.tsx", frozenset({"isolate_host", "block_ip"}))
    assert found == []
    assert unreadable, "the skip has to be reported so it can be counted"


def test_the_scan_reads_more_than_a_handful_of_files(registries):
    """A glob that stops matching is the cheapest way for this to go quiet."""
    assert registries.ts_files_scanned > 100, f"only {registries.ts_files_scanned} TypeScript files scanned"
    assert len(registries.ts_files_skipped) * 4 < registries.ts_files_scanned, (
        f"{len(registries.ts_files_skipped)} of {registries.ts_files_scanned} files could not be read; "
        "the reader has regressed far enough that its skips are no longer incidental"
    )


def test_the_reader_finds_each_shape_a_vocabulary_can_take(gate, tmp_path: Path):
    """Union, array and object — plus the execution annotation, recognised by
    the shape of its values rather than by the property's name."""
    path = tmp_path / "shapes.ts"
    path.write_text(
        'export type S = \n  | "enrich"\n  | "notify";\n'
        "const LIST: S[] = ['enrich', 'notify'];\n"
        "const REG = {\n"
        "  enrich: { kind: 'executed', label: 'a' },\n"
        "  notify: { kind: 'governed', label: 'b' },\n"
        "};\n"
    )
    found, _ = gate._scan_ts_file(path, "shapes.ts", frozenset({"enrich", "notify"}))
    by_symbol = {v.symbol: v for v in found}
    assert set(by_symbol) == {"S", "LIST", "REG"}
    assert {v.kind for v in found} == {"union", "array", "object"}
    assert by_symbol["REG"].execution == {"enrich": "executed", "notify": "governed"}
    assert by_symbol["LIST"].execution == {}


# ---------------------------------------------------------------------------
# The gate's own footing
# ---------------------------------------------------------------------------


def test_refuses_to_grade_a_tree_it_cannot_read(gate, tmp_path: Path):
    """Resolving the repo from `__file__` alone is how a gate ends up
    reporting OK about a tree it never opened. Every marker file must be
    present or it declines to run."""
    with pytest.raises(gate.GateError) as exc:
        gate._find_repo_root(str(tmp_path))
    assert "does not look like the AiSOC repository" in str(exc.value)


def test_refuses_an_empty_step_type_enum(gate, tmp_path: Path):
    """A future refactor emptying the enum must fail loudly, not compare two
    empty sets and pass."""
    with pytest.raises(gate.GateError):
        gate._schema_step_types({"definitions": {"PlaybookStep": {"properties": {"type": {"enum": []}}}}})


def test_refuses_a_schema_with_no_execution_map(gate):
    with pytest.raises(gate.GateError):
        gate._schema_execution({})


def test_names_what_it_scanned(gate):
    """A gate that does not say what it read cannot be told apart from one
    that read nothing."""
    proc = subprocess.run(
        [sys.executable, str(_SCRIPT)],
        capture_output=True,
        text=True,
        cwd=str(_REPO),
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    for expected in ("repo root", "schema", "step types", "execution", "playbooks scanned"):
        assert expected in proc.stdout, f"gate output does not report {expected!r}"
    assert str(_REPO) in proc.stdout


def test_the_execution_map_is_not_all_one_value(registries):
    """If every step type were annotated the same way the map would carry no
    information, and the handler cross-check would be trivially satisfiable."""
    assert len(set(registries.execution.values())) > 1


def test_the_schema_on_disk_is_valid_json_schema(gate):
    jsonschema = pytest.importorskip("jsonschema")
    schema = json.loads((_REPO / "schemas" / "playbook.schema.json").read_text())
    jsonschema.Draft7Validator.check_schema(schema)
