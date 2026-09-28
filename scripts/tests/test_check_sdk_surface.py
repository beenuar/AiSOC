"""The SDK surface gate detects each disagreement it claims to, and only those.

Proven against the four shapes that were live on `main` when the gate was
written — a client calling an operation the spec does not declare, a namespace
recorded as a gap in one language, a declared codegen target with no file, and
a package whose only Go source declares types — plus the near misses that
would make the gate a nuisance: a path parameter named differently on each
side, and a curated client reaching far fewer operations than the spec offers.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_sdk_surface.py"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

from gate_toolkit import refuses_an_empty_tree  # noqa: E402

# The gate reads the spec with a line parser so it can run on a bare
# interpreter. PyYAML is what that parser is checked against, and its absence
# is the environment the parser exists for — so the comparison skips rather
# than fails when it is not installed.
try:
    import yaml as pyyaml
except ModuleNotFoundError:  # pragma: no cover - depends on the environment
    pyyaml = None

SPEC = """openapi: 3.1.0
info:
  title: AiSOC
paths:
  /api/v1/alerts:
    get:
      summary: List alerts
    post:
      summary: Create
  /api/v1/alerts/{alert_id}:
    get:
      summary: Get alert
    patch:
      summary: Update alert
  /api/v1/cases:
    get:
      summary: List cases
components:
  schemas: {}
"""

MANIFEST = {
    "spec": "docs/openapi.yaml",
    "clients": {
        "python": {"package": "packages/sdk-py", "path": "client.py"},
        "go": {"package": "packages/sdk-go", "path": None, "gap": "no HTTP client in the package"},
    },
    "namespaces": {
        "alerts": {"prefixes": ["/api/v1/alerts"]},
        "cases": {"prefixes": ["/api/v1/cases"], "gaps": {"python": "not wrapped yet"}},
    },
}


def _load():
    spec = importlib.util.spec_from_file_location("check_sdk_surface", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _tree(tmp_path: Path, files: dict[str, str], *, manifest: dict | None = None, spec: str | None = None) -> Path:
    """A staged git tree holding a spec, a manifest and whatever else is asked for.

    Staged, because the gate takes its corpus from `git ls-files` and an
    unstaged file is invisible to it — the same trap that makes a gate run
    before `git add` skip the files it is meant to judge.
    """
    root = tmp_path / "tree"
    root.mkdir(exist_ok=True)
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    payload = {
        "docs/openapi.yaml": SPEC if spec is None else spec,
        "packages/sdk-surface.json": json.dumps(MANIFEST if manifest is None else manifest),
        **files,
    }
    for rel, body in payload.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def _run(root: Path, module) -> int:
    return module.main(["--repo-root", str(root)])


# ─── The extraction halves, read directly ────────────────────────────────────


def test_the_spec_parser_agrees_with_pyyaml_on_the_real_document() -> None:
    """A line parser instead of PyYAML, so the gate runs on a bare interpreter.

    Worth only as much as its agreement with a real YAML parser, so that is
    asserted against the actual 34k-line spec rather than a fixture.
    """
    if pyyaml is None:  # pragma: no cover - depends on the environment
        pytest.skip("PyYAML is not installed; the line parser is what this gate uses anyway")

    module = _load()
    text = (REPO_ROOT / "docs" / "openapi.yaml").read_text(encoding="utf-8")
    document = pyyaml.safe_load(text)
    expected = {
        (method.upper(), module.normalise(path))
        for path, item in document["paths"].items()
        for method in item
        if method.lower() in module._HTTP_METHODS
    }
    assert module.spec_operations(text) == expected
    assert len(expected) > 400


def test_python_f_strings_and_typescript_templates_normalise_the_same_way() -> None:
    module = _load()
    assert module.python_endpoints('x._get(f"/api/v1/alerts/{alert_id}")\n') == {("GET", "/api/v1/alerts/{}")}
    assert module.typescript_endpoints('this.request<A>("GET", `/api/v1/alerts/${id}`);') == {("GET", "/api/v1/alerts/{}")}
    # The bracket-indexed form the TypeScript client uses to reach GraphQL.
    assert module.typescript_endpoints('sub["request"]("POST", "/graphql", body);') == {("POST", "/graphql")}


def test_a_parameter_named_differently_on_each_side_is_not_a_finding(tmp_path) -> None:
    """`/alerts/{alert_id}` and `/alerts/{id}` are one route addressed twice."""
    module = _load()
    root = _tree(tmp_path, {"client.py": 'x._get("/api/v1/alerts")\nx._get(f"/api/v1/alerts/{whatever_i_called_it}")\n'})
    assert _run(root, module) == 0


# ─── endpoint-not-in-spec ────────────────────────────────────────────────────


def test_an_sdk_calling_a_path_absent_from_the_spec_fails(tmp_path, capsys) -> None:
    """The shape that was live in both clients: `GET /api/v1/detections`."""
    module = _load()
    root = _tree(tmp_path, {"client.py": 'x._get("/api/v1/alerts")\nx._get("/api/v1/detections")\n'})
    assert _run(root, module) == 1
    assert "endpoint-not-in-spec" in capsys.readouterr().out


def test_an_sdk_calling_the_right_path_with_the_wrong_method_fails(tmp_path, capsys) -> None:
    """The playbooks shape: the route existed, the verb was PUT and not PATCH."""
    module = _load()
    root = _tree(tmp_path, {"client.py": 'x._get("/api/v1/alerts")\nx._delete(f"/api/v1/alerts/{aid}")\n'})
    assert _run(root, module) == 1
    out = capsys.readouterr().out
    assert "DELETE /api/v1/alerts/{}" in out


def test_a_curated_client_reaching_a_fraction_of_the_spec_passes(tmp_path) -> None:
    """Coverage is a scope decision, not a defect. Only absent calls fail."""
    module = _load()
    root = _tree(tmp_path, {"client.py": 'x._get("/api/v1/alerts")\n'})
    assert _run(root, module) == 0


# ─── namespace parity, in both directions ────────────────────────────────────


def test_a_manifest_gap_that_has_been_filled_fails(tmp_path, capsys) -> None:
    """A recorded gap must still be a gap, or the list rots into a licence."""
    module = _load()
    root = _tree(tmp_path, {"client.py": 'x._get("/api/v1/alerts")\nx._get("/api/v1/cases")\n'})
    assert _run(root, module) == 1
    out = capsys.readouterr().out
    assert "gap-filled" in out
    assert "namespaces.cases.gaps.python" in out


def test_a_namespace_no_language_reaches_and_no_gap_records_fails(tmp_path, capsys) -> None:
    module = _load()
    manifest = json.loads(json.dumps(MANIFEST))
    manifest["namespaces"]["orphan"] = {"prefixes": ["/api/v1/orphan"]}
    root = _tree(tmp_path, {"client.py": 'x._get("/api/v1/alerts")\n'}, manifest=manifest)
    assert _run(root, module) == 1
    assert "namespace-regressed" in capsys.readouterr().out


def test_the_recorded_go_gap_fails_once_a_go_file_imports_net_http(tmp_path, capsys) -> None:
    """The day someone writes the client, the record of its absence is stale."""
    module = _load()
    root = _tree(
        tmp_path,
        {
            "client.py": 'x._get("/api/v1/alerts")\n',
            "packages/sdk-go/aisoc/client.go": 'package aisoc\n\nimport "net/http"\n\nvar c *http.Client\n',
        },
    )
    assert _run(root, module) == 1
    assert "clients.go.gap" in capsys.readouterr().out


def test_a_go_package_of_type_declarations_leaves_the_gap_standing(tmp_path) -> None:
    """The tree as it is: models.go declares types and speaks to nothing."""
    module = _load()
    root = _tree(
        tmp_path,
        {
            "client.py": 'x._get("/api/v1/alerts")\n',
            "packages/sdk-go/aisoc/models.go": 'package aisoc\n\nimport "time"\n\ntype Alert struct{ At time.Time }\n',
        },
    )
    assert _run(root, module) == 0


# ─── codegen-target-missing ──────────────────────────────────────────────────


def test_a_declared_codegen_target_that_does_not_exist_fails(tmp_path, capsys) -> None:
    """`packages/sdk-ts` declared this one and shipped no artifact for it."""
    module = _load()
    root = _tree(
        tmp_path,
        {
            "client.py": 'x._get("/api/v1/alerts")\n',
            "packages/sdk-ts/package.json": json.dumps(
                {"scripts": {"codegen": "openapi-typescript ../../docs/openapi.yaml -o src/openapi.d.ts"}}
            ),
        },
    )
    assert _run(root, module) == 1
    out = capsys.readouterr().out
    assert "codegen-target-missing" in out
    assert "src/openapi.d.ts" in out


def test_a_declared_codegen_target_that_exists_passes(tmp_path) -> None:
    module = _load()
    root = _tree(
        tmp_path,
        {
            "client.py": 'x._get("/api/v1/alerts")\n',
            "packages/sdk-ts/package.json": json.dumps({"scripts": {"codegen": "openapi-typescript ../x.yaml -o src/openapi.d.ts"}}),
            "packages/sdk-ts/src/openapi.d.ts": "export type paths = Record<string, never>;\n",
        },
    )
    assert _run(root, module) == 0


def test_a_package_with_no_codegen_declaration_is_not_a_finding(tmp_path) -> None:
    module = _load()
    root = _tree(
        tmp_path,
        {
            "client.py": 'x._get("/api/v1/alerts")\n',
            "packages/sdk-ts/package.json": json.dumps({"scripts": {"build": "tsup src/index.ts"}}),
        },
    )
    assert _run(root, module) == 0


# ─── non-vacuity ─────────────────────────────────────────────────────────────


def test_a_spec_with_no_operations_is_refused_rather_than_called_clean(tmp_path, capsys) -> None:
    module = _load()
    root = _tree(tmp_path, {"client.py": 'x._get("/api/v1/alerts")\n'}, spec="openapi: 3.1.0\npaths: {}\n")
    assert _run(root, module) == 2
    assert "REFUSED" in capsys.readouterr().out


def test_a_client_the_parser_matched_nothing_in_is_refused(tmp_path, capsys) -> None:
    """A clean corpus and an unmatched parser must not print the same word."""
    module = _load()
    root = _tree(tmp_path, {"client.py": "# no request sites at all\n"})
    assert _run(root, module) == 2
    assert "no endpoints parsed" in capsys.readouterr().out


def test_a_missing_manifest_is_refused(tmp_path, capsys) -> None:
    module = _load()
    root = tmp_path / "bare"
    root.mkdir()
    subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)
    assert _run(root, module) == 2
    assert "packages/sdk-surface.json is missing" in capsys.readouterr().out


def test_the_empty_tree_refusal_holds_for_a_copy_of_the_script() -> None:
    """The toolkit's probe: `scripts/` copied into a tree with no content."""
    refused, detail = refuses_an_empty_tree(GATE.name, [])
    assert refused, detail


# ─── the gate, end to end ────────────────────────────────────────────────────


def test_the_gate_answers_the_self_test_flag() -> None:
    result = subprocess.run([sys.executable, str(GATE), "--self-test"], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_live_repository_passes() -> None:
    """The regression this gate exists for, asserted against the real tree."""
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_live_manifest_records_the_go_gap_visibly() -> None:
    """A gap nobody reads is an exemption. The verdict has to print it."""
    result = subprocess.run([sys.executable, str(GATE)], capture_output=True, text=True)
    assert "go: recorded gap" in result.stdout, result.stdout
