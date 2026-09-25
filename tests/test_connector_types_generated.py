"""The console's ConnectorType union must be generated, not maintained.

The union was hand-written, and ten of its members named nothing the platform
could ingest. ``ibm_qradar`` was the expensive one: no connector declared it
and no profile was keyed on it, so strict mode rejected those events and
lenient mode minted a vendor called "ibm_qradar" — a second alert source for
the QRadar deployment ``qradar`` already fed.

PR #811 corrected the members and left the mechanism. These tests hold the
three properties that make the mechanism safe to remove:

  * the output is a pure function of the registry, so regeneration is
    idempotent and reordering the registry cannot change a byte;
  * a connector's identity comes from ``connector_id`` on the class, the way
    ``_build_registry()`` resolves it — two connectors in this tree are
    declared under an id their filename does not spell, so a filename slug
    would silently misname them (the defect
    ``scripts/generate_connector_docs.py`` shipped);
  * the canonical folds survive generation, because the console still emits
    ``ibm_qradar`` and the fold is what makes it arrive as ``qradar``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import generate_connector_types as gct  # noqa: E402

TS_OUT = REPO_ROOT / gct.TS_OUT_REL
JSON_OUT = REPO_ROOT / gct.JSON_OUT_REL
CONSUMER = REPO_ROOT / gct.CONSUMER_REL


@pytest.fixture(scope="module")
def inputs() -> dict:
    return gct.load(REPO_ROOT)


@pytest.fixture(scope="module")
def payload(inputs: dict) -> dict:
    return gct.build_payload(**inputs)


# --------------------------------------------------------------------------
# Committed output is current
# --------------------------------------------------------------------------
def test_committed_outputs_match_generation(payload: dict) -> None:
    assert TS_OUT.read_text(encoding="utf-8") == gct.render_typescript(payload), (
        f"{gct.TS_OUT_REL} is stale. Run `python3 scripts/generate_connector_types.py` and commit the result."
    )
    assert JSON_OUT.read_text(encoding="utf-8") == gct.render_json(payload)


def test_check_mode_passes_on_the_committed_tree() -> None:
    assert gct.main(["--check", "--repo-root", str(REPO_ROOT)]) == 0


def test_self_test_passes() -> None:
    """The generator's own injected-drift suite, run as part of the test suite.

    A `--self-test` nothing invokes is the same defect one level up.
    """
    assert gct.self_test(REPO_ROOT) == 0


# --------------------------------------------------------------------------
# Idempotence, and nothing positional
# --------------------------------------------------------------------------
def test_generation_is_idempotent(payload: dict, inputs: dict) -> None:
    once = gct.render_typescript(payload)
    twice = gct.render_typescript(gct.build_payload(**gct.load(REPO_ROOT)))
    assert once == twice


def test_registry_order_does_not_change_the_output(payload: dict, inputs: dict) -> None:
    """Reordering _CONNECTOR_CLASSES must not move a single byte.

    ``scripts/generate_detections.py`` assigned ``det-{category}-{idx:03d}``
    by position, so inserting anywhere but the end renumbered every later
    rule and it needed a committed lock file to become stable. This generator
    assigns no identity — a member *is* its ``connector_id`` — so the same
    class of bug cannot arise, and this is the assertion that says so.
    """
    reversed_registry = dict(reversed(list(inputs["registry"].items())))
    shuffled = dict(inputs, registry=reversed_registry)
    assert gct.render_typescript(gct.build_payload(**shuffled)) == gct.render_typescript(payload)
    assert gct.render_json(gct.build_payload(**shuffled)) == gct.render_json(payload)


# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------
def test_identity_comes_from_the_class_not_the_filename(inputs: dict) -> None:
    """``jira_connector.py`` declares ``jira``; ``tenable.py`` declares ``tenable_io``.

    A generator that slugged the filename would emit ``jira_connector`` and
    ``tenable``, neither of which any profile, alias or fold resolves — the
    exact shape of the ten dead union members, reintroduced mechanically.
    """
    registry = inputs["registry"]
    mismatched = {cid: info["module"] for cid, info in registry.items() if info["module"][:-3] != cid}
    assert mismatched, "expected at least one connector whose filename does not spell its id"
    assert mismatched == {"jira": "jira_connector.py", "tenable_io": "tenable.py"}
    for connector_id in mismatched:
        assert connector_id in gct.build_payload(**inputs)["members"]


def test_registry_matches_the_runtime_registry_key_set(inputs: dict) -> None:
    """The generator's ids are the keys ``CONNECTOR_REGISTRY`` is built from.

    Resolved independently here — walk the tuple, follow each import, read the
    class attribute — so this fails if the generator ever starts inferring
    identity some other way.
    """
    import ast

    init = ast.parse((REPO_ROOT / gct.REGISTRY_REL).read_text(encoding="utf-8"))
    modules = {
        alias.asname or alias.name: node.module.split(".")[-1]
        for node in ast.walk(init)
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("app.connectors.")
        for alias in node.names
    }
    expected = set()
    for class_name in gct._registered_class_names(init):
        tree = ast.parse((REPO_ROOT / gct.CONNECTORS_REL / f"{modules[class_name]}.py").read_text(encoding="utf-8"))
        expected.add(gct._class_attribute(tree, class_name, "connector_id"))
    assert set(inputs["registry"]) == expected


def test_duplicate_connector_id_is_refused(tmp_path: Path) -> None:
    """``_build_registry()`` raises on a duplicate id; so must the generator.

    Silently collapsing two classes onto one id would shrink the union by one
    member and give no reason.
    """
    pkg = tmp_path / "services/connectors/app/connectors"
    pkg.mkdir(parents=True)
    (pkg / "alpha.py").write_text('class AlphaConnector:\n    connector_id = "same"\n')
    (pkg / "beta.py").write_text('class BetaConnector:\n    connector_id = "same"\n')
    (pkg / "__init__.py").write_text(
        "from app.connectors.alpha import AlphaConnector\n"
        "from app.connectors.beta import BetaConnector\n"
        "_CONNECTOR_CLASSES = (AlphaConnector, BetaConnector)\n"
    )
    with pytest.raises(gct.GateError, match="duplicate connector_id"):
        gct.parse_registry(tmp_path)


# --------------------------------------------------------------------------
# The folds
# --------------------------------------------------------------------------
def test_canonical_folds_survive_generation(payload: dict, inputs: dict) -> None:
    assert inputs["canonical"], "the normalizer declares no canonical folds; the parser has drifted"
    rendered = gct.render_typescript(payload)
    for alternate, target in inputs["canonical"].items():
        assert alternate in payload["members"], f"{alternate!r} was flattened out of the union"
        assert target in payload["members"], f"{alternate!r} folds onto {target!r}, which left the union"
        assert f'"{alternate}": "{target}"' in rendered


def test_the_fold_map_is_the_normalizers(payload: dict) -> None:
    """The five folds PR #811 established, read back off the generated file.

    Two products, one deployment: every source here must denote the same
    vendor product as its target, which is what makes folding safe.
    """
    assert payload["canonical"] == {
        "google_chronicle": "chronicle",
        "ibm_qradar": "qradar",
        "palo_alto_cortex": "cortex_xdr",
        "slack": "slack_audit",
        "syslog": "syslog_cef",
    }


# --------------------------------------------------------------------------
# Drift detection
# --------------------------------------------------------------------------
def test_check_fails_on_a_hand_edit(payload: dict) -> None:
    """A member deleted by hand must fail --check rather than be regenerated away."""
    good = gct.render_typescript(payload)
    edited = good.replace('  "qualys",', "", 1)
    assert edited != good
    codes = {code for code, _ in gct.evaluate(payload, edited, gct.render_json(payload), CONSUMER.read_text(encoding="utf-8"))}
    assert "output-drifted" in codes


def test_check_fails_when_the_console_redeclares_the_union(payload: dict) -> None:
    """The generated file can be perfectly current and completely ignored.

    A hand-written union in ``connector.ts`` is what TypeScript resolves, so
    "the generated file exists" is not the property that matters.
    """
    consumer = CONSUMER.read_text(encoding="utf-8") + '\nexport type ConnectorType = "only_this";\n'
    codes = {code for code, _ in gct.evaluate(payload, gct.render_typescript(payload), gct.render_json(payload), consumer)}
    assert "consumer-redeclares" in codes


def test_new_connector_shows_up_as_drift(payload: dict, inputs: dict) -> None:
    """Adding a connector without regenerating must fail --check.

    This is the direction things actually change: a connector is added far
    more often than the union is edited.
    """
    grown = dict(inputs)
    grown["registry"] = {**inputs["registry"], "acme_xdr_9000": {"class": "AcmeConnector", "module": "acme.py", "name": "Acme"}}
    grown_payload = gct.build_payload(**grown)
    assert "acme_xdr_9000" in grown_payload["members"]
    codes = {
        code
        for code, _ in gct.evaluate(
            grown_payload,
            gct.render_typescript(payload),  # the committed file, now stale
            gct.render_json(payload),
            CONSUMER.read_text(encoding="utf-8"),
        )
    }
    assert "output-drifted" in codes
