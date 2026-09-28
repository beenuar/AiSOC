"""The container egress probe classifies the way the services themselves do.

The Docker-driven half of this gate is exercised in CI by
``.github/workflows/container-egress.yml``, which runs a canary through the
real sinkhole and then shows the gate going red against an image that does
dial out. What is pinned here is everything that can be decided without a
daemon: the sinkhole log parser, the public/private split, and the fact that
the predicate has not drifted from the one the services enforce air-gap
policy with.

That last one matters most. The gate keeps its own copy of the private-suffix
tuple because it runs in a job with no service package importable, and two
copies of a security predicate that nothing compares are two predicates.
"""

from __future__ import annotations

import ast
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
GATE = REPO_ROOT / "scripts" / "check_container_egress.py"
AIRGAP = REPO_ROOT / "services" / "api" / "app" / "core" / "airgap.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_container_egress", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


# ── the predicate has not drifted from the service's own ─────────────────────


def test_private_suffixes_match_the_predicate_the_services_enforce():
    """A second copy of a security predicate is a second predicate."""
    tree = ast.parse(AIRGAP.read_text(encoding="utf-8"))
    service_suffixes = None
    for node in ast.walk(tree):
        # Annotated in the service module, so both assignment forms are read:
        # matching only `Assign` would make this cross-check silently vacuous
        # the moment someone adds or removes the annotation.
        if isinstance(node, ast.AnnAssign) and getattr(node.target, "id", None) == "_PRIVATE_SUFFIXES" and node.value is not None:
            service_suffixes = tuple(ast.literal_eval(node.value))
        elif isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "_PRIVATE_SUFFIXES" for t in node.targets):
            service_suffixes = tuple(ast.literal_eval(node.value))
    assert service_suffixes is not None, f"_PRIVATE_SUFFIXES not found in {AIRGAP}"
    assert gate.PRIVATE_SUFFIXES == service_suffixes


# ── what counts as leaving the building ──────────────────────────────────────


def test_a_public_name_is_public():
    assert gate.is_private_host("api.openai.com") is False
    assert gate.is_private_host("raw.githubusercontent.com") is False


def test_a_bare_label_is_a_compose_service_name():
    """Dialling `redis` is the product working, not a leak."""
    assert gate.is_private_host("redis") is True
    assert gate.is_private_host("postgres") is True


def test_internal_suffixes_and_private_literals_are_internal():
    for host in ("db.internal", "kafka.local", "localhost", "10.0.0.4", "127.0.0.1", "::1"):
        assert gate.is_private_host(host) is True, host


def test_a_public_ip_literal_is_public():
    assert gate.is_private_host("1.1.1.1") is False


# ── reading the sinkhole ─────────────────────────────────────────────────────


def test_only_query_lines_are_read_and_order_is_kept():
    log = "SINKHOLE-READY\nQUERY api.openai.com\nQUERY redis\nSINKHOLE-ERROR whatever\nQUERY api.openai.com\n"
    assert gate.parse_queries(log) == ["api.openai.com", "redis"]


def test_a_trailing_dot_and_case_do_not_make_a_second_name():
    assert gate.parse_queries("QUERY API.OpenAI.Com.\nQUERY api.openai.com\n") == ["api.openai.com"]


def test_classification_splits_a_mixed_log_the_way_the_gate_reports_it():
    public, internal = gate.classify(["api.openai.com", "redis", "db.internal", "8.8.8.8"])
    assert public == ["api.openai.com", "8.8.8.8"]
    assert internal == ["redis", "db.internal"]


def test_an_empty_log_yields_no_findings_but_also_no_evidence():
    """Zero queries is what a correct run *and* a blind probe both look like.

    Which is why the gate requires the canary and refuses a container that
    produced no output — neither of those is decided here, but this pins that
    the parser itself does not manufacture a signal from silence.
    """
    assert gate.parse_queries("SINKHOLE-READY\n") == []
    assert gate.classify([]) == ([], [])


# ── the gate refuses to pass vacuously ───────────────────────────────────────


def test_naming_no_service_is_an_error_not_a_clean_run():
    assert gate.main([]) == 2


def test_a_tree_with_no_compose_file_is_refused(tmp_path):
    assert gate.main(["--service", "api", "--repo-root", str(tmp_path)]) == 2
