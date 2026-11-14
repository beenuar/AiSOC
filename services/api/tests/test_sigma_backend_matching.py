"""The Sigma path must fire on a true positive, and must say when it cannot.

Two defects sat here, and between them no Sigma rule evaluated by this engine
could ever have matched an event:

1. ``_lucene_match`` was ``query.lower() in " ".join(f"{k}:{v}" ...)``. A
   Lucene boolean expression is never a contiguous substring of a
   ``key:value`` join, so ``Image:*\\powershell.exe AND CommandLine:*Mimikatz*``
   — what pySigma's OpenSearch backend emits for a two-field ``selection`` —
   matched nothing and returned ``False`` with no error.

2. ``_run_sigma`` caught ``ImportError`` and returned the reduced built-in
   evaluator's answer with ``error=None``. So a deployment without pySigma
   silently ran a different, weaker evaluator and nothing anywhere said so.

The two interact badly. ``.github/workflows/ci.yml`` did not install pysigma,
so every Sigma test in CI exercised the fallback, while the Docker image
installs it from the lockfile and ran the broken real path. CI and production
evaluated Sigma rules with different engines, and the one CI never ran was
the broken one. The workflow now installs pysigma, and
``test_ci_installs_the_backend_it_claims_to_test`` fails if that is undone —
otherwise the pySigma tests below would skip in CI and report green.

Three callers depended on the answer: ``POST /rules/{id}/backtest`` (which
exists to report an honest ``would_fire``), ``detection_eval`` (the gate a
candidate rule has to pass on its own positive fixtures), and the scheduled
hunt worker.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml
from app.services.detection_eval import evaluate_candidate_rule
from app.services.lucene_eval import LuceneQueryError, lucene_matches
from app.services.rule_engine import SIGMA_DEGRADED, _run_sigma, execute_rule

pysigma = pytest.importorskip("sigma.backends.opensearch", reason="pysigma is required for the real Sigma backend path")

TWO_CLAUSE_RULE = """
title: PowerShell running Mimikatz
id: 11111111-2222-3333-4444-555555555555
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\powershell.exe'
        CommandLine|contains: 'Invoke-Mimikatz'
    condition: selection
level: high
"""

TRUE_POSITIVE = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "powershell.exe -enc Invoke-Mimikatz -DumpCreds",
}
# Satisfies exactly one of the two AND-ed clauses. A matcher that has lost the
# boolean either fires on this or fires on nothing; both are wrong.
HALF_MATCH = {
    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    "CommandLine": "Get-ChildItem -Recurse",
}
TRUE_NEGATIVE = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "dir"}


class TestTheRealBackendFires:
    def test_a_two_clause_sigma_rule_fires_on_its_true_positive(self) -> None:
        matched, error = _run_sigma(TWO_CLAUSE_RULE, [TRUE_POSITIVE])
        assert error is None, error
        assert matched == [TRUE_POSITIVE], "a rule that cannot fire on its own true positive can never fire at all"

    def test_it_stays_silent_when_only_one_clause_holds(self) -> None:
        matched, error = _run_sigma(TWO_CLAUSE_RULE, [HALF_MATCH])
        assert error is None, error
        assert matched == [], "AND must require both clauses"

    def test_it_stays_silent_on_an_unrelated_event(self) -> None:
        matched, error = _run_sigma(TWO_CLAUSE_RULE, [TRUE_NEGATIVE])
        assert error is None, error
        assert matched == []

    def test_the_candidate_rule_gate_can_pass_a_sigma_rule(self) -> None:
        """``detection_eval`` is the promote-gate for a proposed detection.

        With the matcher unable to fire, every Sigma candidate failed on its
        own positive fixture, so the gate rejected correct rules for a reason
        that had nothing to do with them.
        """
        result = evaluate_candidate_rule(
            rule_language="sigma",
            rule_body=TWO_CLAUSE_RULE,
            positive_fixtures=[TRUE_POSITIVE],
            negative_fixtures=[HALF_MATCH, TRUE_NEGATIVE],
        )
        assert result.passed, result.reason
        assert (result.positives_fired, result.negatives_fired) == (1, 0)

    def test_execute_rule_reports_the_match_through_the_public_surface(self) -> None:
        match = execute_rule(
            rule_id="r1",
            rule_name="PowerShell running Mimikatz",
            rule_language="sigma",
            rule_body=TWO_CLAUSE_RULE,
            severity="high",
            events=[TRUE_POSITIVE, TRUE_NEGATIVE],
        )
        assert match.matched is True
        assert match.error is None


class TestTheLuceneEvaluator:
    @pytest.mark.parametrize(
        ("query", "event", "expected"),
        [
            ("EventID:4625", {"eventid": 4625}, True),
            ("EventID:4625", {"eventid": 4624}, False),
            ("a:1 AND b:2", {"a": 1, "b": 2}, True),
            ("a:1 AND b:2", {"a": 1, "b": 3}, False),
            ("a:1 OR b:2", {"a": 9, "b": 2}, True),
            ("a:1 OR b:2", {"a": 9, "b": 9}, False),
            ("NOT a:1", {"a": 2}, True),
            ("NOT a:1", {"a": 1}, False),
            ("(a:1 OR a:2) AND b:3", {"a": 2, "b": 3}, True),
            ("(a:1 OR a:2) AND b:3", {"a": 3, "b": 3}, False),
            ("TargetUserName:(admin OR root)", {"targetusername": "root"}, True),
            ("TargetUserName:(admin OR root)", {"targetusername": "guest"}, False),
            ("Image:*\\\\net.exe", {"image": "C:\\Windows\\System32\\net.exe"}, True),
            ("Image:*\\\\net.exe", {"image": "C:\\Windows\\System32\\cmd.exe"}, False),
            ("ParentImage:C\\:\\\\Windows*", {"parentimage": "C:\\Windows\\explorer.exe"}, True),
            ("CommandLine:/inv.*mimi/", {"commandline": "Invoke-Mimikatz"}, True),
            ("CommandLine:/inv.*mimi/", {"commandline": "Get-Process"}, False),
            ("NOT _exists_:User", {"other": 1}, True),
            ("NOT _exists_:User", {"user": "alice"}, False),
            ("*whoami*", {"cmd": "c:\\tools\\whoami.exe -all"}, True),
            ("*whoami*", {"cmd": "ipconfig"}, False),
            ("ServiceName:Remote\\ Desktop\\ Services", {"servicename": "Remote Desktop Services"}, True),
            # A value carrying regex metacharacters must be a literal, not a pattern.
            ("path:a.b", {"path": "axb"}, False),
            ("path:a.b", {"path": "a.b"}, True),
        ],
    )
    def test_boolean_and_wildcard_semantics(self, query: str, event: dict[str, Any], expected: bool) -> None:
        assert lucene_matches(query, event) is expected

    def test_a_query_outside_the_supported_subset_raises_rather_than_returning_false(self) -> None:
        """Refusing is the property. A `False` here reads exactly like a clean event."""
        with pytest.raises(LuceneQueryError):
            lucene_matches("a:1 b:2", {"a": 1, "b": 2})  # implicit operator
        with pytest.raises(LuceneQueryError):
            lucene_matches("(a:1", {"a": 1})
        with pytest.raises(LuceneQueryError):
            lucene_matches("", {})

    def test_the_substring_matcher_this_replaced_could_not_have_passed(self) -> None:
        """Pin the defect so the old implementation cannot quietly return.

        This is the exact expression that shipped. It is kept here rather than
        described, because the claim "substring containment cannot represent a
        boolean" is worth demonstrating against the same inputs the real
        matcher is graded on above.
        """
        backend = pysigma.OpensearchLuceneBackend()
        from sigma.rule import SigmaRule

        queries = [str(q) for q in backend.convert_rule(SigmaRule.from_yaml(TWO_CLAUSE_RULE))]
        flat = {k.lower(): v for k, v in TRUE_POSITIVE.items()}
        joined = " ".join(f"{k}:{v}" for k, v in flat.items()).lower()

        assert not any(q.lower() in joined for q in queries), "premise changed: the old matcher would have worked"
        assert any(lucene_matches(q, flat) for q in queries), "the replacement must fire where the old one could not"


class TestRulesAuthoredDirectlyInLucene:
    """`rule_language: lucene` was routed to the KQL matcher, which drops booleans.

    `_kql_match` regexes out the *first* `field:value` it can find and
    otherwise falls back to `query.lower() in flat_str`. So a two-clause
    Lucene rule fired whenever its first clause held, whatever the second
    one said — which passes a naive true-positive test and is wrong on
    exactly the events a second clause exists to exclude.
    """

    QUERY = "Image:*powershell.exe AND CommandLine:*Mimikatz*"

    def _matched(self, event: dict[str, Any]) -> bool:
        return execute_rule(
            rule_id="r2",
            rule_name="two clause lucene",
            rule_language="lucene",
            rule_body=self.QUERY,
            severity="high",
            events=[event],
        ).matched

    def test_it_fires_when_both_clauses_hold(self) -> None:
        assert self._matched(TRUE_POSITIVE) is True

    def test_it_stays_silent_when_only_the_first_clause_holds(self) -> None:
        assert self._matched(HALF_MATCH) is False, "the second clause of an AND was being ignored"

    def test_an_unreadable_query_is_an_error_not_an_absence_of_matches(self) -> None:
        match = execute_rule(
            rule_id="r3",
            rule_name="malformed",
            rule_language="lucene",
            rule_body="(Image:*powershell.exe",
            severity="high",
            events=[TRUE_POSITIVE],
        )
        assert match.matched is False
        assert match.error and "unsupported Lucene query" in match.error


class TestTheFallbackIsNotSilent:
    def test_a_missing_backend_is_reported_rather_than_returned_as_no_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without this, a deployment lacking pySigma runs a weaker evaluator invisibly."""
        monkeypatch.setitem(sys.modules, "sigma.backends.opensearch", None)
        matched, error = _run_sigma(TWO_CLAUSE_RULE, [TRUE_POSITIVE])
        assert error == SIGMA_DEGRADED, f"the degraded path must name itself, got {error!r}"
        assert isinstance(matched, list)


def _python_test_install_set() -> tuple[list[str], list[str]]:
    """The services ``ci.yml``'s ``python-test`` job derives its install from,
    and the requirements that derivation produces.

    The job used to carry a hand-written ``API_DEPS`` list and this test read
    it verbatim. It now runs ``service_requirements.py <services>``, so the
    question "does CI install pysigma" is answered by resolving that step the
    way the shell does: read which services the step names, then ask the same
    producer the workflow asks. What stays falsifiable is the naming — a job
    that derives from the wrong service, or a manifest that drops the package,
    both fail here.

    The step now passes ``--locked`` and redirects to a file, so the answer
    comes from the lock rather than from the ranges — which is the point of
    that change, and is also a stronger question: "is pysigma in the set the
    virtualenv receives" rather than "is it in the set a resolver may choose
    from". The tail is cut at the redirect, because a reader that keeps going
    takes ``>`` and ``/tmp/api.lock.txt`` for service names.
    """
    root = Path(__file__).resolve().parents[3]
    sys.path.insert(0, str(root / "scripts"))
    import service_requirements  # noqa: PLC0415

    workflow = yaml.safe_load((root / ".github" / "workflows" / "ci.yml").read_text())
    steps = workflow["jobs"]["python-test"]["steps"]
    named: list[str] = []
    locked: set[str] = set()
    for step in steps:
        for line in str(step.get("run") or "").splitlines():
            if "service_requirements.py" not in line or "--system" in line:
                continue
            tail = re.split(r"[|>;]|&&", line.split("service_requirements.py", 1)[1])[0]
            words = [word for word in tail.split() if re.fullmatch(r"[a-z0-9][a-z0-9-]*", word)]
            named += words
            if "--locked" in line:
                locked.update(words)
    resolved: list[str] = []
    for service in dict.fromkeys(named):
        manifest = root / "services" / service / "pyproject.toml"
        if service in locked:
            resolved += service_requirements.locked_requirements(manifest)
        else:
            resolved += service_requirements.requirements(manifest)
    return list(dict.fromkeys(named)), resolved


def test_ci_installs_the_backend_it_claims_to_test() -> None:
    """The pySigma tests above `importorskip`. A skip in CI would be a green lie.

    CI installed the API's dependencies from a hand-curated pip list that did
    not name pysigma, so the real backend path had never once run in CI while
    the published image installed it from the lockfile and ran it.
    """
    services, requirements = _python_test_install_set()
    assert "api" in services, f"python-test must derive services/api's requirements; it names {services}"

    installed = {requirement.split("[")[0].split(">")[0].split("<")[0].split("=")[0].strip().lower() for requirement in requirements}
    assert "pysigma" in installed, "the job that runs these tests must install pysigma or they silently skip"
    assert "pysigma-backend-opensearch" in installed, "the OpenSearch backend is what rule_engine imports"

    # The floor is the measurement, not a preference: pysigma 0.11.0 through
    # 0.11.16 carry `from pyparsing import List` in `sigma/exceptions.py`, a
    # name pyparsing no longer re-exports, so importing the package raises on
    # any current pyparsing. A release below the floor cannot start, so the
    # question is the same whichever form the step produces — the job must not
    # be able to install one. `==` is checked by value because a pin below the
    # floor is worse than a range permitting one: it installs it every time.
    spec = next(r for r in requirements if re.match(r"pysigma\s*[=><]", r, re.I))
    if "==" in spec:
        pinned = tuple(int(p) for p in re.findall(r"\d+", spec.split("==", 1)[1])[:3])
        assert pinned >= (0, 11, 17), f"the lock pins pysigma {spec}, below the 0.11.17 floor that can actually import"
    else:
        assert ">=0.11.17" in spec, f"pysigma must be floored at 0.11.17; the job would install {spec}"


def test_the_yara_runner_is_installed_too() -> None:
    """`_run_yara` sits 260 lines below `_run_sigma` in the same module and
    degrades the same way — `([], "yara-python not installed")`, a clean empty
    result with no exception. The Sigma fix named one of the two; a job that
    installs pysigma and not yara-python has moved the blind spot rather than
    closed it."""
    _, requirements = _python_test_install_set()
    installed = {requirement.split("[")[0].split(">")[0].split("<")[0].split("=")[0].strip().lower() for requirement in requirements}
    assert "yara-python" in installed, "_run_yara returns no matches and no error when yara-python is absent"
