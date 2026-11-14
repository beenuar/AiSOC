"""The matcher has to separate a failure-as-verdict from an honest failure.

`check_failure_is_not_a_verdict.py` reads TypeScript with a regex, because a
TS parser is not available to a Python gate here. A regex over source sees
text, so the thing worth testing is not "does it flag something" but "does it
flag the right thing and leave the right thing alone".

Both directions are here. A matcher that flagged every `catch` would pass a
one-sided suite and make the gate unusable on the first honest error handler
somebody wrote.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SCRIPTS))

spec = importlib.util.spec_from_file_location("check_failure_is_not_a_verdict", SCRIPTS / "check_failure_is_not_a_verdict.py")
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


#: Each is a real shape. The first is the one that shipped.
BAD = {
    "the bare catch that shipped": """
        try {
          const r = await threatIntelApi.lookup(query.trim());
          setResult(r);
        } catch {
          setNotFound(true);
        }
    """,
    "a named catch": """
        try { await check(ioc); } catch (err) { setClean(true); }
    """,
    "a verdict object in a catch": """
        try { r = await scan(h); } catch (e) { setResult({ status: 'clean' }); }
    """,
    "a rejection handler": """
        const r = await scan(hash).catch(() => ({ verdict: 'benign' }));
    """,
    "a nullish fallback to a verdict": """
        const outcome = data?.result ?? { malicious: false };
    """,
    "a not-malicious flag in a catch": """
        try { await lookup(ip); } catch { setState({ isMalicious: false }); }
    """,
}

GOOD = {
    "naming the failure": """
        try { setResult(await lookup(ioc)); }
        catch (err) { setError(`Lookup failed — ${err.message}. This says nothing about ${ioc}.`); }
    """,
    "rethrowing": """
        try { await lookup(ioc); } catch (err) { throw err; }
    """,
    "logging only": """
        try { await refresh(); } catch (err) { console.warn('refresh failed', err); }
    """,
    "an empty list is not a verdict": """
        try { setRows(await list()); } catch { setRows([]); setError('could not load'); }
    """,
    "a three-state outcome": """
        try { return { status: 'match', indicator }; }
        catch { return { status: 'failed', reason: 'the service could not be reached' }; }
    """,
    "prose that mentions clean": """
        // A failed lookup must never render as clean. status: 'clean' is only
        // for an answer from the store.
        try { await lookup(ioc); } catch { setError('not checked'); }
    """,
    "a clean verdict on the success path": """
        const response = await request('/api/v1/threat-intel/indicators');
        return match ? { status: 'match', indicator: match } : { status: 'clean' };
    """,
}


@pytest.mark.parametrize("label", sorted(BAD))
def test_the_dangerous_shape_is_flagged(label: str) -> None:
    assert gate._findings(BAD[label], "probe.tsx"), f"{label!r} was not flagged"


@pytest.mark.parametrize("label", sorted(GOOD))
def test_an_honest_handler_is_not(label: str) -> None:
    findings = gate._findings(GOOD[label], "probe.tsx")
    assert not findings, f"{label!r} was flagged: {findings}"


def test_the_live_tree_is_clean() -> None:
    """The gate's own subject. Reported with the file count, so a scan that
    silently read nothing is not mistaken for a clean tree."""
    findings, scanned = gate.scan()
    assert scanned > 100, f"only {scanned} files scanned — the roots are wrong"
    assert not findings, findings
