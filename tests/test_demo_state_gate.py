"""Tests for `scripts/check_demo_state_gated.py`.

The gate it replaces recognises *shapes* — `fallbackData:`, `set*(MOCK_…)`,
`?? MOCK_…`. Each was added after a specific escape, so each only knows the
syntax that got past it last time. `SLADashboard.tsx` wrote the same defect as
a ternary and nothing matched: `fallbackData: demoFallback(MOCK_SLA_METRICS)`
on line 446, correct and accepted, then `const metrics = isValidMetrics ?
rawMetrics : MOCK_SLA_METRICS` on line 457.

Two properties decide whether this gate is worth keeping, and both are
asserted here.

It has to catch a read no pattern list anticipated — the ternary, a factory
call, a constant assembled out of another constant — and it has to catch a
component that decides for itself that it is a demo.

And it has to stay *quiet* on the four ways this tree legitimately gates:
the read's own multi-line statement, an enclosing `if`, an early return, and
a local derived from the gate. A gate that rejects working code is a gate
somebody switches off, which is worse than the hole it closes. Roughly half
the cases below are the quiet half for that reason.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "scripts"))

import check_demo_state_gated as gate  # noqa: E402


def _tree(tmp_path: Path, relative: str, source: str) -> Path:
    """A fake `apps/web/src` so findings report real-looking paths."""
    root = tmp_path / "apps" / "web" / "src"
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(source, encoding="utf-8")
    return root


def _findings(tmp_path: Path, source: str, relative: str = "components/x/View.tsx") -> list[str]:
    problems, _matched = gate.findings(_tree(tmp_path, relative, source))
    return problems


# ── The reads it must catch ──────────────────────────────────────────────────

#: Verbatim from `SLADashboard.tsx` before the fix.
TERNARY_BYPASS = """\
'use client';
import useSWR from 'swr';
import { demoFallback } from '@/lib/demoFallback';

const MOCK_SLA_METRICS: SLAMetrics = {
  overall: { total_alerts: 847, total_breaches: 23, breach_rate: 2.7 },
};

export function SLADashboard() {
  const { data: rawMetrics } = useSWR('/api/v1/sla/metrics', fetcher, {
    fallbackData: demoFallback(MOCK_SLA_METRICS),
  });
  const isValidMetrics = rawMetrics && typeof rawMetrics.overall === 'object';
  const metrics = isValidMetrics ? rawMetrics : MOCK_SLA_METRICS;
  return <div>{metrics.overall.total_alerts}</div>;
}
"""


def test_a_correctly_gated_fallback_does_not_excuse_an_ungated_ternary(tmp_path):
    """The whole point: one gated read in a file is not a gated file.

    Both the older checks ask "does this file mention `canUseDemoData`?" at
    some point, which this file does.
    """
    problems = _findings(tmp_path, TERNARY_BYPASS, "components/sla/SLADashboard.tsx")

    assert len(problems) == 1
    assert "MOCK_SLA_METRICS" in problems[0]
    # The ungated ternary, not the gated `fallbackData` three lines above it.
    assert problems[0].startswith("apps/web/src/components/sla/SLADashboard.tsx:14")


#: Verbatim shape from `CaseWorkspace.tsx`. No constant is named anywhere, so
#: the naming convention cannot see it — and the id comes from the route
#: param, so the invention wears the id of the case the analyst opened.
FACTORY_CALL = """\
'use client';

function buildDemoCase(id: string): Case {
  return { id, title: 'Suspected lateral movement from finance subnet' };
}

export function CaseWorkspace({ caseId }: { caseId: string }) {
  const { data, error } = useSWR(['case', caseId], () => casesApi.get(caseId));
  const useFallback = !!error;
  const caseRecord = data ?? (useFallback ? buildDemoCase(caseId) : undefined);
  return <h1>{caseRecord?.title}</h1>;
}
"""


def test_it_catches_a_factory_that_no_naming_convention_covers(tmp_path):
    problems = _findings(tmp_path, FACTORY_CALL, "components/cases/CaseWorkspace.tsx")

    assert len(problems) == 1
    assert "buildDemoCase" in problems[0]


#: `EASMView.tsx` put its headline counts beyond the convention by deriving
#: them: the fabrication is in `SUMMARY`, which is not a `MOCK_*` name.
DERIVED_CONSTANT = """\
const MOCK_ASSETS = [
  { host: 'vpn.example.com', status: 'critical', ports: 3 },
];

const SUMMARY = {
  totalAssets: MOCK_ASSETS.length,
  riskScore: 72,
};

export function EASMView() {
  return <p>{SUMMARY.riskScore}</p>;
}
"""


def test_it_follows_a_fabrication_into_the_constant_assembled_from_it(tmp_path):
    problems = _findings(tmp_path, DERIVED_CONSTANT, "components/easm/EASMView.tsx")

    assert len(problems) == 1
    assert "SUMMARY" in problems[0]


#: Verbatim shape from `HuntView.tsx`.
LOCAL_DEMO_STATE = """\
export function HuntView() {
  const [demoMode, setDemoMode] = useState(false);
  const run = async () => {
    try {
      setResults(await huntApi.search(q));
    } catch {
      setDemoMode(true);
    }
  };
  return <span>{demoMode ? 'Sample data' : 'Live backend'}</span>;
}
"""


def test_it_catches_a_component_deciding_for_itself_that_it_is_a_demo(tmp_path):
    problems = _findings(tmp_path, LOCAL_DEMO_STATE, "components/hunt/HuntView.tsx")

    assert len(problems) == 1
    assert "demoMode" in problems[0]
    assert "property of the deployment" in problems[0]


def test_a_disclosure_string_is_not_demo_state(tmp_path):
    """`sampleNotice` holds the backend's own words about why data is sample.

    Banning it would push authors toward showing sample data with no notice
    at all, which is the failure this whole area exists to prevent.
    """
    source = """\
export function HuntView() {
  const [sampleNotice, setSampleNotice] = useState<string | null>(null);
  return <p>{sampleNotice}</p>;
}
"""
    assert _findings(tmp_path, source) == []


# ── The four ways this tree legitimately gates ───────────────────────────────


@pytest.mark.parametrize(
    ("label", "source"),
    [
        (
            "the read's own statement, wrapped across lines",
            """\
const MOCK_ALERTS = [{ host: 'WIN-DC01', severity: 'high' }];

export function AlertsView() {
  const { data } = useSWR(['alerts'], () => alertsApi.list(), {
    fallbackData: demoFallback({
      alerts: MOCK_ALERTS,
      total: MOCK_ALERTS.length,
    }),
  });
  return <div>{data?.total}</div>;
}
""",
        ),
        (
            "an enclosing block whose condition is the gate",
            """\
const MOCK_RULES = [{ name: 'Encoded PowerShell', hits: 4 }];

export function DetectionCatalog() {
  const load = async () => {
    try {
      setRules(await detectionApi.list());
    } catch (err) {
      if (canUseDemoData()) {
        setRules(MOCK_RULES);
      } else {
        setRules([]);
      }
    }
  };
  return <div onClick={load} />;
}
""",
        ),
        (
            "an early return that withholds the whole render",
            """\
const MOCK_HANDOFF_ITEMS = [{ analyst: 'Sarah Chen', open: 4 }];

export function ShiftsView() {
  const [items] = useState(MOCK_HANDOFF_ITEMS);
  if (!canUseDemoData()) {
    return <NotYetWired title="Shift handoff" />;
  }
  return <ul>{items.length}</ul>;
}
""",
        ),
        (
            "a local derived from the gate",
            """\
const DEMO_CONNECTORS = [{ name: 'CrowdStrike EDR', events: 412 }];

export function SettingsView() {
  const { data, error } = useSWR('connectors', () => connectorsApi.list());
  const useFallback = !!error && canUseDemoData();
  const connectors = data?.connectors ?? (useFallback ? DEMO_CONNECTORS : []);
  return <div>{connectors.length}</div>;
}
""",
        ),
    ],
)
def test_it_stays_quiet_on_correctly_gated_code(tmp_path, label, source):
    assert _findings(tmp_path, source) == [], label


def test_a_scalar_anchor_is_not_a_fabricated_record(tmp_path):
    """`MOCK_BASE` pins the mocks to a fixed instant so SSR and the client agree.

    It is a number. Flagging it teaches authors that the gate cries wolf,
    which is how a gate ends up with a `# noqa` beside every call site.
    """
    source = """\
const MOCK_BASE = new Date('2026-05-06T12:00:00Z').getTime();
const ago = (mins: number) => new Date(MOCK_BASE - mins * 60 * 1000).toISOString();

export function View() {
  return <time>{ago(5)}</time>;
}
"""
    assert _findings(tmp_path, source) == []


def test_a_component_that_renders_a_gated_mock_is_not_itself_fabricated(tmp_path):
    """Promoting the component would flag its own definition as a read of itself."""
    source = """\
const DEMO_ROWS = [{ host: 'WIN-DC01', hits: 2 }];

export function DashboardView() {
  const { data } = useSWR('rows', fetcher, { fallbackData: demoFallback(DEMO_ROWS) });
  return <div>{data?.length}</div>;
}
"""
    assert _findings(tmp_path, source) == []


def test_tests_may_name_a_fabricated_constant(tmp_path):
    """Naming the mock is how a test proves the mock does not render."""
    source = """\
const FABRICATED = ['WORKSTATION-042'];
it('renders none of it', () => {
  expect(screen.queryByText(FABRICATED[0])).toBeNull();
});
"""
    assert _findings(tmp_path, source, "components/x/View.test.tsx") == []


# ── The ratchet, and refusing an empty tree ──────────────────────────────────


def test_the_ratchet_is_empty(tmp_path):
    """A gate seeded with its own exceptions has never been true.

    Not a style preference: `KNOWN_UNGATED` is checked in both directions, so
    an entry that stops matching fails the build. Starting empty is what makes
    the first entry a deliberate act somebody has to justify.
    """
    assert gate.KNOWN_UNGATED == {}


def test_a_stale_ratchet_entry_fails_rather_than_lingering(tmp_path, monkeypatch):
    monkeypatch.setitem(gate.KNOWN_UNGATED, ("components/gone/Ghost.tsx", "MOCK_GHOST"), "removed last year")
    root = _tree(tmp_path, "components/x/View.tsx", "export const x = 1;\n")

    monkeypatch.chdir(root.parents[2])
    monkeypatch.setattr(sys, "argv", ["check_demo_state_gated.py"])

    assert gate.main() == 1


def test_it_refuses_a_tree_it_never_opened(tmp_path, monkeypatch):
    """`found nothing` and `scanned nothing` must not print the same word."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["check_demo_state_gated.py"])

    assert gate.main() == 2


def test_it_refuses_a_present_but_empty_source_tree(tmp_path, monkeypatch):
    (tmp_path / "apps" / "web" / "src").mkdir(parents=True)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["check_demo_state_gated.py"])

    assert gate.main() == 2


def test_the_live_console_passes(tmp_path):
    """The gate is wired into CI, so `main` has to be clean under it."""
    problems, _matched = gate.findings(_REPO / "apps" / "web" / "src")

    assert problems == [], "\n".join(problems)
