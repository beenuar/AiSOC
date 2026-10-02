"""`make up` resolves a port conflict instead of refusing to start.

The friction this removes
--------------------------
`make up` used to stop dead when any one of sixteen host ports was taken,
and tell the operator to go edit `docker-compose.yml`. That is a hard stop
at step one of the documented quick start, triggered by the most common
condition in this audience's environment: a Postgres already on 5432, or
an Ollama already on 11434 — and the reader of that README is exactly the
person who has one.

Refusing beat the alternative at the time. Compose reports `Bind for
127.0.0.1:NNNN failed` against whichever container lost the race, half a
stack later. But the right answer to "that port is busy" is to use a
different one and say so, not to stop.

The two bugs this file pins, both found while building it
----------------------------------------------------------
**`SO_REUSEADDR` made the probe more permissive than the real bind.** With
it set, binding `127.0.0.1:5432` *succeeds* while another container holds
`0.0.0.0:5432`, so the detector reported the single most common conflict
as free. A probe easier to satisfy than the thing it predicts is worse
than no probe.

**`$(wildcard)` in a `:=` variable is evaluated when make parses the
file**, which is before the target that writes the overlay has run. The
first `make up` on a conflicting host therefore generated the overlay
correctly and then started compose without it, failing on exactly the
bind it had just resolved.
"""

from __future__ import annotations

import pathlib
import re
import socket
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "resolve_port_conflicts.py"
MAKEFILE = REPO / "Makefile"


@pytest.fixture(scope="module")
def module():  # noqa: ANN201
    sys.path.insert(0, str(REPO / "scripts"))
    import resolve_port_conflicts  # noqa: PLC0415

    return resolve_port_conflicts


class TestTheProbe:
    def test_it_sees_a_held_port(self, module) -> None:  # noqa: ANN001
        """The behaviour the whole thing rests on.

        This does not hold the wildcard address to simulate a container,
        even though that is the case that originally broke, because
        binding all interfaces in a committed file is a
        `py/bind-socket-all-network-interfaces` finding and this
        repository runs at zero open alerts.

        It does not need to. Once `SO_REUSEADDR` is gone, a loopback bind
        returns `EADDRINUSE` for a wildcard-held port just as it does for
        a loopback-held one — which is why the probe itself stopped
        binding the wildcard too. `test_it_does_not_set_so_reuseaddr` is
        the structural half of that guarantee; this is the behavioural
        half.
        """
        held = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        held.bind(("127.0.0.1", 0))
        held.listen(1)
        port = held.getsockname()[1]
        try:
            assert module._listening(port) is True
        finally:
            held.close()

    def test_it_reports_a_genuinely_free_port_as_free(self, module) -> None:  # noqa: ANN001
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        assert module._listening(port) is False

    def test_it_does_not_set_so_reuseaddr(self) -> None:
        """Pinned in the source, because the failure is silent.

        Nothing about the output of a probe with `SO_REUSEADDR` looks
        wrong; it simply answers "free" for a port that is not.
        """
        import ast

        # Parsed, not grepped: this function's own docstring explains why
        # SO_REUSEADDR is wrong, so a substring search matches the
        # explanation and reports the opposite of the truth.
        tree = ast.parse(SCRIPT.read_text())
        listening = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_listening")
        calls = [n.func.attr for n in ast.walk(listening) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
        assert "setsockopt" not in calls, (
            "the probe calls setsockopt again; with SO_REUSEADDR it is more permissive "
            "than the bind it is predicting and reports held ports as free"
        )

    def test_it_does_not_bind_all_interfaces(self) -> None:
        """Binding the wildcard adds nothing once SO_REUSEADDR is gone,
        and costs a CodeQL finding on a repository that runs at zero.

        Parsed rather than grepped, for the same reason as the test
        above: the function's docstring discusses `0.0.0.0` at length,
        so a substring search matches the explanation.
        """
        import ast

        tree = ast.parse(SCRIPT.read_text())
        listening = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "_listening")
        literals = [n.value for n in ast.walk(listening) if isinstance(n, ast.Constant)]
        assert "0.0.0.0" not in literals


class TestTheInventory:
    def test_it_is_read_from_doctor_rather_than_duplicated(self, module) -> None:  # noqa: ANN001
        """A second hand-maintained list is a second thing to forget.

        The original port list was missing Ollama's 11434 for exactly that
        reason, so the conflict this audience is most likely to hit was
        the one nothing checked.
        """
        ports = module.inventory()
        assert len(ports) >= 16, f"only {len(ports)} ports parsed out of doctor.sh"
        hosts = {p for p, _s, _c in ports}
        for expected in (5432, 3000, 8000, 11434):
            assert expected in hosts, f"port {expected} is not in the inventory"

    def test_every_entry_names_a_service_and_a_container_port(self, module) -> None:  # noqa: ANN001
        for host, service, container in module.inventory():
            assert 1 <= host <= 65535
            assert service and service.islower()
            assert 1 <= container <= 65535


class TestTheOverlay:
    def test_it_uses_override_not_a_plain_merge(self, module) -> None:  # noqa: ANN001
        """A plain override *appends*, leaving the conflicting binding
        published — so compose fails anyway, with the file in place and
        looking correct."""
        rendered = module.render([(5432, "postgres", 5432, 15432)])
        assert "ports: !override" in rendered
        assert '"15432:5432"' in rendered

    def test_it_says_which_port_moved_and_why(self, module) -> None:  # noqa: ANN001
        rendered = module.render([(11434, "ollama", 11434, 15434)])
        assert "11434" in rendered and "15434" in rendered
        assert "in use" in rendered

    def test_it_is_valid_yaml(self, module) -> None:  # noqa: ANN001
        yaml = pytest.importorskip("yaml")
        # `!override` is a compose-specific tag, so a plain loader rejects
        # it. Confirming the *structure* parses is still worth doing.
        rendered = module.render([(5432, "postgres", 5432, 15432)])
        parsed = yaml.safe_load(rendered.replace("ports: !override", "ports:"))
        assert parsed["services"]["postgres"]["ports"] == ["15432:5432"]


class TestTheMakefileWiring:
    def test_compose_resolves_the_overlay_lazily(self) -> None:
        """`:=` with `$(wildcard)` is evaluated at parse time, before the
        target that writes the overlay has run."""
        text = MAKEFILE.read_text()
        line = next(ln for ln in text.splitlines() if ln.startswith("COMPOSE ?="))
        assert "$(wildcard" not in line, (
            "COMPOSE resolves the overlay with $(wildcard), which make expands when it parses the file — before _ports can write it"
        )
        assert "docker-compose.ports.yml" in line

    def test_up_resolves_rather_than_refuses(self) -> None:
        text = MAKEFILE.read_text()
        body = text[text.index("\n_ports:") : text.index("\n_ports:") + 1200]
        assert "resolve_port_conflicts.py" in body
        assert "Not starting:" not in body, "make up still refuses on a port conflict instead of resolving it"

    def test_the_smoke_probe_uses_the_real_console_url(self) -> None:
        """A hardcoded 3000 probes nothing once the console has moved, and
        the failure branch reports that as 'an uncredentialed caller was
        served' — the most alarming thing the script can say, and untrue."""
        text = MAKEFILE.read_text()
        body = text[text.index("_anonymous_write_is_refused:") :][:1800]
        assert "$(console_url)/api/v1/cases" in body
        assert "localhost:3000/api/v1/cases" not in body

    def test_the_smoke_probe_reads_curl_without_doubling_the_status(self) -> None:
        """`curl -w '%{http_code}'` prints 000 on a connection failure
        *and* exits non-zero, so `|| echo 000` appended a second one. The
        result, 000000, matched neither branch and fell through to FAIL."""
        text = MAKEFILE.read_text()
        body = text[text.index("_anonymous_write_is_refused:") :][:1800]
        assert "|| echo 000)" not in body


class TestTheScriptRuns:
    def test_check_mode_changes_nothing(self) -> None:
        before = (REPO / "docker-compose.ports.yml").exists()
        subprocess.run([sys.executable, str(SCRIPT), "--check"], capture_output=True, cwd=REPO, timeout=120)
        assert (REPO / "docker-compose.ports.yml").exists() == before

    def test_it_has_a_docstring_explaining_the_override_tag(self) -> None:
        source = SCRIPT.read_text()
        assert "!override" in source
        assert re.search(r"appends", source), (
            "the reason `ports: !override` is mandatory is not written down, and a "
            "future edit to a plain override would fail in a way that looks correct"
        )
