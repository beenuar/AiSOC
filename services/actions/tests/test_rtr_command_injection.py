"""GHSA-7q37-2wfw-xrx7: RTR command strings are built by interpolation.

Three sinks in this service interpolated caller-supplied values into a command
string that the Falcon agent executes on the endpoint as SYSTEM/root, with no
escaping:

    crowdstrike_rtr.py  rm '{file_path}'
    crowdstrike_rtr.py  ls '{path}'          (the post-quarantine probe, which
                                              solicits no approval of its own)
    endpoint.py         runscript -CloudFile='{script_name}' -CommandLine='{script_args}'

Each interpolation sits inside a single-quoted argument, so one `'` in the
value closes the argument and the rest is parsed as further RTR syntax.

The tests below use the exact payloads from the report. They assert two things
that have to hold together, because either alone is satisfiable by a useless
implementation: the payloads are refused, *and* ordinary Windows paths still
pass. A validator that rejects `C:\\Program Files (x86)\\...` is safe and makes
the containment verb unusable on the platform it is mostly used against.
"""

from __future__ import annotations

import pytest
from app.clients.crowdstrike_rtr import RtrArgumentError, quote_rtr_argument

#: Verbatim from the advisory's PoC §2.
PUBLISHED_PAYLOADS = [
    "/tmp/quarterly-report.pdf' & powershell -enc SQBFAFgA & echo '",
    "-Name x' & whoami & echo '",
    "/tmp/x' & id & echo '",
]


class TestThePublishedPayloadsAreRefused:
    @pytest.mark.parametrize("payload", PUBLISHED_PAYLOADS)
    def test_each_reported_payload_is_refused(self, payload: str) -> None:
        with pytest.raises(RtrArgumentError):
            quote_rtr_argument(payload, field="file_path")

    def test_the_error_names_the_field_so_an_operator_can_act_on_it(self) -> None:
        with pytest.raises(RtrArgumentError, match="script_args"):
            quote_rtr_argument(PUBLISHED_PAYLOADS[1], field="script_args")

    @pytest.mark.parametrize(
        "payload",
        [
            "a\nrm -rf /",  # a newline ends the command line
            "a\rb",
            "x```whoami```",  # backticks delimit the -Raw block runscript uses
            "a\x00b",  # truncation
        ],
    )
    def test_the_other_ways_out_of_the_argument_are_refused_too(self, payload: str) -> None:
        with pytest.raises(RtrArgumentError):
            quote_rtr_argument(payload, field="path")


class TestOrdinaryValuesStillWork:
    """A containment action that refuses real paths is not a control.

    These are the values the verb exists to handle. Inside a single-quoted
    argument `\\`, `(`, `)`, `$` and `&` are literal — they appeared in the
    published payloads only because the payload closed the quote first — so
    refusing them would buy nothing and break Windows.
    """

    @pytest.mark.parametrize(
        "value",
        [
            r"C:\Program Files (x86)\Vendor\agent.exe",
            r"C:\Users\j.smith\AppData\Local\Temp\evil.dll",
            "/var/lib/docker/overlay2/x$y/diff/bin/sh",
            "/tmp/report (final).pdf",
            "cleanup.ps1",
            r"-Name Foo -Force -Path C:\tmp",
            "",
        ],
    )
    def test_a_real_path_or_argument_is_quoted_not_refused(self, value: str) -> None:
        assert quote_rtr_argument(value, field="file_path") == f"'{value}'"


class TestTheSinksUseIt:
    """The helper existing is not the fix; the sinks calling it is.

    Asserted against the rendered command string rather than by inspecting
    source, because a sink that stopped calling the helper would still pass a
    source-level check that only looked for the import.
    """

    @pytest.mark.asyncio
    async def test_quarantine_refuses_before_it_opens_an_rtr_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.clients import crowdstrike_rtr

        client = crowdstrike_rtr.CrowdStrikeRTRClient("id", "secret", "https://example.invalid")

        async def _fail(*_a: object, **_k: object) -> None:
            raise AssertionError("an RTR session was opened for a payload that should have been refused")

        monkeypatch.setattr(client, "_ensure_token", _fail)
        with pytest.raises(RtrArgumentError):
            await client.quarantine_file("device-1", PUBLISHED_PAYLOADS[0])

    @pytest.mark.asyncio
    async def test_the_unapproved_ls_probe_refuses_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from app.clients import crowdstrike_rtr

        client = crowdstrike_rtr.CrowdStrikeRTRClient("id", "secret", "https://example.invalid")

        async def _fail(*_a: object, **_k: object) -> None:
            raise AssertionError("the probe ran a command for a payload that should have been refused")

        monkeypatch.setattr(client, "_read_only_command", _fail)
        with pytest.raises(RtrArgumentError):
            await client.path_exists("device-1", PUBLISHED_PAYLOADS[2])
