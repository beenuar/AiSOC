"""Probes for the three disruptive endpoint verbs that had none.

``kill_process``, ``quarantine_file`` and ``run_script`` change an endpoint,
and their success was inferred from a vendor API accepting the request. That
is the same claim the isolation probe used to make when it returned
``bool(device_id)`` — "the host exists", offered as "the host is contained".

Two of the three now have a real read-back and the third does not, for a
reason recorded on its contract:

* ``kill_process``    — RTR ``ps``, checking the PID is gone.
* ``quarantine_file`` — RTR ``ls``, checking the path is gone.
* ``run_script``      — nothing to probe. The platform does not know what an
  arbitrary script was supposed to do, so no read-back can confirm it did
  it. It is mandatory-human, and the approver is the verification.

``run_av_scan`` is here too. It is not disruptive, but it is *automatic*, and
Defender replies ``Pending`` the instant it queues the sweep — so its
response is the clearest case in the service of an acknowledgement standing
in for an effect.

Most of what follows is about the indeterminate case, because that is where
these probes can do harm. A probe that cannot reach the vendor, or cannot
parse what the vendor said, must answer "I do not know". Answering "yes"
certifies a process that is still running.
"""

from __future__ import annotations

import inspect
import json
from typing import Any
from unittest.mock import AsyncMock, create_autospec

import httpx
import pytest
import respx
from app.clients.crowdstrike_rtr import CrowdStrikeRTRClient
from app.clients.defender_client import DefenderClient
from app.executors.endpoint import AV_SCAN_ACTION
from app.live_actions.capability_contracts import CAPABILITY_CONTRACTS
from app.models.action import ActionType
from app.services import verification as module
from app.services.verification import (
    _DEFAULT_PROBES,
    _probe_kill_process,
    _probe_quarantine_file,
    _probe_run_av_scan,
)

CS_PARAMS: dict[str, Any] = {"cs_client_id": "cid", "cs_client_secret": "unit-test-placeholder", "pid": 4242}
FILE_PARAMS: dict[str, Any] = {
    "cs_client_id": "cid",
    "cs_client_secret": "unit-test-placeholder",
    "file_path": "C:\\Users\\Public\\evil.exe",
}

#: A realistic RTR ``ps`` listing: header row, then one line per process with
#: the PID in the first column.
PS_OUTPUT = "PID    PPID   ImageName\n4242   1180   evil.exe\n1180   712    explorer.exe\n"
PS_OUTPUT_WITHOUT_TARGET = "PID    PPID   ImageName\n1180   712    explorer.exe\n"


def _cs(monkeypatch: pytest.MonkeyPatch, **methods: Any) -> AsyncMock:
    client = AsyncMock()
    client.get_device_id = AsyncMock(return_value="dev-1")
    for name, value in methods.items():
        setattr(client, name, AsyncMock(return_value=value))
    monkeypatch.setattr(module, "_cs_client", lambda params: client)
    return client


class TestKillProcessProbe:
    @pytest.mark.asyncio
    async def test_a_pid_gone_from_the_table_verifies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _cs(monkeypatch, is_process_running=False)
        assert await _probe_kill_process("WKSTN-01", CS_PARAMS) is True

    @pytest.mark.asyncio
    async def test_a_pid_still_in_the_table_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The alarm this probe exists for: RTR took the kill, nothing died."""
        _cs(monkeypatch, is_process_running=True)
        assert await _probe_kill_process("WKSTN-01", CS_PARAMS) is False

    @pytest.mark.asyncio
    async def test_an_unreadable_process_table_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _cs(monkeypatch, is_process_running=None)
        assert await _probe_kill_process("WKSTN-01", CS_PARAMS) is None

    @pytest.mark.asyncio
    async def test_no_crowdstrike_credentials_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The SentinelOne arm lands here: it kills by hash and lists nothing."""
        monkeypatch.setattr(module, "_cs_client", lambda params: None)
        assert await _probe_kill_process("WKSTN-01", CS_PARAMS) is None

    @pytest.mark.asyncio
    async def test_a_missing_pid_is_indeterminate_not_verified(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Without a PID there is no question to ask.

        Falling back to ``process_name`` would confirm the wrong thing on a
        host running two copies of it, and defaulting to True would certify
        every kill the S1 arm ever made.
        """
        client = _cs(monkeypatch, is_process_running=False)
        assert await _probe_kill_process("WKSTN-01", {"cs_client_id": "c", "cs_client_secret": "s"}) is None
        client.is_process_running.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_a_non_numeric_pid_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _cs(monkeypatch, is_process_running=False)
        assert await _probe_kill_process("WKSTN-01", {**CS_PARAMS, "pid": "not-a-pid"}) is None

    @pytest.mark.asyncio
    async def test_an_unresolvable_host_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A renamed host is not the same fact as "the kill did not take"."""
        client = _cs(monkeypatch, is_process_running=False)
        client.get_device_id = AsyncMock(return_value=None)
        assert await _probe_kill_process("WKSTN-01", CS_PARAMS) is None


class TestQuarantineFileProbe:
    @pytest.mark.asyncio
    async def test_a_removed_file_verifies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _cs(monkeypatch, path_exists=False)
        assert await _probe_quarantine_file("WKSTN-01", FILE_PARAMS) is True

    @pytest.mark.asyncio
    async def test_a_file_still_on_disk_fails(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _cs(monkeypatch, path_exists=True)
        assert await _probe_quarantine_file("WKSTN-01", FILE_PARAMS) is False

    @pytest.mark.asyncio
    async def test_an_unreadable_path_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _cs(monkeypatch, path_exists=None)
        assert await _probe_quarantine_file("WKSTN-01", FILE_PARAMS) is None

    @pytest.mark.asyncio
    async def test_no_file_path_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = _cs(monkeypatch, path_exists=False)
        assert await _probe_quarantine_file("WKSTN-01", {"cs_client_id": "c", "cs_client_secret": "s"}) is None
        client.path_exists.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_the_sentinelone_arm_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """S1 fetches the file into the forensics vault; it does not remove it.

        So its absence is not the effect, and probing for one would report
        FAILED for an arm that worked correctly.
        """
        monkeypatch.setattr(module, "_cs_client", lambda params: None)
        assert await _probe_quarantine_file("WKSTN-01", {"s1_console_url": "https://x", "s1_api_token": "t"}) is None


class TestRunAVScanProbe:
    @pytest.mark.asyncio
    async def test_a_succeeded_scan_verifies(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mde = AsyncMock()
        mde.get_machine_action = AsyncMock(return_value={"id": "act-1", "status": "Succeeded"})
        monkeypatch.setattr(module, "_mde_client", lambda params: mde)
        assert await _probe_run_av_scan("WKSTN-01", {"mde_action_id": "act-1"}) is True

    @pytest.mark.parametrize("status", ["Failed", "TimeOut", "Cancelled"])
    @pytest.mark.asyncio
    async def test_terminal_failures_are_a_real_alarm(self, monkeypatch: pytest.MonkeyPatch, status: str) -> None:
        mde = AsyncMock()
        mde.get_machine_action = AsyncMock(return_value={"id": "act-1", "status": status})
        monkeypatch.setattr(module, "_mde_client", lambda params: mde)
        assert await _probe_run_av_scan("WKSTN-01", {"mde_action_id": "act-1"}) is False

    @pytest.mark.parametrize("status", ["Pending", "InProgress"])
    @pytest.mark.asyncio
    async def test_a_running_scan_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch, status: str) -> None:
        """Where the immediate post-dispatch probe lands nearly every time.

        Reporting VERIFIED here would certify a sweep that has not started,
        which is exactly the state Defender returns from the executor.
        """
        mde = AsyncMock()
        mde.get_machine_action = AsyncMock(return_value={"id": "act-1", "status": status})
        monkeypatch.setattr(module, "_mde_client", lambda params: mde)
        assert await _probe_run_av_scan("WKSTN-01", {"mde_action_id": "act-1"}) is None

    @pytest.mark.asyncio
    async def test_it_finds_the_newest_scan_when_no_action_id_was_passed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mde = AsyncMock()
        mde.find_machine = AsyncMock(return_value={"id": "mde-1"})
        mde.list_machine_actions = AsyncMock(return_value=[{"id": "act-7"}])
        mde.get_machine_action = AsyncMock(return_value={"id": "act-7", "status": "Succeeded"})
        monkeypatch.setattr(module, "_mde_client", lambda params: mde)

        assert await _probe_run_av_scan("WKSTN-01", {}) is True
        mde.list_machine_actions.assert_awaited_once_with("mde-1", AV_SCAN_ACTION, limit=5)

    @pytest.mark.asyncio
    async def test_it_asks_for_av_scans_and_not_some_other_action_type(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The wrong action type would read back a different action's status.

        A host that had a forensic package collected an hour ago would report
        its AV scan as Succeeded on the strength of that.
        """
        assert AV_SCAN_ACTION == "RunAntiVirusScan"

    @pytest.mark.asyncio
    async def test_no_defender_credentials_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(module, "_mde_client", lambda params: None)
        assert await _probe_run_av_scan("WKSTN-01", {}) is None

    @pytest.mark.asyncio
    async def test_a_host_with_no_scan_history_is_indeterminate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mde = AsyncMock()
        mde.find_machine = AsyncMock(return_value={"id": "mde-1"})
        mde.list_machine_actions = AsyncMock(return_value=[])
        monkeypatch.setattr(module, "_mde_client", lambda params: mde)
        assert await _probe_run_av_scan("WKSTN-01", {}) is None


class TestTheRTRReadCommands:
    """The client half, against mocked HTTP rather than a mocked client.

    A probe that calls a correct client method on a client that parses the
    vendor wrongly is still a probe that certifies falsely.
    """

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_pid_present_in_the_listing_reads_as_running(self) -> None:
        _mock_rtr(stdout=PS_OUTPUT)
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.is_process_running("dev-1", 4242) is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_pid_absent_from_the_listing_reads_as_gone(self) -> None:
        _mock_rtr(stdout=PS_OUTPUT_WITHOUT_TARGET)
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.is_process_running("dev-1", 4242) is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_pid_appearing_only_as_a_parent_reads_as_gone(self) -> None:
        """Only the first column is a PID.

        A surviving child listing the killed process as its parent would
        otherwise report the kill as failed on every run.
        """
        _mock_rtr(stdout="PID    PPID   ImageName\n9001   4242   child.exe\n")
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.is_process_running("dev-1", 4242) is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_output_that_is_not_a_process_table_is_indeterminate(self) -> None:
        """The guard against a false confirmation from an unparsed response.

        If RTR returns an error page, a prompt, or a format this does not
        understand, no PID is found — and "no PID found" would otherwise read
        as "the process is gone".
        """
        _mock_rtr(stdout="Access denied. The user is not authorized to run this command.")
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.is_process_running("dev-1", 4242) is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_incomplete_command_is_indeterminate(self) -> None:
        """An offline agent leaves the batch entry incomplete."""
        _mock_rtr(stdout="", complete=False)
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.is_process_running("dev-1", 4242) is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_host_missing_from_the_batch_response_is_indeterminate(self) -> None:
        respx.post("https://api.crowdstrike.com/oauth2/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
        respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-init-session/v1").mock(
            return_value=httpx.Response(200, json={"batch_id": "b-1"})
        )
        respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-command/v1").mock(
            return_value=httpx.Response(200, json={"combined": {"resources": {"some-other-host": {"stdout": PS_OUTPUT}}}})
        )
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.is_process_running("dev-1", 4242) is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_non_200_is_indeterminate(self) -> None:
        respx.post("https://api.crowdstrike.com/oauth2/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
        respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-init-session/v1").mock(
            return_value=httpx.Response(200, json={"batch_id": "b-1"})
        )
        respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-command/v1").mock(return_value=httpx.Response(403))
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.is_process_running("dev-1", 4242) is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_transport_failure_is_indeterminate(self) -> None:
        respx.post("https://api.crowdstrike.com/oauth2/token").mock(side_effect=httpx.ConnectError("unreachable"))
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.path_exists("dev-1", "C:\\evil.exe") is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_an_empty_listing_means_the_path_is_gone(self) -> None:
        """The one place an empty string is a result rather than an absence.

        ``ls`` on a removed path returns no stdout, so ``_read_only_command``
        has to distinguish "" from None or the quarantine could never verify.
        """
        _mock_rtr(stdout="")
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.path_exists("dev-1", "C:\\evil.exe") is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_listing_with_content_means_the_path_is_still_there(self) -> None:
        _mock_rtr(stdout="Directory listing for C:\\Users\\Public\\\n-rw-r--r--  evil.exe  184320\n")
        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        assert await client.path_exists("dev-1", "C:\\Users\\Public\\evil.exe") is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_reads_go_to_the_read_only_command_tier(self) -> None:
        """Not ``batch-active-responder-command``, which is where ``rm`` lives.

        A verification path that posts to the mutating endpoint is one typo
        away from deleting the thing it was asked to check.
        """
        seen: dict[str, Any] = {}

        def record(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            seen["body"] = request.read().decode()
            return httpx.Response(200, json={"combined": {"resources": {"dev-1": {"stdout": PS_OUTPUT, "complete": True}}}})

        respx.post("https://api.crowdstrike.com/oauth2/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
        respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-init-session/v1").mock(
            return_value=httpx.Response(200, json={"batch_id": "b-1"})
        )
        respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-command/v1").mock(side_effect=record)

        client = CrowdStrikeRTRClient(client_id="cid", client_secret="unit-test-placeholder")
        await client.is_process_running("dev-1", 4242)

        assert seen["url"].endswith("/real-time-response/combined/batch-command/v1")
        assert json.loads(seen["body"])["base_command"] == "ps"


def _mock_rtr(*, stdout: str, complete: bool = True) -> None:
    respx.post("https://api.crowdstrike.com/oauth2/token").mock(return_value=httpx.Response(200, json={"access_token": "t"}))
    respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-init-session/v1").mock(
        return_value=httpx.Response(200, json={"batch_id": "b-1"})
    )
    respx.post("https://api.crowdstrike.com/real-time-response/combined/batch-command/v1").mock(
        return_value=httpx.Response(200, json={"combined": {"resources": {"dev-1": {"stdout": stdout, "complete": complete}}}})
    )


class TestProbesCallTheirClientsWithSignaturesThatExist:
    """Autospec, for the reason this service has learned twice.

    Simulation mode never constructs a vendor client, so a wrong keyword is
    invisible until a live call raises ``TypeError``. It is worse in a probe
    than in an executor: ``PostActionVerifier.verify`` catches every
    exception and reports UNVERIFIED, so a probe calling a method that does
    not exist would degrade silently and permanently to "we could not check"
    — with a contract next to it declaring that we could.
    """

    @pytest.mark.asyncio
    async def test_kill_process_probe_matches_the_rtr_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = create_autospec(CrowdStrikeRTRClient, spec_set=True, instance=True)
        client.get_device_id.return_value = "dev-1"
        client.is_process_running.return_value = False
        monkeypatch.setattr(module, "_cs_client", lambda params: client)

        assert await _probe_kill_process("WKSTN-01", CS_PARAMS) is True
        client.is_process_running.assert_awaited_once_with("dev-1", 4242)

    @pytest.mark.asyncio
    async def test_quarantine_file_probe_matches_the_rtr_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = create_autospec(CrowdStrikeRTRClient, spec_set=True, instance=True)
        client.get_device_id.return_value = "dev-1"
        client.path_exists.return_value = False
        monkeypatch.setattr(module, "_cs_client", lambda params: client)

        assert await _probe_quarantine_file("WKSTN-01", FILE_PARAMS) is True
        client.path_exists.assert_awaited_once_with("dev-1", FILE_PARAMS["file_path"])

    @pytest.mark.asyncio
    async def test_av_scan_probe_matches_the_defender_client(self, monkeypatch: pytest.MonkeyPatch) -> None:
        client = create_autospec(DefenderClient, spec_set=True, instance=True)
        client.find_machine.return_value = {"id": "mde-1"}
        client.list_machine_actions.return_value = [{"id": "act-7"}]
        client.get_machine_action.return_value = {"id": "act-7", "status": "Succeeded"}
        monkeypatch.setattr(module, "_mde_client", lambda params: client)

        assert await _probe_run_av_scan("WKSTN-01", {}) is True
        client.list_machine_actions.assert_awaited_once_with("mde-1", AV_SCAN_ACTION, limit=5)
        client.get_machine_action.assert_awaited_once_with("act-7")

    def test_the_read_commands_are_real_methods_on_the_real_client(self) -> None:
        """An autospec of a class that lost a method passes vacuously.

        ``create_autospec`` builds from whatever the class has, so if
        ``is_process_running`` were deleted the tests above would fail on the
        attribute — but a *renamed* one would not be caught by anything that
        only asserts the probe's own behaviour against a mock.
        """
        for name in ("is_process_running", "path_exists"):
            method = getattr(CrowdStrikeRTRClient, name, None)
            assert method is not None, f"CrowdStrikeRTRClient.{name} is gone; the probe that calls it will report UNVERIFIED forever"
            assert inspect.iscoroutinefunction(method)


class TestTheContractsMatchWhatShipped:
    @pytest.mark.parametrize("capability", ["kill_process", "quarantine_file", "run_av_scan"])
    def test_the_new_probes_are_declared_and_registered(self, capability: str) -> None:
        assert CAPABILITY_CONTRACTS[capability].has_verification_probe is True
        assert ActionType(capability) in _DEFAULT_PROBES

    def test_run_script_still_reports_unverified_and_says_why(self) -> None:
        """The honest answer, not an absence.

        No read-back can confirm an arbitrary script did what it was meant to
        — the platform does not know what that was. The exit code says it
        ran, which is a different claim. An invented probe here would be one
        that cannot fail.
        """
        contract = CAPABILITY_CONTRACTS["run_script"]
        assert contract.has_verification_probe is False
        assert ActionType.RUN_SCRIPT not in _DEFAULT_PROBES
        assert "nothing to probe" in contract.verification_gap.lower()
