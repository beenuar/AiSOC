"""Mailbox remediation: the reproduction, the behaviour, and the negative controls.

The reproduction this file pins first is the one the gate found: before depth
7.1 the live-action registry held 79 builtin arms and not one of them could
touch a mailbox, so ``dispatcher.dispatch`` answered ``executor_not_found``
for ``purge_email``. That is recorded in
:func:`test_every_mailbox_verb_resolves_through_governed_dispatch`, which
fails on the pre-fix tree for exactly that reason.

Everything else here exists because its opposite has shipped in this
repository at least once:

* a dry run reporting a vendor call that never happened;
* a "purge" over mailboxes that never held the message, counted as a success;
* a rollback that returns ``True`` without contacting anything;
* a pinned vendor honoured without checking that vendor's credentials exist;
* a verification probe whose confirming answer has the polarity inverted.

The vendor payloads are the documented shapes — a Microsoft Graph ``message``
resource and a Gmail ``Message`` — and the HTTP layer is a real ``respx``
mock, so the request path, the URL and the body are exercised rather than
described. That is the point of
:class:`TestTheRequestShapeIsWhatTheVendorDocuments`: a mock that answers
whatever the reader asks for cannot notice a query that never requested the
field, which is how hostname and username came to be null on four of five
closed-finding readers.
"""

from __future__ import annotations

import json
import uuid

import httpx
import pytest
import respx
from app.clients import factories
from app.clients.m365_mail_client import RECOVERABLE_ITEMS, normalise_internet_message_id, quote_odata_string
from app.core.config import get_settings
from app.executors import mailbox
from app.executors.mailbox import (
    BlockSenderExecutor,
    PurgeEmailExecutor,
    choose_vendor,
)
from app.live_actions import builtins, dispatcher, registry
from app.live_actions.capability_contracts import (
    CAPABILITY_CONTRACTS,
    recipient_count_from,
    scaled_impact,
)
from app.live_actions.contract import ActionImpact, ApprovalRequirement, Reversal
from app.live_actions.investigation_reads import M365SearchMailboxes
from app.live_actions.models import LiveActionRequest, LiveActionStatus
from app.models.action import ActionRequest, ActionStatus, ActionType
from app.services.verification import PostActionVerifier, VerificationOutcome

MAILBOX_VERBS = ("search_mailboxes", "purge_email", "restore_email", "block_sender", "unblock_sender")
#: The four that change state. `search_mailboxes` is a native read in
#: `investigation_reads` with no ActionType and no legacy executor behind
#: it, so the adapter-shaped assertions below do not apply to it.
STATE_CHANGING_VERBS = ("purge_email", "restore_email", "block_sender", "unblock_sender")
VENDORS = ("m365", "google_workspace")

#: RFC 5737 documentation addresses and RFC 2606 names throughout. Nothing
#: here resolves, and that is asserted by the repo's own fixture conventions
#: rather than left to reviewer discipline.
MAILBOX = "alice@example.com"
SENDER = "billing@phish.example.net"
INTERNET_ID = "<CAF=20261011.0001@mail.example.net>"

M365_CREDENTIALS = {
    "azure_tenant_id": "00000000-0000-4000-8000-000000000001",
    "azure_client_id": "00000000-0000-4000-8000-000000000002",
    "azure_client_secret": "unit-test-placeholder",
}
GMAIL_CREDENTIALS = {
    # A structurally valid service-account document. The private key is only
    # ever used by a test that does not mint a token.
    "gws_service_account_key": json.dumps({"client_email": "svc@example.iam.gserviceaccount.com", "private_key": "-----BEGIN-----"}),
    "gws_subject_email": "soc@example.com",
}

#: A trimmed Microsoft Graph `message` resource, in the documented shape.
GRAPH_MESSAGE = {
    "id": "AAMkAGI2THVSAAA=",
    "internetMessageId": INTERNET_ID,
    "subject": "Action required: your invoice is overdue",
    "from": {"emailAddress": {"name": "Billing", "address": SENDER}},
    "toRecipients": [{"emailAddress": {"address": MAILBOX}}],
    "receivedDateTime": "2026-10-11T06:04:00Z",
    "parentFolderId": "AQMkADAwATM0MDAAMS0wAGZmYy1",
    "hasAttachments": True,
}

#: Gmail's `users.messages.list` answers id + threadId and nothing else.
GMAIL_LIST = {"messages": [{"id": "19a2f4c1d0e5b7a3", "threadId": "19a2f4c1d0e5b7a3"}], "resultSizeEstimate": 1}


@pytest.fixture(autouse=True)
def _registered() -> None:
    registry.reset_for_tests()
    builtins.register_builtin_executors(overwrite=True)


@pytest.fixture
def _enabled(monkeypatch: pytest.MonkeyPatch):
    """Turn the feature on for the duration of one test.

    ``get_settings`` is ``lru_cache``d, so the object is shared and the
    attribute is patched on the instance rather than the environment.
    """
    monkeypatch.setattr(get_settings(), "AISOC_FEATURE_MAILBOX_REMEDIATION", True, raising=False)
    return None


def _request(action_type: ActionType, target: str = MAILBOX, **params) -> ActionRequest:
    return ActionRequest(
        incident_id=uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        action_type=action_type,
        target=target,
        parameters=params,
    )


def _graph_token_route() -> None:
    respx.post(url__regex=r"https://login\.microsoftonline\.com/.*/oauth2/v2\.0/token").mock(
        return_value=httpx.Response(200, json={"access_token": "unit-test-token", "expires_in": 3600})
    )


# ───────────────────────── reproduction ──────────────────────────────────


@pytest.mark.parametrize("vendor", VENDORS)
@pytest.mark.parametrize("capability", MAILBOX_VERBS)
def test_every_mailbox_verb_resolves_through_governed_dispatch(vendor: str, capability: str) -> None:
    """The regression. All ten of these returned ``None`` before depth 7.1.

    Recorded against the pre-fix tree by driving the dispatcher directly: it
    logged ``live_action.unknown`` and answered ``executor_not_found`` for a
    phishing response that could block the sender's domain at the firewall
    and could not remove the message it arrived in.
    """
    assert registry.get_executor(vendor, capability) is not None, (
        f"{vendor}/{capability} does not resolve, so dispatcher.dispatch answers executor_not_found."
    )


@pytest.mark.asyncio
async def test_dispatch_no_longer_answers_executor_not_found() -> None:
    result = await dispatcher.dispatch(
        LiveActionRequest(capability="purge_email", vendor_id="m365", target=MAILBOX, dry_run=True, confidence=0.5)
    )
    assert result.error != "executor_not_found"


# ───────────────────────── off by default ────────────────────────────────


class TestOffByDefault:
    """A reach-out capability an upgrade must not silently acquire."""

    def test_the_flag_defaults_off(self) -> None:
        from app.core.config import ActionsSettings

        assert ActionsSettings.model_fields["AISOC_FEATURE_MAILBOX_REMEDIATION"].default is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize("action_type", [ActionType.PURGE_EMAIL, ActionType.BLOCK_SENDER])
    async def test_disabled_fails_and_says_why_rather_than_simulating(self, action_type: ActionType) -> None:
        executor = {
            ActionType.PURGE_EMAIL: PurgeEmailExecutor(),
            ActionType.BLOCK_SENDER: BlockSenderExecutor(),
        }[action_type]
        result = await executor.execute(_request(action_type, sender=SENDER, **M365_CREDENTIALS))
        assert result.status is ActionStatus.FAILED
        assert result.output["executed"] is False
        assert "AISOC_FEATURE_MAILBOX_REMEDIATION" in (result.error or "")

    @pytest.mark.asyncio
    async def test_the_read_is_gated_too(self) -> None:
        """Enumerating a tenant's mail is not a neutral act, so the read is gated with the writes."""
        result = await M365SearchMailboxes().execute(
            LiveActionRequest(
                capability="search_mailboxes",
                vendor_id="m365",
                target=MAILBOX,
                params={"internet_message_id": INTERNET_ID, **M365_CREDENTIALS},
            )
        )
        assert result.status is LiveActionStatus.FAILED
        assert "AISOC_FEATURE_MAILBOX_REMEDIATION" in (result.error or "")

    @pytest.mark.asyncio
    async def test_disabled_reads_differently_from_a_missing_credential(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Three causes, three next steps. A shared message sends an operator to the wrong one."""
        disabled = await PurgeEmailExecutor().execute(_request(ActionType.PURGE_EMAIL, **M365_CREDENTIALS))
        monkeypatch.setattr(get_settings(), "AISOC_FEATURE_MAILBOX_REMEDIATION", True, raising=False)
        uncredentialed = await PurgeEmailExecutor().execute(_request(ActionType.PURGE_EMAIL))
        assert disabled.error != uncredentialed.error
        assert "credentials" in (uncredentialed.error or "")


# ───────────────────────── a dry run is not a success ────────────────────


class TestADryRunNeverReportsAVendorCall:
    """``NotifySlackExecutor`` reported ``message_sent: true`` for a message it never sent."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize("vendor", VENDORS)
    async def test_dry_run_is_simulated_and_executed_is_false(self, vendor: str, _enabled) -> None:
        executor = registry.get_executor(vendor, "purge_email")
        assert executor is not None
        result = await executor.execute(
            LiveActionRequest(
                capability="purge_email",
                vendor_id=vendor,
                target=MAILBOX,
                params={**M365_CREDENTIALS, **GMAIL_CREDENTIALS, "internet_message_id": INTERNET_ID},
                dry_run=True,
            )
        )
        assert result.status is LiveActionStatus.SIMULATED
        assert result.details["executed"] is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_dry_run_makes_no_http_call_at_all(self, _enabled) -> None:
        """Stronger than checking the status: nothing may reach the network.

        Every route is mocked to raise, so a request of any kind fails the
        test with the URL rather than by relying on CI refusing egress.
        """
        tripwire = respx.route().mock(side_effect=AssertionError("a dry run made an HTTP call"))
        executor = registry.get_executor("m365", "purge_email")
        assert executor is not None
        result = await executor.execute(
            LiveActionRequest(
                capability="purge_email",
                vendor_id="m365",
                target=MAILBOX,
                params={**M365_CREDENTIALS, "internet_message_id": INTERNET_ID},
                dry_run=True,
            )
        )
        assert result.status is LiveActionStatus.SIMULATED
        assert not tripwire.called


# ───────────────────────── the vendor request shape ──────────────────────


class TestTheRequestShapeIsWhatTheVendorDocuments:
    """A mock that answers whatever is asked cannot notice an unasked field."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_m365_search_filters_on_the_bracketed_internet_message_id(self, _enabled) -> None:
        _graph_token_route()
        route = respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages").mock(
            return_value=httpx.Response(200, json={"value": [GRAPH_MESSAGE]})
        )
        result = await M365SearchMailboxes().execute(
            LiveActionRequest(
                capability="search_mailboxes",
                vendor_id="m365",
                target=MAILBOX,
                params={"internet_message_id": INTERNET_ID.strip("<>"), **M365_CREDENTIALS},
            )
        )
        assert result.status is LiveActionStatus.SUCCEEDED
        assert result.details["match_count"] == 1
        # Read the decoded parameters, not the raw URL: percent-encoding
        # would hide both of these assertions behind `%27%3C`.
        params = route.calls.last.request.url.params
        assert f"internetMessageId eq '{INTERNET_ID}'" == params["$filter"], (
            "Graph stores a Message-ID bracketed; an unbracketed filter matches nothing and reads as 'the message is not in that mailbox'."
        )
        assert "parentFolderId" in params["$select"], "restore needs the original folder, and only the search can read it"

    @pytest.mark.asyncio
    @respx.mock
    async def test_gmail_search_uses_the_documented_rfc822msgid_operator(self, _enabled) -> None:
        respx.post("https://oauth2.googleapis.com/token").mock(
            return_value=httpx.Response(200, json={"access_token": "unit-test-token", "expires_in": 3600})
        )
        route = respx.get(url__regex=r"https://gmail\.googleapis\.com/gmail/v1/users/.*/messages").mock(
            return_value=httpx.Response(200, json=GMAIL_LIST)
        )
        client = factories._gmail_client(GMAIL_CREDENTIALS)
        assert client is not None, "the factory refused credentials the fixture declares complete"
        # Minting a token needs a real RSA key; the search itself is what is
        # under test, so the token cache is primed directly.
        client._tokens[MAILBOX] = ("unit-test-token", 2**31)
        found = await client.search_messages(MAILBOX, internet_message_id=INTERNET_ID)
        assert found == GMAIL_LIST["messages"]
        assert "rfc822msgid" in str(route.calls.last.request.url)

    @pytest.mark.asyncio
    @respx.mock
    async def test_m365_purge_moves_to_recoverable_items_not_a_hard_delete(self, _enabled) -> None:
        _graph_token_route()
        respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages\?.*").mock(
            return_value=httpx.Response(200, json={"value": [GRAPH_MESSAGE]})
        )
        move = respx.post(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages/.*/move").mock(
            return_value=httpx.Response(201, json={**GRAPH_MESSAGE, "id": "AAMkNEWID=", "parentFolderId": "recoverableitems"})
        )
        deleted = respx.delete(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages/.*").mock(
            side_effect=AssertionError("purge must never issue a hard DELETE: it has no reverse")
        )

        result = await PurgeEmailExecutor().execute(_request(ActionType.PURGE_EMAIL, internet_message_id=INTERNET_ID, **M365_CREDENTIALS))

        assert result.status is ActionStatus.COMPLETED
        assert result.output["executed"] is True
        assert json.loads(move.calls.last.request.content)["destinationId"] == RECOVERABLE_ITEMS
        assert not deleted.called
        # What the rollback needs, carried out of the action that created it.
        assert result.rollback_data["restore_message_id"] == "AAMkNEWID="
        assert result.rollback_data["restore_folder_id"] == GRAPH_MESSAGE["parentFolderId"]


# ───────────────────────── nothing found is not a purge ──────────────────


class TestNothingFoundIsNotASuccess:
    @pytest.mark.asyncio
    @respx.mock
    async def test_a_mailbox_without_the_message_fails_rather_than_reporting_a_purge(self, _enabled) -> None:
        """A fan-out that counts empty mailboxes as purged publishes a meaningless number."""
        _graph_token_route()
        respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages\?.*").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        move = respx.post(url__regex=r".*/move").mock(side_effect=AssertionError("nothing to move"))
        result = await PurgeEmailExecutor().execute(_request(ActionType.PURGE_EMAIL, internet_message_id=INTERNET_ID, **M365_CREDENTIALS))
        assert result.status is ActionStatus.FAILED
        assert result.output["executed"] is False
        assert result.output["match_count"] == 0
        assert not move.called


# ───────────────────────── the rollback is real ──────────────────────────


class TestTheRollbackContactsTheVendor:
    """``unisolate_host`` resolved to nothing. This is the same shape, wider."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_purge_rollback_issues_a_move_back_to_the_original_folder(self, _enabled) -> None:
        _graph_token_route()
        move = respx.post(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages/.*/move").mock(
            return_value=httpx.Response(201, json={**GRAPH_MESSAGE, "id": "AAMkRESTORED="})
        )
        purged = await PurgeEmailExecutor().execute(
            _request(
                ActionType.PURGE_EMAIL,
                message_id=GRAPH_MESSAGE["id"],
                source_folder_id=GRAPH_MESSAGE["parentFolderId"],
                **M365_CREDENTIALS,
            )
        )
        assert purged.status is ActionStatus.COMPLETED
        # The credentials have to travel with the rollback; without them the
        # reverse resolves to "no credentials" and returns False, which is
        # the honest answer and a useless one.
        purged.output["credentials"] = M365_CREDENTIALS
        ok = await PurgeEmailExecutor().rollback(purged)
        assert ok is True
        assert move.call_count == 2
        assert json.loads(move.calls.last.request.content)["destinationId"] == GRAPH_MESSAGE["parentFolderId"]

    @pytest.mark.asyncio
    async def test_a_rollback_with_nothing_to_restore_returns_false_rather_than_true(self, _enabled) -> None:
        """``BaseExecutor.rollback`` defaults to ``False``; an optimistic ``True`` is worse than no rollback."""
        from app.models.action import ActionResult, BlastRadius

        incomplete = ActionResult(
            action_id=uuid.uuid4(),
            status=ActionStatus.COMPLETED,
            blast_radius=BlastRadius.MEDIUM,
            rollback_data={"vendor": "m365", "mailbox": MAILBOX},
        )
        assert await PurgeEmailExecutor().rollback(incomplete) is False

    def test_the_contract_names_a_reverse_that_exists(self) -> None:
        contract = CAPABILITY_CONTRACTS["purge_email"]
        assert contract.reversal is Reversal.PLATFORM
        assert contract.reverse_capability == "restore_email"
        assert registry.get_executor("m365", contract.reverse_capability) is not None
        assert registry.get_executor("google_workspace", contract.reverse_capability) is not None


# ───────────────────────── blast radius scales ───────────────────────────


class TestBlastRadiusScalesWithRecipients:
    """Gap-closure 10.2: "blast radius scales with the number of recipients"."""

    @pytest.mark.parametrize(
        ("count", "expected"),
        [
            (1, ActionImpact.MODERATE),
            (4, ActionImpact.MODERATE),
            (5, ActionImpact.HIGH),
            (24, ActionImpact.HIGH),
            (25, ActionImpact.SEVERE),
        ],
    )
    def test_the_ladder(self, count: int, expected: ActionImpact) -> None:
        assert scaled_impact("purge_email", {"recipient_count": count}) is expected

    def test_an_unknown_count_reads_as_one_not_as_zero(self) -> None:
        """Zero would let a caller omit the field to dodge the ladder."""
        assert recipient_count_from(None) == 1
        assert recipient_count_from({}) == 1
        assert recipient_count_from({"recipient_count": "not a number"}) == 1
        assert recipient_count_from({"recipient_count": 0}) == 1

    def test_a_recipient_list_counts_itself(self) -> None:
        assert recipient_count_from({"recipients": [MAILBOX, "bob@example.com"]}) == 2

    def test_scaling_never_lowers_an_impact(self) -> None:
        """The same one-way property the approval matrix has."""
        base = CAPABILITY_CONTRACTS["purge_email"].impact
        for count in (1, 2, 5, 25, 1000):
            assert scaled_impact("purge_email", {"recipient_count": count}).value in {
                base.value,
                ActionImpact.HIGH.value,
                ActionImpact.SEVERE.value,
            }

    def test_restore_is_deliberately_not_scaled(self) -> None:
        """Making the rollback harder to authorise than the action is how a containment becomes permanent."""
        assert scaled_impact("restore_email", {"recipient_count": 500}) is CAPABILITY_CONTRACTS["restore_email"].impact

    def test_a_twenty_five_recipient_campaign_requires_a_human_at_any_confidence(self) -> None:
        """The gap-closure plan's own 'Done when' clause, as an assertion."""
        from app.live_actions.approval_rules import evaluate

        for tier in ("L0", "L1", "L2", "L3", "L4"):
            decision = evaluate(
                impact=scaled_impact("purge_email", {"recipient_count": 25}),
                declared_approval=CAPABILITY_CONTRACTS["purge_email"].approval,
                confidence=1.0,
                tier=tier,
            )
            assert decision.requirement is ApprovalRequirement.MANDATORY_HUMAN
            assert decision.can_auto_execute is False

    def test_a_single_recipient_purge_still_needs_an_analyst(self) -> None:
        from app.live_actions.approval_rules import evaluate

        decision = evaluate(
            impact=scaled_impact("purge_email", {"recipient_count": 1}),
            declared_approval=CAPABILITY_CONTRACTS["purge_email"].approval,
            confidence=1.0,
            tier="L4",
        )
        assert decision.requirement is ApprovalRequirement.ANALYST


# ───────────────────────── verification re-queries ───────────────────────


class TestVerificationRequeriesTheMailbox:
    """10.2: "verification re-queries the mailboxes". The probe's confirming answer is an absence."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_purged_message_that_is_gone_verifies(self, _enabled) -> None:
        _graph_token_route()
        respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages\?.*").mock(
            return_value=httpx.Response(200, json={"value": []})
        )
        result = await PostActionVerifier().verify(
            ActionType.PURGE_EMAIL, MAILBOX, {"internet_message_id": INTERNET_ID, **M365_CREDENTIALS}
        )
        assert result.outcome is VerificationOutcome.VERIFIED

    @pytest.mark.asyncio
    @respx.mock
    async def test_a_message_still_present_fails_verification(self, _enabled) -> None:
        """The negative control for the polarity. Inverting the probe makes this pass as VERIFIED."""
        _graph_token_route()
        respx.get(url__regex=r"https://graph\.microsoft\.com/v1\.0/users/.*/messages\?.*").mock(
            return_value=httpx.Response(200, json={"value": [GRAPH_MESSAGE]})
        )
        result = await PostActionVerifier().verify(
            ActionType.PURGE_EMAIL, MAILBOX, {"internet_message_id": INTERNET_ID, **M365_CREDENTIALS}
        )
        assert result.outcome is VerificationOutcome.FAILED

    @pytest.mark.asyncio
    async def test_no_credentials_is_unverified_never_verified(self) -> None:
        result = await PostActionVerifier().verify(ActionType.PURGE_EMAIL, MAILBOX, {"internet_message_id": INTERNET_ID})
        assert result.outcome is VerificationOutcome.UNVERIFIED

    @pytest.mark.asyncio
    async def test_the_feature_being_off_is_unverified_never_verified(self) -> None:
        """Off must not certify: a probe that cannot run has not confirmed anything."""
        result = await PostActionVerifier().verify(
            ActionType.PURGE_EMAIL, MAILBOX, {"internet_message_id": INTERNET_ID, **M365_CREDENTIALS}
        )
        assert result.outcome is VerificationOutcome.UNVERIFIED

    @pytest.mark.parametrize("action_type", [ActionType.PURGE_EMAIL, ActionType.RESTORE_EMAIL, ActionType.BLOCK_SENDER])
    def test_every_verb_declaring_a_probe_has_one_registered(self, action_type: ActionType) -> None:
        """A contract declaring a probe nothing can call is worse than declaring none."""
        assert CAPABILITY_CONTRACTS[action_type.value].has_verification_probe is True
        assert action_type in PostActionVerifier().probes


# ───────────────────────── vendor selection ──────────────────────────────


class TestVendorSelection:
    def test_a_pin_is_ignored_when_that_vendors_credentials_are_absent(self) -> None:
        """Honouring a pin blindly is how a dry run called a customer's Splunk."""
        assert choose_vendor({"alert_vendor": "m365", **GMAIL_CREDENTIALS}) == mailbox.GOOGLE_WORKSPACE

    def test_a_pin_wins_when_both_are_configured(self) -> None:
        both = {**M365_CREDENTIALS, **GMAIL_CREDENTIALS}
        assert choose_vendor({"alert_vendor": "gmail", **both}) == mailbox.GOOGLE_WORKSPACE
        assert choose_vendor({"alert_vendor": "m365", **both}) == mailbox.M365

    def test_no_credentials_selects_nothing(self) -> None:
        assert choose_vendor({}) == ""

    def test_the_adapter_pins_its_own_vendor(self) -> None:
        for vendor in VENDORS:
            for capability in STATE_CHANGING_VERBS:
                executor = registry.get_executor(vendor, capability)
                assert executor is not None
                # The pin is the concrete adapter's own attribute; the registry's
                # base type deliberately does not declare it.
                assert executor._vendor_pin == vendor  # type: ignore[attr-defined]  # noqa: SLF001

    def test_each_adapters_strip_list_is_its_factorys_key_set(self) -> None:
        """The hand-copied list is the shape that let a 'dry run' reach production Splunk."""
        expected = {
            "m365": set(mailbox.M365_CLIENT_PARAM_KEYS),
            "google_workspace": set(mailbox.GMAIL_CLIENT_PARAM_KEYS),
        }
        for vendor in VENDORS:
            for capability in STATE_CHANGING_VERBS:
                executor = registry.get_executor(vendor, capability)
                assert executor is not None
                # Same: an adapter internal asserted on purpose, absent from the base type.
                assert set(executor._credential_keys) == expected[vendor]  # type: ignore[attr-defined]  # noqa: SLF001

    @pytest.mark.parametrize(
        ("vendor", "factory", "credentials"),
        [
            ("m365", factories._m365_mail_client, M365_CREDENTIALS),
            ("google_workspace", factories._gmail_client, GMAIL_CREDENTIALS),
        ],
    )
    def test_stripping_the_declared_keys_disables_the_factory(self, vendor: str, factory, credentials: dict) -> None:
        """The behavioural claim behind the strip list."""
        full = {**M365_CREDENTIALS, **GMAIL_CREDENTIALS}
        assert factory(full) is not None
        declared = mailbox.M365_CLIENT_PARAM_KEYS if vendor == "m365" else mailbox.GMAIL_CLIENT_PARAM_KEYS
        assert factory({k: v for k, v in full.items() if k not in set(declared)}) is None


# ───────────────────────── scope honesty ─────────────────────────────────


class TestTheSenderBlockSaysItIsPerMailbox:
    @pytest.mark.asyncio
    @respx.mock
    async def test_the_summary_an_analyst_reads_states_the_scope(self, _enabled) -> None:
        """ "Sender blocked" without the scope means something the action did not do."""
        _graph_token_route()
        respx.post(url__regex=r".*/mailFolders/inbox/messageRules").mock(return_value=httpx.Response(201, json={"id": "rule-1"}))
        result = await BlockSenderExecutor().execute(_request(ActionType.BLOCK_SENDER, sender=SENDER, **M365_CREDENTIALS))
        assert result.status is ActionStatus.COMPLETED
        assert result.output["scope"] == "mailbox"
        assert "only" in result.output["summary"]
        assert "organisation-wide" in result.output["summary"] or "tenant-wide" in result.output["summary"]


# ───────────────────────── injection surfaces ────────────────────────────


class TestAttackerSuppliedValuesCannotCloseAQuery:
    """Every value here comes off a message a stranger sent to the customer."""

    def test_odata_single_quotes_are_doubled(self) -> None:
        assert quote_odata_string("o'brien@example.com") == "o''brien@example.com"

    def test_control_characters_are_dropped_rather_than_escaped(self) -> None:
        assert "\n" not in quote_odata_string("a\nb@example.com")

    def test_an_unbracketed_message_id_is_bracketed(self) -> None:
        assert normalise_internet_message_id("abc@example.net") == "<abc@example.net>"
        assert normalise_internet_message_id("<abc@example.net>") == "<abc@example.net>"

    @pytest.mark.parametrize(
        "payload",
        [
            "x in:anywhere from:ceo@example.com",
            'x" OR label:inbox',
            "x\nfrom:ceo@example.com",
            "subject:(secret)",
        ],
    )
    def test_gmail_refuses_a_query_value_rather_than_escaping_it(self, payload: str) -> None:
        """Refuse, do not escape: an escaped value that matches nothing reports a clean mailbox."""
        from app.clients.gmail_client import quote_gmail_query_value

        with pytest.raises(ValueError):
            quote_gmail_query_value(payload)

    def test_an_ordinary_message_id_is_accepted(self) -> None:
        from app.clients.gmail_client import quote_gmail_query_value

        assert quote_gmail_query_value(INTERNET_ID) == INTERNET_ID.strip("<>")
