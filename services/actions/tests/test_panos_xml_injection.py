"""GHSA-w754-prh8-m56j: the PAN-OS client must not let a caller write XML.

`_xml_register` and `_xml_unregister` interpolated `ip` and `tag` straight
into a user-id message with f-strings. Both values arrive from
`ActionRequest.parameters`, so a value that closed the `ip` attribute could
append further `<payload>` elements to the same message.

The consequence is worse than it first sounds, and is why this is graded high
rather than medium: the injected payload is *valid* PAN-OS, so calling
`block_ip` produced well-formed XML containing an `unregister` for whatever
address the caller chose. The containment action released a block instead of
applying one, and the firewall reported success.

The fix validates before it escapes. Escaping alone stops the injection and
still hands the firewall a string that is not an address, where it matches
nothing — so a block that never applied would report success, trading a loud
failure for a silent one.
"""

from __future__ import annotations

import xml.dom.minidom

import pytest

from app.clients.panos_client import PanOsClient

try:  # pragma: no cover - the pre-fix module has no such symbol
    from app.clients.panos_client import PanOsAddressError
except ImportError:  # the vulnerable tree, where the impact test must still run
    PanOsAddressError = ValueError  # type: ignore[assignment,misc]

#: Verbatim from the advisory. It closes the `ip` attribute, ends the
#: register payload, opens an unregister payload for an unrelated host, and
#: reopens a register so the message still parses.
REPORTED_PAYLOAD = (
    '"><tag><member>x</member></tag></entry></register></payload>'
    '<payload><unregister><entry ip="192.168.1.1">'
    "<tag><member>aisoc-blocked</member></tag></entry></unregister></payload>"
    '<payload><register><entry ip="127.0.0.2'
)

#: The same break-out through the tag, which the advisory's fix suggestion
#: also covers and which is reachable by the same route.
TAG_PAYLOAD = '</member></tag></entry></register></payload><payload><unregister><entry ip="10.0.0.1"><tag><member>aisoc-blocked'


@pytest.fixture
def client() -> PanOsClient:
    """A client with no transport — these assertions are about the payload."""
    return PanOsClient.__new__(PanOsClient)


class TestTheReportedInjectionIsRefused:
    def test_the_address_payload_cannot_reach_the_firewall(self, client: PanOsClient) -> None:
        with pytest.raises(PanOsAddressError):
            client._xml_register(REPORTED_PAYLOAD, "aisoc-blocked")

    def test_the_tag_payload_cannot_reach_the_firewall(self, client: PanOsClient) -> None:
        with pytest.raises(PanOsAddressError):
            client._xml_register("10.0.0.1", TAG_PAYLOAD)

    def test_unregister_is_refused_the_same_way(self, client: PanOsClient) -> None:
        """Both builders shared the defect, so both need the assertion."""
        with pytest.raises(PanOsAddressError):
            client._xml_unregister(REPORTED_PAYLOAD, "aisoc-blocked")

    @pytest.mark.parametrize("hostile", [REPORTED_PAYLOAD, '10.0.0.1"/><unregister>', "10.0.0.1</member>"])
    def test_a_block_never_emits_an_unregister(self, client: PanOsClient, hostile: str) -> None:
        """The impact, asserted without naming the fix.

        Deliberately does not require `PanOsAddressError`: a test that only
        asserts a new exception type fails against the vulnerable tree with
        `ImportError`, which proves the symbol is absent rather than that the
        defect is detected. Refusing and returning safe XML are both passes
        here, so this assertion is meaningful against any version of the
        module — and against the pre-fix one it fails on the payload, which
        is the point.
        """
        try:
            built = client._xml_register(hostile, "aisoc-blocked")
        except ValueError:
            return  # refused before building: the shipped behaviour
        assert "<unregister>" not in built, f"block_ip({hostile!r}) built a message telling the firewall to RELEASE a block"


class TestLegitimateInputStillWorks:
    """A fix that refused real addresses would be reverted, so pin them.

    PAN-OS registers three forms and all three are in use; validating only
    `ip_address()` would break CIDR and range blocks.
    """

    @pytest.mark.parametrize(
        "address",
        ["10.0.0.1", "192.168.1.254", "2001:db8::1", "10.0.0.0/24", "2001:db8::/32", "10.0.0.1-10.0.0.9"],
    )
    def test_accepted_address_forms(self, client: PanOsClient, address: str) -> None:
        message = client._xml_register(address, "aisoc-blocked")
        assert xml.dom.minidom.parseString(message)
        assert "<unregister>" not in message
        assert address in message

    def test_a_host_bit_in_a_network_is_accepted(self, client: PanOsClient) -> None:
        """`10.0.0.1/24` means the network to an operator, and to PAN-OS."""
        assert client._xml_register("10.0.0.1/24", "aisoc-blocked")

    @pytest.mark.parametrize("tag", ["aisoc-blocked", "SOC_Quarantine", "tier1.block", "a" * 127])
    def test_accepted_tag_forms(self, client: PanOsClient, tag: str) -> None:
        assert f"<member>{tag}</member>" in client._xml_register("10.0.0.1", tag)


class TestRefusalRatherThanEscaping:
    """A non-address must raise, not be escaped into the message.

    An escaped non-address is syntactically safe and semantically wrong: the
    firewall matches nothing and answers success, so a block that never
    applied reports as applied. That is a worse outcome than an error.
    """

    @pytest.mark.parametrize(
        "value",
        ["", "   ", "not-an-ip", "10.0.0.999", "10.0.0.1 10.0.0.2", "10.0.0.9-10.0.0.1", "example.com"],
    )
    def test_non_addresses_raise(self, client: PanOsClient, value: str) -> None:
        with pytest.raises(PanOsAddressError):
            client._xml_register(value, "aisoc-blocked")

    @pytest.mark.parametrize("tag", ["", "   ", "tag with space", "tag<x", "a" * 128, "tag&amp;"])
    def test_invalid_tags_raise(self, client: PanOsClient, tag: str) -> None:
        with pytest.raises(PanOsAddressError):
            client._xml_register("10.0.0.1", tag)

    def test_a_reversed_range_is_refused(self, client: PanOsClient) -> None:
        """Ordering is checked, not just parseability of both halves."""
        with pytest.raises(PanOsAddressError):
            client._xml_register("10.0.0.9-10.0.0.1", "aisoc-blocked")

    def test_mixed_family_range_is_refused(self, client: PanOsClient) -> None:
        with pytest.raises(PanOsAddressError):
            client._xml_register("10.0.0.1-2001:db8::1", "aisoc-blocked")
