"""
Palo Alto Networks PAN-OS XML API client.

Wraps the subset of the PAN-OS XML API the AiSOC action layer needs:
add / remove an IP address to a dynamic address group via "register"
and "unregister" tag updates, and commit the candidate config when
the caller asks for it.

Why dynamic address groups (DAGs) instead of editing static address
objects: every reasonable PAN-OS deployment uses DAGs for
SOC-driven blocks because (a) tagged-IP changes don't require a
commit on PA-3000 / PA-5000 series boxes (they take effect inside
seconds via the user-id agent / runtime engine), (b) they round-trip
cleanly through Panorama, and (c) tagging is idempotent so AiSOC
can retry without leaving stale entries.

Credentials expected in ``ActionRequest.parameters``:

* ``panos_host``    — firewall management IP / FQDN.
* ``panos_api_key`` — generated via ``/api/?type=keygen&user=...``.
* ``panos_tag``     — tag the firewall's DAG is matched against
                      (e.g. ``aisoc-blocked``). The DAG itself
                      must already exist; AiSOC never creates it
                      because security teams own the policy layer.
* ``panos_vsys``    — vsys identifier, default ``vsys1``.

The client does not own a long-lived ``httpx.AsyncClient`` because
the PAN-OS XML API has session-bound caching surprises that bite
when the same connection straddles a commit; opening a new
connection per call is cheap (the firewall is on a low-latency
management network) and avoids those.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
from xml.sax.saxutils import escape, quoteattr

import httpx
import structlog

logger = structlog.get_logger()

#: PAN-OS accepts a tag name of up to 127 characters. Restricting it to this
#: set is narrower than the firewall allows and deliberately so: a tag is
#: chosen by an operator from a small vocabulary their DAG already matches,
#: not composed from event data, so nothing legitimate needs a character that
#: carries meaning in XML.
_TAG_PATTERN = re.compile(r"\A[A-Za-z0-9._-]{1,127}\Z")


class PanOsAddressError(ValueError):
    """The value offered as an address is not one.

    Raised rather than escaped. An escaped non-address would be sent to the
    firewall as a literal, where it silently matches nothing — so a block that
    never applied would report success. Refusing names the problem at the
    point it can still be fixed.
    """


def _validated_address(value: str) -> str:
    """Return ``value`` if it is an address PAN-OS registers, else raise.

    Accepts the three forms the user-id API takes: a single address, a CIDR
    network, and a hyphenated range. Everything else is refused.

    This is the primary control, with escaping below as defence in depth.
    Escaping alone would stop the injection and still hand the firewall a
    string that is not an address; validation means the only values that reach
    the XML are ones that cannot contain a character worth escaping.
    """
    candidate = (value or "").strip()
    if not candidate:
        raise PanOsAddressError("no address supplied")

    try:
        ipaddress.ip_address(candidate)
        return candidate
    except ValueError:
        pass

    try:
        # strict=False so an operator may pass 10.0.0.1/24 and mean the
        # network; PAN-OS resolves it the same way.
        ipaddress.ip_network(candidate, strict=False)
        return candidate
    except ValueError:
        pass

    start, separator, end = candidate.partition("-")
    if separator:
        try:
            first = ipaddress.ip_address(start.strip())
            last = ipaddress.ip_address(end.strip())
        except ValueError:
            pass
        else:
            if first.version == last.version and first <= last:
                return candidate

    raise PanOsAddressError(f"{value!r} is not an IP address, CIDR network or address range; refusing to send it to the firewall")


def _validated_tag(value: str) -> str:
    candidate = (value or "").strip()
    if not _TAG_PATTERN.match(candidate):
        raise PanOsAddressError(f"{value!r} is not a valid PAN-OS tag name; expected 1-127 characters from [A-Za-z0-9._-]")
    return candidate


class PanOsClient:
    """Thin async wrapper over the PAN-OS XML API used by AiSOC."""

    def __init__(
        self,
        host: str,
        api_key: str,
        *,
        vsys: str = "vsys1",
        verify_tls: bool = True,
    ) -> None:
        self._base_url = f"https://{host}/api/"
        self._api_key = api_key
        self._vsys = vsys
        self._verify_tls = verify_tls

    def _xml_register(self, ip: str, tag: str) -> str:
        """Build the user-id message that tags ``ip`` with ``tag``.

        We persist the entry indefinitely (``timeout=0``) because
        AiSOC owns the block lifecycle; the firewall must not
        decide to silently release the block. Operators who want a
        TTL on the block should set it at the AiSOC playbook
        layer where it's auditable.

        ``ip`` and ``tag`` arrive from ``ActionRequest.parameters`` and were
        interpolated raw. A value closing the attribute could append further
        payloads to the same message, so a *block* emitted well-formed XML
        containing an ``unregister`` of any address the caller chose — the
        containment action releasing a block instead of applying one
        (GHSA-w754-prh8-m56j). Both are validated, then escaped.
        """
        address = quoteattr(_validated_address(ip))
        member = escape(_validated_tag(tag))
        return (
            f"<uid-message>"
            f"<version>2.0</version><type>update</type>"
            f"<payload><register>"
            f'<entry ip={address} persistent="1">'
            f"<tag><member>{member}</member></tag>"
            f"</entry></register></payload></uid-message>"
        )

    def _xml_unregister(self, ip: str, tag: str) -> str:
        address = quoteattr(_validated_address(ip))
        member = escape(_validated_tag(tag))
        return (
            f"<uid-message>"
            f"<version>2.0</version><type>update</type>"
            f"<payload><unregister>"
            f"<entry ip={address}>"
            f"<tag><member>{member}</member></tag>"
            f"</entry></unregister></payload></uid-message>"
        )

    async def _post_user_id(self, cmd: str) -> dict[str, Any]:
        params = {
            "type": "user-id",
            "key": self._api_key,
            "vsys": self._vsys,
            "cmd": cmd,
        }
        async with httpx.AsyncClient(timeout=30.0, verify=self._verify_tls) as client:
            resp = await client.post(self._base_url, params=params)
            resp.raise_for_status()
            text = resp.text
            # PAN-OS returns 200 even for "status=error" payloads.
            # We surface the body so the executor logs something
            # actionable instead of a misleading success.
            if 'status="error"' in text:
                raise RuntimeError(f"PAN-OS XML API returned error: {text}")
            return {"status": "ok", "raw": text}

    async def block_ip(self, ip: str, tag: str) -> dict[str, Any]:
        """Register ``ip`` against the DAG matching ``tag``."""
        result = await self._post_user_id(self._xml_register(ip, tag))
        logger.info("panos.block_ip.success", ip=ip, tag=tag, vsys=self._vsys)
        return {
            "success": True,
            "action": "block_ip",
            "ip": ip,
            "tag": tag,
            "vsys": self._vsys,
            "raw": result["raw"],
        }

    async def unblock_ip(self, ip: str, tag: str) -> dict[str, Any]:
        result = await self._post_user_id(self._xml_unregister(ip, tag))
        logger.info("panos.unblock_ip.success", ip=ip, tag=tag, vsys=self._vsys)
        return {
            "success": True,
            "action": "unblock_ip",
            "ip": ip,
            "tag": tag,
            "vsys": self._vsys,
            "raw": result["raw"],
        }
