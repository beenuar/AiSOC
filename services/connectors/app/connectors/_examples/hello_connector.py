"""
HelloConnector — reference implementation for the connector tutorial.

This module backs the tutorial at
``apps/docs/docs/connectors/hello-connector.md``. It is **not** registered
in the connector registry: it lives under ``_examples/`` precisely so it
can't accidentally end up in the catalog, the scheduler, or the
marketplace index.

The connector talks to `httpbin.org <https://httpbin.org>`_, a no-auth
HTTP testing service, so the tutorial is reproducible without any vendor
account, API key, or paid tier. The point isn't to ingest httpbin events
into your SOC — it's to demonstrate every method you need to override on
:class:`BaseConnector` with a backend that:

* responds without authentication,
* returns deterministic JSON shapes you can assert on,
* never goes down (it has been up roughly forever).

Layout of this file mirrors the order a real connector usually grows:

1. Identity attributes (``connector_id`` / ``connector_name`` / ``connector_category``).
2. ``schema()`` — what the wizard renders.
3. ``capabilities()`` — what the agent layer is allowed to ask of you.
4. ``__init__`` — accept exactly the fields the schema declares.
5. ``test_connection()`` — pre-save sanity check.
6. ``fetch_alerts()`` — the polling read path.
7. ``normalize()`` — vendor JSON → AiSOC's common alert shape.

If you copy this file as a starting point for a new connector, remember
to:

* Move it out of ``_examples/`` into ``services/connectors/app/connectors/``.
* Add the class to ``_CONNECTOR_CLASSES`` in the parent ``__init__.py``.
* Drop a ``plugins/<connector-id>/plugin.yaml`` mirroring ``schema()``.
* Add a per-connector docs page under ``apps/docs/docs/connectors/``.
* Run ``pnpm marketplace:sync``.
"""

from __future__ import annotations

from typing import Any

import httpx
import structlog

from app.connectors.base import (
    BaseConnector,
    Capability,
    ConnectorSchema,
    Field,
)

logger = structlog.get_logger()

# httpbin's `/anything` endpoint echoes whatever you send back as JSON.
# We treat each response as a "synthetic event" so the connector has
# something concrete to normalize. Real connectors point at a vendor
# audit endpoint here.
_DEFAULT_BASE_URL = "https://httpbin.org"


class HelloConnector(BaseConnector):
    """Tutorial connector that polls httpbin.org.

    Demonstrates the full :class:`BaseConnector` contract end-to-end
    against a public, no-auth backend. See the docstring at the top of
    this module for the rationale behind picking httpbin.
    """

    # ---- identity --------------------------------------------------------
    #
    # `connector_id` is the stable wire identifier — it shows up in
    # database rows, plugin manifests, and API URLs. Treat it like a
    # primary key: lowercase, hyphen- or underscore-separated, never
    # changes after first release.
    connector_id = "hello"
    connector_name = "Hello (Tutorial)"
    # `saas` is the closest-fit existing category; if you're shipping a
    # real new connector that doesn't slot into the existing taxonomy
    # (`identity` / `cloud` / `vcs` / `siem` / `edr` / `xdr` / `network`
    # / `posture` / `saas`), discuss in a PR before inventing a new one.
    connector_category = "saas"

    # ---- self-description ------------------------------------------------

    @classmethod
    def schema(cls) -> ConnectorSchema:
        """Tell the wizard which fields to render.

        ``api_token`` is marked ``secret`` so the UI uses a masked input
        and the credential vault encrypts it at rest. We don't actually
        send the token to httpbin — that's the point of the example —
        but we still declare it as a secret so the encryption code path
        is exercised exactly as it would be for a real vendor.
        """
        return ConnectorSchema(
            connector_id=cls.connector_id,
            connector_name=cls.connector_name,
            category=cls.connector_category,
            description=(
                "Tutorial connector that polls httpbin.org. Use this as a "
                "reference when writing a new connector — it implements "
                "every BaseConnector method against a public, no-auth API."
            ),
            docs_url="/docs/connectors/hello-connector",
            fields=[
                Field(
                    "api_token",
                    "secret",
                    "API Token",
                    help_text=(
                        "Pretend credential. httpbin doesn't actually "
                        "validate it — this field exists so the tutorial "
                        "exercises the credential vault."
                    ),
                ),
                Field(
                    "base_url",
                    "string",
                    "Base URL",
                    required=False,
                    default=_DEFAULT_BASE_URL,
                    placeholder=_DEFAULT_BASE_URL,
                    help_text="Override only when running against a self-hosted httpbin.",
                ),
            ],
        )

    # ---- capabilities ----------------------------------------------------

    @classmethod
    def capabilities(cls) -> tuple[Capability, ...]:
        """Declare what the agent layer is allowed to ask us to do.

        The tutorial connector is intentionally read-only — it polls,
        normalizes, and hands events to the ingest service. Anything
        kinetic (isolating a host, blocking a hash) would require a
        real backend that can act on those verbs.
        """
        return (Capability.PULL_ALERTS,)

    # ---- construction ----------------------------------------------------

    def __init__(self, api_token: str, base_url: str | None = None):
        # The constructor signature MUST line up with the schema field
        # names. The connector router unpacks the decrypted ``auth_config``
        # dict as kwargs, so a typo here turns into a 500 at poll time.
        self._api_token = api_token
        # Strip a trailing slash so we can compose URLs with simple `+`.
        self._base_url = (base_url or _DEFAULT_BASE_URL).rstrip("/")

    # ---- runtime: pre-save test -----------------------------------------

    async def test_connection(self) -> dict[str, Any]:
        """Pre-save liveness check.

        Called by ``POST /connectors/test`` *before* the row is written
        to the database. Returning ``success: false`` here blocks the
        save, so keep this cheap and deterministic — one round trip,
        short timeout, no pagination.

        We use httpbin's ``/status/200`` which echoes back a 200 with no
        body. That's the cheapest possible "is the network path open?"
        signal you can ask for.
        """
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.get(f"{self._base_url}/status/200")
        except httpx.HTTPError as exc:
            # Network errors, DNS failures, TLS handshake errors — all
            # surface here. We prefer a single, structured failure shape
            # so the UI can render it without sniffing exception types.
            logger.warning("hello.test_connection.network_error", error=str(exc))
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"network error: {exc.__class__.__name__}",
            }

        if resp.status_code != 200:
            return {
                "success": False,
                "connector": self.connector_id,
                "error": f"unexpected status: HTTP {resp.status_code}",
            }
        return {"success": True, "connector": self.connector_id}

    # ---- runtime: poll ---------------------------------------------------

    async def fetch_alerts(self, since_seconds: int = 300) -> list[dict[str, Any]]:
        """Pull a batch of "events" since the last poll.

        Real connectors translate ``since_seconds`` into a vendor-native
        time filter (Auth0 uses a Lucene query string, Cloudflare uses
        ``since=<ISO-8601>``, GitHub uses cursor pagination, etc.). We
        don't have a real time window — httpbin doesn't store events —
        so we just hit ``/anything`` once and treat the response body as
        a single synthetic event. Keep ``since_seconds`` in the signature
        anyway: the scheduler always passes it.

        On any HTTP error we log and return ``[]`` rather than raising.
        Polling failures are non-terminal — the next interval will retry
        and the failure is already surfaced via ``health_status`` once
        the scheduler records it.
        """
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.get(
                    f"{self._base_url}/anything",
                    params={"since_seconds": since_seconds},
                )
        except httpx.HTTPError as exc:
            logger.warning("hello.fetch_alerts.network_error", error=str(exc))
            return []

        if resp.status_code != 200:
            logger.warning(
                "hello.fetch_alerts.bad_status",
                status=resp.status_code,
                body=resp.text[:300],
            )
            return []

        try:
            payload = resp.json() or {}
        except ValueError:
            logger.warning("hello.fetch_alerts.invalid_json")
            return []

        # Wrap the single response as a list-of-events so callers don't
        # have to special-case "one event per poll" vs "many events per
        # poll". Real connectors typically iterate over the vendor's
        # paginated cursor here.
        return [self.normalize(payload)]

    # ---- runtime: normalization ------------------------------------------

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Map vendor JSON → the common alert shape AiSOC ingests.

        The contract for the returned dict is documented in
        ``services/ingest`` and includes (at minimum) ``source``,
        ``category``, ``severity``, ``title``, plus a ``raw`` blob with
        the original event preserved for forensics. We always carry the
        raw payload through — detection rules and explanation lineage
        both rely on it.

        Severity is hard-coded ``info`` because httpbin doesn't carry a
        severity signal. Real connectors derive severity from the
        vendor's risk score, status code, anomaly flag, etc. — see the
        Auth0 connector for an example of a simple rule-based mapping.
        """
        # httpbin echoes the request URL back at us — extract it for the
        # description so the event in the UI looks plausible.
        url = raw.get("url") or "(no url)"
        return {
            "source": "hello",
            "category": self.connector_category,
            "severity": "info",
            "title": f"Hello connector: pinged {url}",
            "description": "Synthetic event from the hello-connector tutorial.",
            # `alert_id` should be stable across re-fetches when the
            # vendor exposes a unique ID. httpbin doesn't, so we cheat:
            # use the request origin + URL as a poor-but-stable hash.
            "alert_id": f"hello:{raw.get('origin', '?')}:{url}",
            "host": None,
            "raw": raw,
        }
