"""Depth 2 wave 2 item 2.4 — API abuse from proxy, gateway and WAF logs.

AiSOC already ingests access logs through the WAF and CDN connectors, the
OTLP receiver and syslog. Every line carries a path, a query, a method and a
status, and nothing read them as a *shape*: `/api/users/4821` and
`/api/users/4822` were two unrelated strings, so neither an unknown
parameter on a known endpoint nor a walk across identifiers was visible.

Three steps:

1. **Template the path.** `/api/users/4821/orders` becomes
   `/api/users/{id}/orders`. Templating is lexical and conservative — a
   segment is replaced only when it is unambiguously an identifier (all
   digits, a UUID, a long hex or base64url string), never because it merely
   looks unusual. Over-templating merges genuinely different endpoints and
   makes every profile a mixture; under-templating leaves identifiers in the
   key and learns nothing.
2. **Learn per template.** Which parameter names appear, what type each
   value has, which status codes the endpoint returns.
3. **Signal on the differences.** A parameter nobody has sent before, a
   known parameter whose type changed, and one client walking many distinct
   identifiers through one template.

Off by default, per tenant
--------------------------
The plan requires it and so does the cost: templating every access-log line
is work on the hot path, and most deployments ingest no access logs at all.
`enabled_for` is consulted per event, so a tenant that has not opted in
pays one set membership test.

Absent, not zero
----------------
A template with too little history reports nothing. "No parameter has ever
been seen on this endpoint" and "this parameter is new" are different
statements, and publishing the second for the first would make the first
request to every new endpoint a finding.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass
from typing import Any

import structlog

logger = structlog.get_logger()

#: Requests a template needs before any novelty is reported. Below this
#: every parameter is new because the endpoint is new.
MIN_REQUESTS = int(os.getenv("AISOC_API_PROFILE_MIN_REQUESTS", "50"))

#: Parameter names one template will learn. Names are caller-supplied, so an
#: unbounded set is a memory-exhaustion primitive aimed at the hot path.
MAX_PARAMETERS = int(os.getenv("AISOC_API_PROFILE_MAX_PARAMETERS", "128"))

#: Distinct identifiers one client may walk through one template inside the
#: window before it reads as enumeration.
ENUMERATION_THRESHOLD = int(os.getenv("AISOC_API_ENUMERATION_THRESHOLD", "50"))
ENUMERATION_WINDOW_SECONDS = int(os.getenv("AISOC_API_ENUMERATION_WINDOW_SECONDS", "300"))

TTL_SECONDS = int(os.getenv("AISOC_API_PROFILE_TTL_SECONDS", str(30 * 86400)))

_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
_DIGITS = re.compile(r"^\d+$")
_OPAQUE = re.compile(r"^[A-Za-z0-9_-]{20,}$")

#: Fields the access-log sources put a request path under.
_PATH_FIELDS = ("http_path", "url_path", "request_uri", "uri_path", "path", "request_path")
_QUERY_FIELDS = ("http_query", "url_query", "query_string", "query")
_STATUS_FIELDS = ("http_status", "status_code", "response_status", "status")
_METHOD_FIELDS = ("http_method", "method", "request_method")
_CLIENT_FIELDS = ("src_ip", "client_ip", "ip_address", "actor_email", "actor")


@dataclass(frozen=True)
class ApiSignal:
    """One deviation from an endpoint's learned shape."""

    kind: str
    template: str
    detail: str
    observed: int


def template_path(path: str) -> tuple[str, list[str]]:
    """`/api/users/4821/orders` -> `('/api/users/{id}/orders', ['4821'])`.

    Returns the identifiers it removed as well as the template, because the
    enumeration signal counts distinct identifiers and would otherwise have
    to re-parse the path to find them.
    """
    if not path:
        return "", []
    query_split = path.split("?", 1)[0]
    segments = query_split.split("/")
    out: list[str] = []
    identifiers: list[str] = []
    for segment in segments:
        if not segment:
            out.append(segment)
            continue
        if _DIGITS.match(segment) or _UUID.match(segment) or _HEX.match(segment) or _OPAQUE.match(segment):
            out.append("{id}")
            identifiers.append(segment)
        else:
            out.append(segment)
    return "/".join(out), identifiers


def value_type(value: str) -> str:
    """A coarse type, chosen so a change in it is meaningful.

    Four buckets rather than a parser: an `int` becoming a `string` is the
    shape of an injection attempt or a mass-assignment probe, while
    distinguishing an int from a float says nothing an operator would act on.
    """
    if value == "":
        return "empty"
    if _DIGITS.match(value):
        return "int"
    if value.lower() in {"true", "false"}:
        return "bool"
    return "string"


def parse_query(query: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for pair in (query or "").lstrip("?").split("&"):
        if not pair:
            continue
        name, _, value = pair.partition("=")
        if name:
            out[name] = value
    return out


def _first(event: dict[str, Any], fields: tuple[str, ...]) -> str | None:
    for field in fields:
        value = event.get(field)
        if value not in (None, ""):
            return str(value)
    return None


class ApiBehaviourProfiler:
    """Per-endpoint parameter, type and status profiles, in fusion's Redis.

    `enabled_for` is the per-tenant opt-in. It is checked before any Redis
    call, so a deployment that ingests no access logs — which is most of
    them — does no work here at all.
    """

    def __init__(
        self,
        redis: Any,
        *,
        enabled_for: frozenset[str] | None = None,
        key_prefix: str = "aisoc:api",
        min_requests: int | None = None,
    ) -> None:
        self._redis = redis
        self._enabled = enabled_for if enabled_for is not None else frozenset()
        self._prefix = key_prefix
        self._min_requests = min_requests if min_requests is not None else MIN_REQUESTS

    def enabled(self, tenant: str) -> bool:
        return tenant in self._enabled

    def _key(self, tenant: str, *parts: str) -> str:
        return ":".join((self._prefix, tenant, *parts))

    async def observe(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> list[ApiSignal]:
        """Learn from this request and return whatever deviated from the profile."""
        if not self.enabled(tenant):
            return []
        path = _first(event, _PATH_FIELDS)
        if not path:
            return []
        at = now if now is not None else time.time()
        method = (_first(event, _METHOD_FIELDS) or "GET").upper()
        template, identifiers = template_path(path)
        endpoint = f"{method} {template}"
        status = _first(event, _STATUS_FIELDS) or ""
        client = _first(event, _CLIENT_FIELDS) or ""

        query = _first(event, _QUERY_FIELDS)
        if query is None and "?" in path:
            query = path.split("?", 1)[1]
        parameters = parse_query(query or "")

        signals: list[ApiSignal] = []
        try:
            total = int(await self._redis.hincrby(self._key(tenant, "count"), endpoint, 1) or 0)
            await self._redis.expire(self._key(tenant, "count"), TTL_SECONDS)

            params_key = self._key(tenant, "params", endpoint)
            known = await self._redis.hgetall(params_key)
            known_types = {
                (k.decode() if isinstance(k, bytes) else str(k)): (v.decode() if isinstance(v, bytes) else str(v))
                for k, v in (known or {}).items()
            }

            for name, raw in parameters.items():
                observed_type = value_type(raw)
                if name not in known_types:
                    if len(known_types) < MAX_PARAMETERS:
                        await self._redis.hset(params_key, name, observed_type)
                        known_types[name] = observed_type
                    # Only a *warm* endpoint can have an unknown parameter.
                    # On a cold one every parameter is new, which is a
                    # property of the history and not of the request.
                    if total >= self._min_requests:
                        signals.append(ApiSignal("unknown_parameter", endpoint, name, total))
                elif known_types[name] != observed_type and total >= self._min_requests:
                    signals.append(ApiSignal("parameter_type_change", endpoint, f"{name}: {known_types[name]} -> {observed_type}", total))
            await self._redis.expire(params_key, TTL_SECONDS)

            if status:
                status_key = self._key(tenant, "status", endpoint)
                await self._redis.hincrby(status_key, status, 1)
                await self._redis.expire(status_key, TTL_SECONDS)

            if identifiers and client:
                walk_key = self._key(tenant, "walk", endpoint, client, str(int(at // ENUMERATION_WINDOW_SECONDS)))
                for identifier in identifiers:
                    await self._redis.sadd(walk_key, identifier)
                await self._redis.expire(walk_key, ENUMERATION_WINDOW_SECONDS * 2)
                distinct = int(await self._redis.scard(walk_key) or 0)
                if distinct >= ENUMERATION_THRESHOLD:
                    signals.append(ApiSignal("identifier_enumeration", endpoint, f"{client} walked {distinct}", distinct))
        except Exception as exc:  # noqa: BLE001 — see the module docstring
            logger.debug("api_behaviour.unavailable", error=str(exc))
            return []

        return signals

    async def derived_fields(self, tenant: str, event: dict[str, Any], *, now: float | None = None) -> dict[str, Any]:
        """The API-behaviour fields this request produces, for the engine."""
        signals = await self.observe(tenant, event, now=now)
        if not signals:
            return {}
        out: dict[str, Any] = {"api_template": signals[0].template}
        for signal in signals:
            out[f"api_{signal.kind}"] = True
            out[f"api_{signal.kind}_detail"] = signal.detail
            if signal.kind == "identifier_enumeration":
                out["api_enumeration_distinct"] = signal.observed
        return out


#: Every key `derived_fields` can publish, pinned by
#: `scripts/check_detection_fields.py` and asserted in both directions by
#: `services/fusion/tests/test_api_behaviour.py`.
DERIVED_FIELDS = frozenset(
    {
        "api_template",
        "api_unknown_parameter",
        "api_unknown_parameter_detail",
        "api_parameter_type_change",
        "api_parameter_type_change_detail",
        "api_identifier_enumeration",
        "api_identifier_enumeration_detail",
        "api_enumeration_distinct",
    }
)
