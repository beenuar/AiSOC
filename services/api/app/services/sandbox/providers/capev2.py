"""CAPEv2, the open-source reference provider.

Why this one is the reference
-----------------------------
It is open source, it is the sandbox an operator can actually stand up next to
AiSOC, and because it runs on the operator's own network it is the provider
that stays usable in air-gapped mode. It is also the useful shape to write the
interface against first: CAPE publishes a ``malscore`` on a 0-10 scale and no
verdict string at all, which forces the interface to own both the range and the
word rather than adopting whichever provider was wired first.

What is mapped, and what is derived
-----------------------------------
``malscore`` is multiplied by 10 into the interface's 0-100 score. The verdict
is *derived*, because CAPE does not publish one: at or above 7.0 malicious, at
or above 3.0 suspicious, above 0 unknown, and exactly 0 benign. Those numbers
are a judgement this adapter makes and they are stated here, on the API
response and in the operator documentation, rather than presented as CAPE's
own opinion.

Verification status
-------------------
Written against the documented CAPEv2 REST API and exercised in CI against
recorded, synthetic payloads. **Not verified against a live CAPEv2 instance**
by anyone in this repository. The docs page says the same thing. An operator
who runs it against a real deployment and finds a mismatch is fixing a real
defect, not a hypothetical one.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import httpx
import structlog

from app.services.sandbox.base import SandboxProvider, guard_outbound_url
from app.services.sandbox.types import (
    UNAVAILABLE,
    AnalysisState,
    AttackTechnique,
    ProviderCapabilities,
    SandboxIocs,
    SandboxReport,
    SandboxUnavailable,
    SandboxVerdict,
    Signature,
    SubmissionReceipt,
)

log = structlog.get_logger(__name__)

__all__ = ["CapeV2Provider"]

#: CAPE task states that mean the analysis is finished and a report exists.
_DONE = frozenset({"reported"})
#: States that mean it is still going. Anything unrecognised is treated as
#: running rather than failed: a new CAPE release adding a state must not turn
#: a healthy analysis into a reported failure.
_FAILED = frozenset({"failed_analysis", "failed_processing", "failed_reporting", "banned"})

_MALICIOUS_AT = 7.0
_SUSPICIOUS_AT = 3.0


class CapeV2Provider(SandboxProvider):
    """Adapter for a self-hosted CAPEv2 instance."""

    def __init__(
        self,
        base_url: str,
        *,
        api_token: str | None = None,
        timeout_seconds: float = 20.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._token = (api_token or "").strip()
        self._timeout = timeout_seconds
        self._client = client
        self._owns_client = client is None

    @property
    def capabilities(self) -> ProviderCapabilities:
        return ProviderCapabilities(
            name="capev2",
            local=True,
            supports_hash_lookup=True,
            supports_file_submission=True,
            supports_url_submission=True,
            submissions_are_public_by_default=False,
            description="Self-hosted CAPEv2 sandbox. Runs on the operator's own network, so it stays usable air-gapped.",
        )

    # ---------------------------------------------------------------- transport

    def _headers(self) -> dict[str, str]:
        # CAPEv2 documents `Authorization: Token <apitoken>` when token auth is
        # enabled, and no header at all when it is not. Sending an empty token
        # would turn an open instance into a 401, so the header is omitted
        # rather than sent blank.
        return {"Authorization": f"Token {self._token}"} if self._token else {}

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    async def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        url = guard_outbound_url(f"{self._base}{path}", provider="capev2", allow_private=True)
        client = await self._get_client()
        try:
            return await client.request(method, url, headers=self._headers(), **kwargs)
        except httpx.HTTPError as exc:
            raise SandboxUnavailable("capev2", f"{method} {path} failed: {exc}", kind="network") from exc

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
            self._client = None

    # ------------------------------------------------------------------- verbs

    async def lookup_hash(self, sha256: str) -> SandboxReport | None:
        digest = (sha256 or "").strip().lower()
        resp = await self._request("GET", f"/apiv2/tasks/search/sha256/{digest}/")
        if resp.status_code == 404:
            return None
        if resp.status_code == 401 or resp.status_code == 403:
            raise SandboxUnavailable("capev2", f"authentication refused (HTTP {resp.status_code})", kind="auth")
        if resp.status_code >= 400:
            raise SandboxUnavailable("capev2", f"hash search returned HTTP {resp.status_code}", kind="bad_response")
        body = _json(resp, "hash search")
        # CAPE answers a miss with `error: true` and a 200, so the status code
        # alone does not separate hit from miss.
        if body.get("error"):
            return None
        tasks = body.get("data") or []
        if not isinstance(tasks, list) or not tasks:
            return None
        task_id = tasks[0].get("id") if isinstance(tasks[0], dict) else None
        if task_id is None:
            return None
        return await self.poll(str(task_id))

    async def submit_file(self, content: bytes, file_name: str, *, visibility: str | None = None) -> SubmissionReceipt:
        resp = await self._request(
            "POST",
            "/apiv2/tasks/create/file/",
            files={"file": (file_name, content, "application/octet-stream")},
        )
        return self._receipt(resp, "file submission")

    async def submit_url(self, url: str) -> SubmissionReceipt:
        resp = await self._request("POST", "/apiv2/tasks/create/url/", data={"url": url})
        return self._receipt(resp, "URL submission")

    def _receipt(self, resp: httpx.Response, what: str) -> SubmissionReceipt:
        if resp.status_code >= 400:
            raise SandboxUnavailable("capev2", f"{what} returned HTTP {resp.status_code}", kind="bad_response")
        body = _json(resp, what)
        data = body.get("data") or {}
        task_id = data.get("task_ids", [None])[0] if isinstance(data.get("task_ids"), list) else data.get("task_id")
        if task_id is None:
            raise SandboxUnavailable("capev2", f"{what} returned no task id", kind="bad_response")
        return SubmissionReceipt(
            provider="capev2",
            handle=str(task_id),
            state=AnalysisState.PENDING,
            visibility="private",
            poll_after_seconds=30,
            submitted_at=datetime.now(UTC),
        )

    async def poll(self, handle: str) -> SandboxReport:
        resp = await self._request("GET", f"/apiv2/tasks/view/{handle}/")
        if resp.status_code == 404:
            return SandboxReport(
                provider="capev2",
                state=AnalysisState.NOT_FOUND,
                unavailable_reasons={"verdict": f"CAPEv2 has no task {handle}"},
            )
        if resp.status_code >= 400:
            raise SandboxUnavailable("capev2", f"task view returned HTTP {resp.status_code}", kind="bad_response")
        task = (_json(resp, "task view").get("data") or {}).get("task") or {}
        status = str(task.get("status") or "").lower()
        if status in _FAILED:
            return SandboxReport(
                provider="capev2",
                state=AnalysisState.FAILED,
                unavailable_reasons={"verdict": f"CAPEv2 analysis {handle} ended in state {status!r}"},
            )
        if status not in _DONE:
            return self._pending("capev2", handle, AnalysisState.RUNNING if status else AnalysisState.PENDING)

        report_resp = await self._request("GET", f"/apiv2/tasks/get/report/{handle}/json/")
        if report_resp.status_code >= 400:
            raise SandboxUnavailable("capev2", f"report fetch returned HTTP {report_resp.status_code}", kind="bad_response")
        return self.to_report(_json(report_resp, "report"), handle=handle)

    # ------------------------------------------------------------------ mapping

    @staticmethod
    def to_report(payload: dict[str, Any], *, handle: str = "") -> SandboxReport:
        """Map a CAPEv2 JSON report onto the interface. Pure, so tests can drive it."""
        info = payload.get("info") if isinstance(payload.get("info"), dict) else {}
        target_file = ((payload.get("target") or {}).get("file") or {}) if isinstance(payload.get("target"), dict) else {}

        malscore = payload.get("malscore")
        score: Any = UNAVAILABLE
        verdict: Any = UNAVAILABLE
        reasons: dict[str, str] = {}
        if isinstance(malscore, (int, float)):
            value = float(malscore)
            score = max(0, min(100, round(value * 10)))
            if value >= _MALICIOUS_AT:
                verdict = SandboxVerdict.MALICIOUS
            elif value >= _SUSPICIOUS_AT:
                verdict = SandboxVerdict.SUSPICIOUS
            elif value > 0:
                verdict = SandboxVerdict.UNKNOWN
            else:
                verdict = SandboxVerdict.BENIGN
        else:
            reasons["score"] = "CAPEv2 report carried no malscore"
            reasons["verdict"] = "CAPEv2 publishes no verdict and this report carried no malscore to derive one from"

        signatures: list[Signature] = []
        techniques: dict[str, AttackTechnique] = {}
        raw_signatures = payload.get("signatures")
        if isinstance(raw_signatures, list):
            for sig in raw_signatures:
                if not isinstance(sig, dict):
                    continue
                signatures.append(
                    Signature(
                        identifier=str(sig.get("name") or "").strip() or "unnamed",
                        source="capev2",
                        description=str(sig.get("description") or "").strip(),
                        severity=str(sig.get("severity")) if sig.get("severity") is not None else None,
                        confidence=_confidence(sig.get("confidence")),
                    )
                )
                for tid in _technique_ids(sig):
                    techniques.setdefault(tid, AttackTechnique(technique_id=tid))
        else:
            reasons["signatures"] = "CAPEv2 report carried no signatures array"

        for tid in _technique_ids(payload):
            techniques.setdefault(tid, AttackTechnique(technique_id=tid))

        network = payload.get("network") if isinstance(payload.get("network"), dict) else None
        if network is None:
            iocs = SandboxIocs()
            reasons["iocs"] = "CAPEv2 report carried no network section"
        else:
            iocs = SandboxIocs(
                urls=tuple(_strings(network.get("http"), "uri")),
                domains=tuple(_strings(network.get("domains"), "domain")),
                ipv4=tuple(_strings(network.get("hosts"), "ip")),
            )

        analyzed_at = _parse_time(info.get("ended") or info.get("started"))
        return SandboxReport(
            provider="capev2",
            state=AnalysisState.COMPLETED,
            verdict=verdict,
            score=score,
            signatures=tuple(signatures) if isinstance(raw_signatures, list) else UNAVAILABLE,
            iocs=iocs,
            # An empty tuple here is a real answer: CAPE ran the behavioural
            # stage and mapped no techniques. That differs from the commercial
            # adapter, where an absent behavioural stage makes it unavailable.
            attack=tuple(techniques.values()),
            sha256=str(target_file.get("sha256") or "") or None,
            file_name=str(target_file.get("name") or "") or None,
            file_type=str(target_file.get("type") or "") or None,
            report_url=None,
            visibility="private",
            analyzed_at=analyzed_at,
            unavailable_reasons=reasons,
        )


def _json(resp: httpx.Response, what: str) -> dict[str, Any]:
    try:
        body = resp.json()
    except ValueError as exc:
        raise SandboxUnavailable("capev2", f"{what} returned a non-JSON body", kind="bad_response") from exc
    return body if isinstance(body, dict) else {}


def _confidence(value: Any) -> float | None:
    """CAPE reports confidence as a percentage; the interface uses 0-1."""
    if not isinstance(value, (int, float)):
        return None
    return round(float(value) / 100.0, 3) if value > 1 else float(value)


def _technique_ids(container: Any) -> list[str]:
    """Pull ATT&CK ids out of the several shapes CAPE has used for them."""
    found: list[str] = []
    if not isinstance(container, dict):
        return found
    for key in ("ttp", "ttps", "attack_id", "attack"):
        raw = container.get(key)
        if isinstance(raw, str):
            found.append(raw)
        elif isinstance(raw, list):
            for item in raw:
                if isinstance(item, str):
                    found.append(item)
                elif isinstance(item, dict):
                    found.extend(str(v) for v in (item.get("ttp"), item.get("id")) if isinstance(v, str))
        elif isinstance(raw, dict):
            found.extend(str(k) for k in raw)
    return [t.strip().upper() for t in found if t and t.strip().upper().startswith("T")]


def _strings(container: Any, key: str) -> list[str]:
    if not isinstance(container, list):
        return []
    out: list[str] = []
    for item in container:
        value = item.get(key) if isinstance(item, dict) else item
        if isinstance(value, str) and value.strip():
            out.append(value.strip())
    return sorted(set(out))


def _parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
