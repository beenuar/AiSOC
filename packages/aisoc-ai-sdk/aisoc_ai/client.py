"""Emit AI-estate telemetry to AiSOC from inside an agent or LLM app.

AiSOC could already ingest an organisation's OpenAI and Anthropic *audit logs*
— who minted an API key, who was made an owner. That is control-plane
governance. It says nothing about what the agents actually did once running:
which tools they invoked, on whose behalf, against which resources, and
whether anything tried to steer them.

This is the runtime half. Point it at an inbox token and every tool call,
model invocation and guardrail finding lands in the same pipeline as every
other security signal — OCSF normalized, archived to the lake, matched by the
detection engine, promoted and triaged.

Two spans, matching the two ingest templates, and the distinction matters:

* `tool_call` / `model_call` are routine activity. They normalize to OCSF
  `6003` API Activity, which is category 6, so the promoter leaves them in the
  lake to be hunted. An agent doing its job is not an alert.
* `finding` is something a guardrail judged worth reporting. It normalizes to
  `2001` Security Finding, category 2, which the promoter always promotes.

Design constraints this file holds to:

**Never break the caller's app.** This is instrumentation inside somebody
else's request path. A network failure, a bad token or an unreachable AiSOC
must degrade to a dropped span, never to an exception escaping into their
agent. Every public method is therefore best-effort and returns a bool.

**Never block it either.** Emission is fire-and-forget onto a bounded queue
drained by a background worker. A full queue drops the oldest span and counts
the drop, because unbounded buffering inside a customer's process is a worse
failure than losing telemetry.

**Redaction before transmission, not after.** See `redaction.py`. Prompt and
response content is hashed by default and only ever sent when the caller opts
in explicitly.
"""

from __future__ import annotations

import atexit
import json
import logging
import queue
import threading
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass, field
from typing import Any

from aisoc_ai.redaction import CaptureMode, redact, secret_kinds

logger = logging.getLogger("aisoc_ai")

#: Bounded so instrumentation cannot grow memory without limit in the host
#: process. Sized for a burst of agent activity between flushes, not for
#: riding out a long AiSOC outage.
_QUEUE_MAXSIZE = 1000

_BATCH_SIZE = 50
_FLUSH_INTERVAL_SECONDS = 2.0
_REQUEST_TIMEOUT_SECONDS = 5.0


@dataclass
class _Counters:
    """Observable from the host process, so a silent SDK is diagnosable."""

    emitted: int = 0
    sent: int = 0
    dropped_queue_full: int = 0
    failed_transport: int = 0


@dataclass
class AiSocAiClient:
    """Emits AI runtime spans to an AiSOC inbox token.

    `endpoint` is the full inbox URL, e.g.
    `https://aisoc.example.com/v1/inbox/<token>`. Mint the token with
    `POST /api/v1/inbox/tokens` and the `ai-runtime` template; findings go to a
    second token using the `ai-finding` template.
    """

    endpoint: str
    finding_endpoint: str | None = None
    agent_id: str = "unknown-agent"
    agent_name: str | None = None
    capture: CaptureMode = CaptureMode.HASHED
    enabled: bool = True

    _queue: queue.Queue = field(default_factory=lambda: queue.Queue(maxsize=_QUEUE_MAXSIZE), init=False)
    _worker: threading.Thread | None = field(default=None, init=False)
    _stop: threading.Event = field(default_factory=threading.Event, init=False)
    _counters: _Counters = field(default_factory=_Counters, init=False)

    def __post_init__(self) -> None:
        if not self.endpoint:
            # No endpoint configured is a legitimate state — it is how an
            # operator turns the SDK off — so it disables rather than raises.
            self.enabled = False
            return
        self._worker = threading.Thread(target=self._drain, name="aisoc-ai-emitter", daemon=True)
        self._worker.start()
        atexit.register(self.flush)

    # ── public API ────────────────────────────────────────────────────────

    def tool_call(
        self,
        tool_name: str,
        *,
        on_behalf_of: str | None = None,
        server_name: str | None = None,
        resource: str | None = None,
        arguments: dict[str, Any] | None = None,
        outcome: str = "success",
        latency_ms: float | None = None,
        session_id: str | None = None,
        severity: str = "info",
    ) -> bool:
        """Record that the agent invoked a tool.

        `arguments` keys are transmitted; values are not. Which tool was
        called with which parameter *names* is the detection signal, and the
        values are frequently the sensitive part.
        """
        return self._emit(
            self.endpoint,
            {
                "tool_name": tool_name,
                "server_name": server_name,
                "resource": resource,
                "argument_keys": sorted(arguments or {}),
                "outcome": outcome,
                "latency_ms": latency_ms,
                "session_id": session_id or str(uuid.uuid4()),
                "severity": severity,
                "on_behalf_of": on_behalf_of,
            },
        )

    def model_call(
        self,
        model: str,
        *,
        provider: str | None = None,
        prompt: str | None = None,
        response: str | None = None,
        prompt_tokens: int | None = None,
        completion_tokens: int | None = None,
        on_behalf_of: str | None = None,
        latency_ms: float | None = None,
        session_id: str | None = None,
        severity: str = "info",
    ) -> bool:
        """Record a model invocation.

        Prompt and response go through `redact()` first. In the default hashed
        mode the SOC receives a digest, a length, and — importantly — which
        secret shapes were present, so "this prompt contained an AWS key" is
        detectable without the key ever leaving the process.
        """
        redacted_prompt = redact(prompt, self.capture)
        redacted_response = redact(response, self.capture)
        payload: dict[str, Any] = {
            "tool_name": f"model:{model}",
            "model": model,
            "provider": provider,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "prompt_sha256": redacted_prompt.sha256,
            "prompt_length": redacted_prompt.length,
            "response_sha256": redacted_response.sha256,
            "response_length": redacted_response.length,
            "prompt_secret_kinds": list(secret_kinds(prompt)),
            "latency_ms": latency_ms,
            "session_id": session_id or str(uuid.uuid4()),
            "severity": severity,
            "on_behalf_of": on_behalf_of,
        }
        if redacted_prompt.content is not None:
            payload["prompt"] = redacted_prompt.content
        if redacted_response.content is not None:
            payload["response"] = redacted_response.content
        return self._emit(self.endpoint, payload)

    def finding(
        self,
        finding_type: str,
        title: str,
        *,
        severity: str = "high",
        description: str | None = None,
        confidence: float | None = None,
        rule_id: str | None = None,
        matched_pattern: str | None = None,
        tool_name: str | None = None,
        model: str | None = None,
        on_behalf_of: str | None = None,
        session_id: str | None = None,
    ) -> bool:
        """Report something a guardrail judged worth a human's attention.

        Routed to `finding_endpoint` when configured, because findings use the
        `ai-finding` template (OCSF 2001, always promoted) rather than
        `ai-runtime` (6003, lake-only). Falling back to the runtime endpoint
        would silently downgrade a finding into routine activity, so the
        fallback is deliberate and logged.

        `finding_type` is the field detections match on: prompt_injection,
        excessive_agency, sensitive_data_egress, unapproved_model,
        tool_escalation, shadow_ai.
        """
        target = self.finding_endpoint
        if target is None:
            target = self.endpoint
            logger.warning(
                "aisoc_ai: no finding_endpoint configured; sending %r to the runtime "
                "endpoint, where it will normalize as routine activity and will not "
                "be promoted to an alert",
                finding_type,
            )
        return self._emit(
            target,
            {
                "finding_id": str(uuid.uuid4()),
                "finding_type": finding_type,
                "title": title,
                "description": description,
                "severity": severity,
                "confidence": confidence,
                "rule_id": rule_id,
                "matched_pattern": matched_pattern,
                "tool_name": tool_name,
                "model": model,
                "on_behalf_of": on_behalf_of,
                "session_id": session_id,
            },
        )

    def flush(self, timeout: float = 5.0) -> None:
        """Drain the queue. Called at interpreter exit."""
        if not self.enabled:
            return
        deadline = time.monotonic() + timeout
        while not self._queue.empty() and time.monotonic() < deadline:
            time.sleep(0.05)

    def close(self) -> None:
        self.flush()
        self._stop.set()

    def stats(self) -> dict[str, int]:
        """Counters, so an operator can tell a silent SDK from an idle one."""
        c = self._counters
        return {
            "emitted": c.emitted,
            "sent": c.sent,
            "dropped_queue_full": c.dropped_queue_full,
            "failed_transport": c.failed_transport,
        }

    # ── internals ─────────────────────────────────────────────────────────

    def _emit(self, target: str, payload: dict[str, Any]) -> bool:
        if not self.enabled:
            return False
        envelope = {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name or self.agent_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            **{k: v for k, v in payload.items() if v is not None},
        }
        self._counters.emitted += 1
        try:
            self._queue.put_nowait((target, envelope))
        except queue.Full:
            # Drop the oldest rather than the newest: recent agent behaviour is
            # more useful to a detection than a span from 30 seconds ago.
            self._counters.dropped_queue_full += 1
            try:
                self._queue.get_nowait()
                self._queue.put_nowait((target, envelope))
            except (queue.Empty, queue.Full):
                return False
        return True

    def _drain(self) -> None:
        """Background worker. Must never raise out of this thread."""
        while not self._stop.is_set():
            batches: dict[str, list[dict[str, Any]]] = {}
            deadline = time.monotonic() + _FLUSH_INTERVAL_SECONDS
            while len(batches.get(self.endpoint, [])) < _BATCH_SIZE and time.monotonic() < deadline:
                try:
                    target, envelope = self._queue.get(timeout=0.2)
                except queue.Empty:
                    continue
                batches.setdefault(target, []).append(envelope)

            for target, spans in batches.items():
                if spans:
                    self._post(target, spans)

    def _post(self, target: str, spans: list[dict[str, Any]]) -> None:
        body = json.dumps(spans).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 — operator-configured URL
            target,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "aisoc-ai-sdk"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=_REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
                if 200 <= response.status < 300:
                    self._counters.sent += len(spans)
                else:
                    self._counters.failed_transport += len(spans)
        except (urllib.error.URLError, OSError, ValueError) as exc:
            # Instrumentation must not surface a transport problem into the
            # host application's control flow.
            self._counters.failed_transport += len(spans)
            logger.debug("aisoc_ai: dropped %d span(s): %s", len(spans), exc)
