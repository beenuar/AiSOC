"""Replay recorded model replies to the real gateway client over a real socket.

Fix pass item 3.5. The recorder that produced the fixture, and the reasoning
for recording at all, are in ``record_replay_triage.py`` beside this file.

The server here is deliberately a socket rather than a patched transport. The
thing under test is the production triage path end to end — the factory builds
a ``ChatOpenAI``, the OpenAI SDK serialises the request, the reply is parsed by
``_parse_llm_response`` — and a patch applied anywhere inside that chain would
excuse whichever link it replaced. Only the model is substituted, by replaying
what that model actually said.
"""

from __future__ import annotations

import json
import re
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any

from tests.record_replay_triage import RECORDING_PATH, finding_id_in

if TYPE_CHECKING:  # pragma: no cover - import kept off the module load path
    from app.replay.findings import HistoricalFinding


class SplunkNotableNormalizer:
    """The mapping ``services/connectors`` applies to a Splunk ES notable row.

    A stand-in for the real connector, which is reached over HTTP in production
    (``app.replay.connector_normalizer``) and is exercised against the registry
    in the connectors service's own suite. Shared between the recorder and the
    test so the prompt a reply was recorded against is the prompt it is
    replayed against.
    """

    connector_id = "splunk"

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        return {
            "source": "splunk",
            "external_id": raw.get("event_id", ""),
            "title": raw.get("search_name") or "Splunk Notable Event",
            "severity": {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}.get(str(raw.get("urgency")), "medium"),
            "src_ip": raw.get("src"),
            "hostname": raw.get("host"),
            "username": raw.get("user"),
            "raw_event": raw,
            "created_at": raw.get("_time"),
        }


def load_recording(path: Path = RECORDING_PATH) -> dict[str, Any]:
    return json.loads(path.read_text())


def historical_findings(recording: dict[str, Any]) -> list[HistoricalFinding]:
    from app.replay.findings import HistoricalFinding

    return [
        HistoricalFinding(
            vendor=row["vendor"],
            finding_id=row["finding_id"],
            title=row["title"],
            disposition=row["disposition"],
            vendor_disposition=row["vendor_disposition"],
            closed_at=datetime.fromisoformat(row["closed_at"]),
            rule_id=row["rule_id"],
            raw=dict(row["raw"]),
        )
        for row in recording["findings"]
    ]


class _RecordedGateway(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, responses: dict[str, Any]) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.responses = responses
        self.served: list[str] = []
        self.refused: list[str] = []


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler's spelling
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
        key = finding_id_in(body)
        server: _RecordedGateway = self.server  # type: ignore[assignment]
        recorded = server.responses.get(key)

        if recorded is None:
            # Refused, never substituted. A reply served for an alert it was not
            # recorded against would make the run reproducible and meaningless
            # at the same time, which is the shape of defect this whole item is
            # about.
            server.refused.append(key)
            self._write(404, {"error": {"message": f"no recorded reply for {key!r}"}})
            return

        server.served.append(key)
        self._write(200, recorded)

    def _write(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *args: Any) -> None:
        return


#: ``run_auto_triage`` writes the call's elapsed time into a human-readable
#: finding ("Auto-triage: verdict=…, confidence=…, latency=41ms"), so the
#: `latency_ms` column is not the only wall clock a decision carries. Only the
#: digits are replaced: the rest of that sentence is a property of the input
#: and still has to match.
_LATENCY_IN_FINDING = re.compile(r"latency=\d+ms")


def comparable(decision: dict[str, Any]) -> dict[str, Any]:
    """A decision with the wall clock taken out, and nothing else."""
    row = {key: value for key, value in decision.items() if key != "latency_ms"}
    row["findings"] = [_LATENCY_IN_FINDING.sub("latency=<excluded>", str(f)) for f in row.get("findings") or []]
    return row


def verdict_classes(rows: list[dict[str, Any]]) -> set[str]:
    """The distinct verdicts a run predicted.

    Rows triage refused are excluded: a refusal is neither a verdict nor an
    abstention, and counting one as a class would let a run that answered
    nothing clear the bar below.
    """
    return {str(row["verdict"]) for row in rows if row.get("verdict") and row.get("error") is None}


def assert_non_degenerate(rows: list[dict[str, Any]]) -> None:
    """Refuse a run whose verdicts are all the same verdict.

    Fix pass 3.5. Reproducibility is trivially true of a constant, so a
    reproducibility assertion is only evidence when paired with this one. The
    deterministic tier answers ``likely_benign`` at 0.10 for every alert, and
    the test this guards passed over exactly that for as long as it existed.
    """
    classes = verdict_classes(rows)
    if len(classes) < 2:
        raise AssertionError(
            f"the run predicted one class ({sorted(classes) or 'none'}); reproducibility over a constant proves nothing about the runner"
        )


@contextmanager
def recorded_gateway(responses: dict[str, Any], monkeypatch: Any) -> Iterator[_RecordedGateway]:
    """Serve ``responses`` on loopback and point the agents LLM path at it.

    ``AISOC_MODEL_PIN_TRIAGE`` names a concrete model rather than leaving the
    ``aisoc-triage`` alias in place: an alias is routable only at a gateway the
    factory recognises, and this server is not one.
    """
    server = _RecordedGateway(responses)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = server.server_address[1]

    monkeypatch.delenv("AISOC_DETERMINISTIC", raising=False)
    monkeypatch.setenv("OPENAI_BASE_URL", f"http://127.0.0.1:{port}/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "replayed-recording")
    monkeypatch.setenv("AISOC_MODEL_PIN_TRIAGE", "recorded-model")
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
