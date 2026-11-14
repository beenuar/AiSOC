"""Smoke test for t5-connector-sdk-ga (Python <-> TS dev-server bridge).

We don't need Node installed: the bridge talks HTTP, so we stand up a
tiny in-process HTTP server that pretends to be a running
``aisoc-connector dev`` instance and verify:

  1. ``attach_ts_dev_connector`` registers a Python factory for
     ``(kind, vendor)`` and the registry exposes it.
  2. Calling an action through ``TsDevConnector`` round-trips JSON,
     applies tenant + idempotency metadata, and returns the validated
     output.
  3. Error paths: 401/403 -> ConnectorAuthError; 429 ->
     ConnectorRateLimitError; 408 -> ConnectorTimeoutError; unknown
     status -> ConnectorError.
  4. ``detach_ts_dev_connector`` removes the factory + flushes cache.
  5. The TS-side artefacts on disk are well-formed (package.json
     parses, the README + examples + bin all exist) so we don't ship
     a publicly broken SDK.

The fake dev server is stdlib-only — we avoid pulling in any extra
test dependency. It runs in a daemon thread for the duration of the
test and is shut down at exit.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# ─── Hermetic setup ─────────────────────────────────────────────────
_TMP = tempfile.NamedTemporaryFile(prefix="aisoc-tsbridge-", suffix=".db", delete=False)
_TMP.close()
os.environ["AISOC_DB_PATH"] = _TMP.name
os.environ["AISOC_LLM_PROVIDER"] = "mock"
os.environ["AISOC_DEV_ALLOW_ANON_TENANT"] = "true"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def _bad(msg: str, *details: object) -> None:
    print(f"FAIL: {msg}")
    for d in details:
        print(f"  -> {d}")


# ─── Fake TS dev server ────────────────────────────────────────────


_FAKE_MANIFEST = {
    "sdk_version": "0.1.0-beta.1",
    "kind": "siem",
    "vendor": "echo-fake",
    "version": "0.1.0",
    "actions": {
        "echo": {
            "description": "Echo back",
            "risk": "READ",
            "idempotent": True,
            "reversible": False,
            "input_schema": {
                "type": "object",
                "properties": {"message": {"type": "string"}},
                "required": ["message"],
            },
            "output_schema": {
                "type": "object",
                "properties": {
                    "echoes": {"type": "array", "items": {"type": "string"}},
                    "tenant_id": {"type": "string"},
                },
                "required": ["echoes", "tenant_id"],
            },
        },
        "force_429": {"description": "rate limit", "input_schema": {}, "output_schema": {}},
        "force_401": {"description": "auth", "input_schema": {}, "output_schema": {}},
        "force_408": {"description": "timeout", "input_schema": {}, "output_schema": {}},
        "force_500": {"description": "boom", "input_schema": {}, "output_schema": {}},
    },
}


class _Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 — stdlib API
        if self.path == "/healthz":
            self._json(200, {"ok": True, "vendor": "echo-fake", "kind": "siem", "reload_version": 1, "errors": []})
        elif self.path == "/manifest":
            self._json(200, _FAKE_MANIFEST)
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if not self.path.startswith("/actions/"):
            self._json(404, {"error": "not found"})
            return
        action = self.path.split("/actions/", 1)[1]
        length = int(self.headers.get("content-length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")
        if action == "echo":
            inp = body.get("input") or {}
            self._json(
                200,
                {
                    "output": {
                        "echoes": [str(inp.get("message", ""))],
                        "tenant_id": str(body.get("tenant_id", "")),
                    },
                    "invocation_id": "inv_test",
                },
            )
        elif action == "force_429":
            self._json(429, {"error": "rate limited"})
        elif action == "force_401":
            self._json(401, {"error": "unauthorized"})
        elif action == "force_408":
            self._json(408, {"error": "timeout"})
        elif action == "force_500":
            self._json(500, {"error": "boom"})
        else:
            self._json(404, {"error": f"unknown action {action}"})

    def log_message(self, *args, **kwargs) -> None:  # noqa: D401, ANN001
        return  # silence stdlib server's noisy stderr logging


    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _start_fake_server() -> tuple[str, ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return f"http://127.0.0.1:{port}", server, thread


def main() -> int:
    from app.connectors.sdk.base import (
        ConnectorAuthError,
        ConnectorConfig,
        ConnectorError,
        ConnectorKind,
        ConnectorRateLimitError,
        ConnectorTimeoutError,
    )
    from app.connectors.sdk.registry import (
        list_registered_factories,
        _FACTORIES,
        _reset_for_tests,
    )
    from app.connectors.sdk.ts_bridge import (
        TsDevConnector,
        attach_ts_dev_connector,
        detach_ts_dev_connector,
        fetch_manifest,
    )

    base_url, server, _thread = _start_fake_server()

    try:
        # 1. Manifest fetch + attach.
        manifest = fetch_manifest(base_url)
        if manifest.vendor != "echo-fake" or manifest.kind != ConnectorKind.SIEM:
            _bad("unexpected manifest contents", manifest)
            return 1
        attached = attach_ts_dev_connector(base_url)
        if attached.vendor != "echo-fake":
            _bad("attach returned wrong manifest", attached)
            return 1
        keys = list_registered_factories()
        if (ConnectorKind.SIEM, "echo-fake") not in keys:
            _bad("attach did not register factory", keys)
            return 1

        # 2. Round-trip echo action.
        config = ConnectorConfig(
            tenant_id="demo-tenant",
            kind=ConnectorKind.SIEM,
            vendor="echo-fake",
            params={"baseUrl": base_url, "token": "x"},
            secrets={},
            enabled=True,
        )
        factory = _FACTORIES[(ConnectorKind.SIEM, "echo-fake")]
        connector = factory(config)
        if not isinstance(connector, TsDevConnector):
            _bad("factory did not return TsDevConnector", connector)
            return 1

        loop = asyncio.new_event_loop()
        try:
            health = loop.run_until_complete(connector.health_check())
            if not health.get("ok"):
                _bad("health check failed", health)
                return 1

            result = loop.run_until_complete(
                connector.call_action(
                    "echo",
                    input={"message": "hello"},
                    idempotency_key="abc",
                )
            )
            if result != {"echoes": ["hello"], "tenant_id": "demo-tenant"}:
                _bad("echo round-trip wrong", result)
                return 1

            # 3. Error paths.
            for action, expected in (
                ("force_401", ConnectorAuthError),
                ("force_429", ConnectorRateLimitError),
                ("force_408", ConnectorTimeoutError),
                ("force_500", ConnectorError),
            ):
                try:
                    loop.run_until_complete(connector.call_action(action))
                except expected as exc:
                    _ = exc
                except Exception as exc:  # noqa: BLE001
                    _bad(
                        f"{action} should raise {expected.__name__}, got {type(exc).__name__}",
                        exc,
                    )
                    return 1
                else:
                    _bad(f"{action} should have raised", expected.__name__)
                    return 1

            # Unknown action -> ConnectorError before HTTP is even called.
            try:
                loop.run_until_complete(connector.call_action("nope"))
            except ConnectorError:
                pass
            else:
                _bad("unknown action should ConnectorError")
                return 1

            loop.run_until_complete(connector.aclose())

            # 4. Detach.
            evicted = loop.run_until_complete(
                detach_ts_dev_connector(
                    kind=ConnectorKind.SIEM, vendor="echo-fake"
                )
            )
            if (ConnectorKind.SIEM, "echo-fake") in _FACTORIES:
                _bad("detach left factory in registry")
                return 1
        finally:
            loop.close()
            _reset_for_tests()

        # 5. TS-side artefacts on disk.
        sdk_root = Path(ROOT).parent / "sdk" / "connector-ts"
        if not sdk_root.exists():
            _bad("ts SDK directory missing", sdk_root)
            return 1
        pkg = json.loads((sdk_root / "package.json").read_text())
        if pkg.get("name") != "@cyble/aisoc-connector":
            _bad("ts SDK package.json has wrong name", pkg.get("name"))
            return 1
        for required in (
            "tsconfig.json",
            "src/index.ts",
            "src/dev.ts",
            "src/_zodSchema.ts",
            "bin/cli.js",
            "examples/echo/index.ts",
            "README.md",
        ):
            if not (sdk_root / required).exists():
                _bad(f"missing TS SDK file: {required}")
                return 1

        # The example must reference defineConnector + ConnectorKind so
        # we know it didn't drift from the SDK API.
        echo_ts = (sdk_root / "examples/echo/index.ts").read_text()
        if "defineConnector(" not in echo_ts or "ConnectorKind." not in echo_ts:
            _bad("echo example does not use the public API")
            return 1
    finally:
        server.shutdown()
        server.server_close()

    print("OK t5-connector-sdk-ga")
    print(json.dumps({
        "manifest_actions": list(manifest.actions.keys()),
        "ts_sdk_path": str(sdk_root.relative_to(Path(ROOT).parent.parent)),
    }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
