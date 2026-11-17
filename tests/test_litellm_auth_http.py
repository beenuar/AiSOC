"""Pinned-image transport checks against protocol fixtures, never AWS/providers.

AISOC_TEST_LITELLM=1 enables these Docker tests. The fixture server and real
gateway run together inside a container with --network none; only loopback is
available. These prove credential selection and wire shape, not model access.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MASTER = "sk-fixture-gateway-only"
MODELS = {
    "ollama": "ollama_chat/llama3.2:3b-instruct-q4_K_M",
    "openai": "openai/gpt-4o-mini",
    "anthropic": "anthropic/claude-3-haiku-20240307",
    "bedrock": "bedrock/converse/anthropic.claude-3-haiku-20240307-v1:0",
}


def _inside(case: str) -> None:
    """Executed by the image's Python, with its actual LiteLLM dependencies."""
    if case == "default-endpoint":
        import runpy
        from unittest.mock import patch

        from litellm.llms.bedrock.base_aws_llm import BaseAWSLLM
        from litellm.secret_managers.main import get_secret

        os.environ["AISOC_LLM_API_BASE"] = ""
        with patch("os.execv"):
            runpy.run_path("/etc/litellm/start.py", run_name="__main__")
        base = get_secret("os.environ/AISOC_LLM_API_BASE")
        assert base is None
        endpoints = BaseAWSLLM().get_runtime_endpoint(base, None, "us-east-1")
        assert endpoints == ("https://bedrock-runtime.us-east-1.amazonaws.com",) * 2
        return

    provider = case.split("-", 1)[0]
    requests: list[tuple[str, dict, dict]] = []
    metadata_requests: list[tuple[str, str, dict]] = []

    class Backend(BaseHTTPRequestHandler):
        def log_message(self, *_args) -> None:
            pass

        def reply(self, status: int, result: dict | str, extra_headers: dict | None = None) -> None:
            data = json.dumps(result).encode() if isinstance(result, dict) else result.encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json" if isinstance(result, dict) else "text/plain")
            self.send_header("Content-Length", str(len(data)))
            for name, value in (extra_headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(data)

        def do_PUT(self) -> None:
            metadata_requests.append(("PUT", self.path, dict(self.headers.items())))
            if self.path != "/latest/api/token" or not self.headers.get("x-aws-ec2-metadata-token-ttl-seconds"):
                self.send_error(400, "Unexpected metadata token request")
                return
            self.reply(200, "fixture-imds-token")

        def do_GET(self) -> None:
            metadata_requests.append(("GET", self.path, dict(self.headers.items())))
            # Refuse IMDSv1: success must use the actual botocore IMDSv2 flow.
            if self.headers.get("x-aws-ec2-metadata-token") != "fixture-imds-token":
                self.send_error(401, "IMDSv2 token required")
                return
            if self.path == "/latest/meta-data/iam/security-credentials/":
                self.reply(200, "fixture-role")
            elif self.path == "/latest/meta-data/iam/security-credentials/fixture-role":
                now = datetime.now(UTC)
                self.reply(
                    200,
                    {
                        "Code": "Success",
                        "LastUpdated": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        "Type": "AWS-HMAC",
                        "AccessKeyId": "fixture-imds-access",
                        "SecretAccessKey": "fixture-imds-secret",
                        "Token": "fixture-imds-session",
                        "Expiration": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    },
                )
            else:
                self.send_error(400, "Unexpected metadata request")

        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append((self.path, dict(self.headers.items()), body))
            if self.path.endswith("/chat/completions"):
                result = {
                    "id": "fixture",
                    "object": "chat.completion",
                    "created": 1,
                    "model": "gpt-4o-mini",
                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture-ok"}, "finish_reason": "stop"}],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                }
            elif self.path.endswith("/messages"):
                result = {
                    "id": "fixture",
                    "type": "message",
                    "role": "assistant",
                    "model": "claude-3-haiku-20240307",
                    "content": [{"type": "text", "text": "fixture-ok"}],
                    "stop_reason": "end_turn",
                    "stop_sequence": None,
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                }
            elif self.path.endswith("/converse"):
                if case == "bedrock-bearer-denied":
                    self.reply(403, {"message": "fixture access denied"}, {"x-amzn-ErrorType": "AccessDeniedException"})
                    return
                result = {
                    "output": {"message": {"role": "assistant", "content": [{"text": "fixture-ok"}]}},
                    "stopReason": "end_turn",
                    "usage": {"inputTokens": 1, "outputTokens": 1, "totalTokens": 2},
                    "metrics": {"latencyMs": 1},
                }
            elif self.path.endswith("/api/chat"):
                result = {
                    "model": "llama3.2:3b-instruct-q4_K_M",
                    "created_at": "2026-01-01T00:00:00Z",
                    "message": {"role": "assistant", "content": "fixture-ok"},
                    "done": True,
                    "done_reason": "stop",
                    "prompt_eval_count": 1,
                    "eval_count": 1,
                }
            elif provider == "ollama" and self.path.endswith("/api/show"):
                result = {"model_info": {}, "capabilities": ["completion"]}
            else:
                self.send_error(400, "Unexpected fixture path")
                return
            self.reply(200, result)

    backend = ThreadingHTTPServer(("127.0.0.1", 0), Backend)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {
        **os.environ,
        "LITELLM_MASTER_KEY": MASTER,
        "AISOC_LLM_MODEL_FAST": MODELS[provider],
        "AISOC_LLM_MODEL_DEEP": MODELS[provider],
        "AISOC_LLM_API_BASE": f"http://127.0.0.1:{backend.server_port}" + ("/v1" if provider == "openai" else ""),
        "AISOC_LITELLM_REQUEST_TIMEOUT": "5",
        "AWS_EC2_METADATA_DISABLED": "false" if case in {"bedrock-imds", "bedrock-bearer-imds", "bedrock-bearer-denied"} else "true",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT": f"http://127.0.0.1:{backend.server_port}",
        "AWS_EC2_METADATA_V1_DISABLED": "true",
        "AWS_REGION": "" if case == "bedrock-profile" else "us-east-1",
        "AWS_REGION_NAME": "",
        "AWS_DEFAULT_REGION": "",
        "AWS_PROFILE_NAME": "",
        "AWS_PROFILE": "aisoc-fixture" if case == "bedrock-profile" else "",
        "AWS_CONFIG_FILE": "",
        "AWS_SHARED_CREDENTIALS_FILE": "",
        "AWS_BEARER_TOKEN_BEDROCK": "fixture-bedrock" if "bearer" in case else "",
        "AWS_ACCESS_KEY_ID": "fixture-access" if case in {"bedrock-sigv4", "bedrock-bearer-denied"} else "",
        "AWS_SECRET_ACCESS_KEY": "fixture-secret" if case in {"bedrock-sigv4", "bedrock-bearer-denied"} else "",
        "AWS_SESSION_TOKEN": "fixture-session" if case in {"bedrock-sigv4", "bedrock-bearer-denied"} else "",
        "OPENAI_API_KEY": "fixture-openai" if case in {"openai", "anthropic", "bedrock-bearer-conflict"} else "",
        "ANTHROPIC_API_KEY": "fixture-anthropic" if provider == "anthropic" else "",
    }
    keyless = case.endswith(("-empty-key", "-whitespace-key"))
    if keyless:
        env[f"{provider.upper()}_API_KEY"] = " \t\n" if case.endswith("-whitespace-key") else ""
    if case == "bedrock-bearer-empty-endpoint":
        # Exercise config env resolution and actual HTTP, without reaching AWS.
        # The separate default-endpoint case checks the SDK's regional URL.
        env["AWS_BEDROCK_RUNTIME_ENDPOINT"] = env["AISOC_LLM_API_BASE"]
        env["AISOC_LLM_API_BASE"] = ""
    try:
        with tempfile.TemporaryFile(mode="w+") as logs:
            process = subprocess.Popen(
                [sys.executable, "/etc/litellm/start.py", "--config", "/etc/litellm/config.yaml", "--port", str(port)],
                env=env,
                stdout=logs,
                stderr=subprocess.STDOUT,
            )
            try:
                deadline = time.monotonic() + 75
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise AssertionError(f"Gateway exited {process.returncode}")
                    try:
                        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health/liveliness", timeout=1) as response:
                            if response.status == 200:
                                break
                    except (OSError, urllib.error.URLError):
                        time.sleep(0.25)
                else:
                    raise AssertionError("Gateway readiness timed out")
                request = urllib.request.Request(
                    f"http://127.0.0.1:{port}/v1/chat/completions",
                    data=json.dumps(
                        {"model": "aisoc-triage", "messages": [{"role": "user", "content": "fixture"}], "max_tokens": 8, "stream": False}
                    ).encode(),
                    headers={"Content-Type": "application/json", "Authorization": f"Bearer {MASTER}"},
                )
                if case in {"bedrock-imds-disabled", "bedrock-bearer-denied"}:
                    try:
                        with urllib.request.urlopen(request, timeout=30) as response:
                            raise AssertionError(f"Expected authentication failure, got {response.status}")
                    except urllib.error.HTTPError as error:
                        detail = error.read().decode()
                        assert error.code >= 400
                        if case == "bedrock-imds-disabled":
                            assert "credential" in detail.lower(), detail
                            assert not requests, "A provider request was sent with no credentials"
                        else:
                            assert "fixture access denied" in detail, detail
                            assert requests, "The denying provider was not contacted"
                            for _path, sent_headers, _body in requests:
                                sent_headers = {name.lower(): value for name, value in sent_headers.items()}
                                assert sent_headers["authorization"] == "Bearer fixture-bedrock", (
                                    "Denied bearer fell back to another identity"
                                )
                        assert not metadata_requests, "Authentication unexpectedly queried IMDS"
                    return
                with urllib.request.urlopen(request, timeout=30) as response:
                    assert json.load(response)["choices"][0]["message"]["content"] == "fixture-ok"
                assert requests, "No provider request reached the fixture"
                path, headers, _body = requests[-1]
                headers = {name.lower(): value for name, value in headers.items()}
                assert MASTER not in str(headers), "Gateway credential leaked upstream"
                if provider == "openai":
                    assert path == "/v1/chat/completions"
                    if keyless:
                        assert not headers.get("authorization"), "Keyless endpoint received an authorization header"
                    else:
                        assert headers["authorization"] == "Bearer fixture-openai"
                elif provider == "anthropic":
                    assert path.endswith("/messages")
                    if keyless:
                        assert not headers.get("x-api-key"), "Keyless endpoint received a provider key"
                        assert not headers.get("authorization"), "Keyless endpoint received an authorization header"
                    else:
                        assert headers["x-api-key"] == "fixture-anthropic"
                elif provider == "bedrock":
                    assert path.endswith("/converse")
                    if "bearer" in case:
                        assert headers["authorization"] == "Bearer fixture-bedrock"
                    else:
                        identity = (
                            "fixture-profile" if case == "bedrock-profile" else "fixture-imds" if case == "bedrock-imds" else "fixture"
                        )
                        region = "us-west-1" if case == "bedrock-profile" else "us-east-1"
                        assert headers["authorization"].startswith(f"AWS4-HMAC-SHA256 Credential={identity}-access/")
                        assert f"/{region}/bedrock/aws4_request" in headers["authorization"]
                        assert headers["x-amz-security-token"] == f"{identity}-session"
                else:
                    assert path.endswith("/api/chat")
                if case == "bedrock-imds":
                    assert [(method, path) for method, path, _headers in metadata_requests] == [
                        ("PUT", "/latest/api/token"),
                        ("GET", "/latest/meta-data/iam/security-credentials/"),
                        ("GET", "/latest/meta-data/iam/security-credentials/fixture-role"),
                    ]
                else:
                    assert not metadata_requests, "Available credentials unexpectedly queried IMDS"
            except Exception:
                logs.seek(0)
                print(logs.read()[-12000:])  # Only fixed fixture credentials exist in this isolated container.
                raise
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    finally:
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=5)


@unittest.skipUnless(os.getenv("AISOC_TEST_LITELLM") == "1", "set AISOC_TEST_LITELLM=1 for pinned-image transport checks")
class GatewayHTTPTests(unittest.TestCase):
    def run_image(self, case: str) -> None:
        import yaml

        image = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["litellm"]["image"]
        name = "aisoc-llm-fixture-" + uuid.uuid4().hex
        command = ["docker", "run", "--rm", "--name", name, "--network", "none", "--entrypoint", "python"]
        for source, target in (
            (ROOT / "infra/litellm/start.py", "/etc/litellm/start.py"),
            (ROOT / "infra/litellm/config.yaml", "/etc/litellm/config.yaml"),
            (Path(__file__).resolve(), "/fixture/test.py"),
        ):
            command.extend(["--mount", f"type=bind,source={source},target={target},readonly"])
        command += ["-e", "LITELLM_LOCAL_MODEL_COST_MAP=True", "-e", "DO_NOT_TRACK=True", "-e", "AWS_EC2_METADATA_DISABLED=true"]
        with tempfile.TemporaryDirectory(prefix="aisoc-aws-fixture-") as profile_dir:
            if case == "bedrock-profile":
                # This is a real read-only host-directory mount, like the overlay.
                # It contains only fixed fixture credentials, never the host's AWS files.
                profile = Path(profile_dir)
                (profile / "config").write_text("[profile aisoc-fixture]\nregion = us-west-1\n", encoding="utf-8")
                (profile / "credentials").write_text(
                    "[aisoc-fixture]\naws_access_key_id = fixture-profile-access\n"
                    "aws_secret_access_key = fixture-profile-secret\naws_session_token = fixture-profile-session\n",
                    encoding="utf-8",
                )
                command.extend(["--mount", f"type=bind,source={profile},target=/root/.aws,readonly"])
            try:
                result = subprocess.run(
                    [*command, image, "/fixture/test.py", "--inside", case], capture_output=True, text=True, timeout=180
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            finally:
                subprocess.run(["docker", "rm", "-f", name], capture_output=True, timeout=15, check=False)

    def test_ollama_without_provider_key(self):
        self.run_image("ollama")

    def test_openai_native_key(self):
        self.run_image("openai")

    def test_openai_compatible_endpoint_with_empty_key(self):
        self.run_image("openai-empty-key")

    def test_openai_compatible_endpoint_with_whitespace_key(self):
        self.run_image("openai-whitespace-key")

    def test_anthropic_does_not_use_openai_key(self):
        self.run_image("anthropic")

    def test_anthropic_compatible_endpoint_with_empty_key(self):
        self.run_image("anthropic-empty-key")

    def test_anthropic_compatible_endpoint_with_whitespace_key(self):
        self.run_image("anthropic-whitespace-key")

    def test_bedrock_bearer_with_empty_openai_key(self):
        self.run_image("bedrock-bearer")

    def test_bedrock_bearer_with_conflicting_openai_key(self):
        self.run_image("bedrock-bearer-conflict")

    def test_bedrock_native_credentials(self):
        self.run_image("bedrock-sigv4")

    def test_bedrock_existing_host_profile_with_metadata_disabled(self):
        self.run_image("bedrock-profile")

    def test_bedrock_instance_role_uses_imdsv2_without_explicit_credentials(self):
        self.run_image("bedrock-imds")

    def test_bedrock_metadata_disabled_prevents_instance_role_lookup(self):
        self.run_image("bedrock-imds-disabled")

    def test_bedrock_bearer_skips_enabled_metadata(self):
        self.run_image("bedrock-bearer-imds")

    def test_denied_bedrock_bearer_does_not_fall_back_to_sigv4(self):
        self.run_image("bedrock-bearer-denied")

    def test_blank_endpoint_resolves_through_proxy_config(self):
        self.run_image("bedrock-bearer-empty-endpoint")

    def test_blank_bedrock_endpoint_uses_native_default(self):
        self.run_image("default-endpoint")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        _inside(sys.argv[2])
    else:
        unittest.main()
