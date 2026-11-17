"""Prove gateway reload replaces startup state, using real Compose and HTTP.

The temporary project has no network access and makes no model requests.
Removing --force-recreate from the real make target is the negative control:
the final assertions must fail with the old model still loaded.
"""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import tempfile
import time
import unittest
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_SCRIPT = """
import hashlib, json, os, urllib.request
request = urllib.request.Request(
    'http://127.0.0.1:4000/model/info',
    headers={'Authorization': 'Bearer ' + os.environ['LITELLM_MASTER_KEY']},
)
with urllib.request.urlopen(request, timeout=2) as response:
    models = {item['model_name']: item['litellm_params']['model'] for item in json.load(response)['data']}
with open('/etc/litellm/config.yaml', 'rb') as config:
    digest = hashlib.sha256(config.read()).hexdigest()
print(json.dumps({'model': models['aisoc-reload-fixture'], 'sha256': digest}))
"""


@unittest.skipUnless(os.getenv("AISOC_TEST_LITELLM") == "1", "set AISOC_TEST_LITELLM=1 for real Compose reload checks")
class GatewayReloadTests(unittest.TestCase):
    def test_make_reload_refreshes_a_changed_bind_mount_and_loaded_model(self):
        import yaml

        image = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["litellm"]["image"]
        with tempfile.TemporaryDirectory(prefix="aisoc-reload-fixture-") as directory:
            fixture = Path(directory)
            config_path = fixture / "config.yaml"
            compose_path = fixture / "compose.yaml"
            compose = ["docker", "compose", "-p", "aisoc-reload-" + uuid.uuid4().hex, "-f", str(compose_path)]
            compose_path.write_text(
                yaml.safe_dump(
                    {
                        "services": {
                            "litellm": {
                                "image": image,
                                "network_mode": "none",
                                "entrypoint": ["python", "/etc/litellm/start.py"],
                                "command": ["--config", "/etc/litellm/config.yaml", "--port", "4000"],
                                "environment": {
                                    "LITELLM_MASTER_KEY": "sk-fixture-reload-only",
                                    "OPENAI_API_KEY": "fixture-no-provider-requests",
                                    "LITELLM_LOCAL_MODEL_COST_MAP": "True",
                                    "DO_NOT_TRACK": "True",
                                    "AWS_EC2_METADATA_DISABLED": "true",
                                },
                                "volumes": [
                                    {"type": "bind", "source": str(source), "target": target, "read_only": True}
                                    for source, target in (
                                        (ROOT / "infra/litellm/start.py", "/etc/litellm/start.py"),
                                        (config_path, "/etc/litellm/config.yaml"),
                                    )
                                ],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            def write_config(model: str) -> str:
                config = {
                    "model_list": [{"model_name": "aisoc-reload-fixture", "litellm_params": {"model": model}}],
                    "general_settings": {"master_key": "os.environ/LITELLM_MASTER_KEY"},
                }
                # Write in place: ordinary Compose up must see changed bytes on
                # its existing bind mount while keeping the old startup state.
                config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
                return hashlib.sha256(config_path.read_bytes()).hexdigest()

            def run(*args: str) -> str:
                result = subprocess.run([*compose, *args], capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                return result.stdout.strip()

            def state(expected_hash: str) -> dict:
                deadline = time.monotonic() + 90
                last_output = ""
                while time.monotonic() < deadline:
                    result = subprocess.run(
                        [*compose, "exec", "-T", "litellm", "python", "-c", STATE_SCRIPT],
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    last_output = result.stdout + result.stderr
                    if result.returncode == 0:
                        current = json.loads(result.stdout)
                        if current["sha256"] == expected_hash:
                            return current
                    time.sleep(0.25)
                raise AssertionError("Gateway state did not become readable with the expected mounted bytes: " + last_output)

            try:
                original_hash = write_config("openai/gpt-4o-mini")
                run("up", "-d", "litellm")
                original_id = run("ps", "-q", "litellm")
                self.assertTrue(original_id)
                original = state(original_hash)
                self.assertEqual(original["model"].removeprefix("openai/"), "gpt-4o-mini")

                changed_hash = write_config("openai/gpt-4o")
                self.assertNotEqual(original_hash, changed_hash)
                run("up", "-d", "litellm")
                self.assertEqual(run("ps", "-q", "litellm"), original_id)
                stale = state(changed_hash)
                self.assertEqual(stale["model"], original["model"], "Ordinary up unexpectedly reloaded the mounted YAML")

                result = subprocess.run(
                    ["make", "--no-print-directory", "llm-reload", "COMPOSE=" + shlex.join(compose), "PROFILE="],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                refreshed = state(changed_hash)
                self.assertEqual(refreshed["model"].removeprefix("openai/"), "gpt-4o", "llm-reload kept the old startup model")
                self.assertNotEqual(run("ps", "-q", "litellm"), original_id, "llm-reload did not recreate the container")
            except Exception:
                logs = subprocess.run([*compose, "logs", "--no-color"], capture_output=True, text=True, timeout=15)
                print((logs.stdout + logs.stderr)[-12000:])  # This project contains only fixed fixture credentials.
                raise
            finally:
                subprocess.run([*compose, "down", "--remove-orphans", "--timeout", "5"], capture_output=True, timeout=30, check=False)


if __name__ == "__main__":
    unittest.main()
