#!/usr/bin/env python3
"""No audio may leave the responder app.

Depth 9.6. The plan's wording is exact: voice input "converts speech to text
on the device and sends the text to the grounded copilot. **No audio leaves
the device.**"

A responder saying "what did this host do before the alert" out loud at 3am
is in a room with other people's conversations in it. A SOC product that
uploaded that audio to a transcription service would be exfiltrating its
customer's office, and the customer would have no way to tell — which is
exactly the shape of claim this repository has learned not to make in a
comment.

So the property is checked rather than promised. Two rules:

``no-recording-api``
    No module under ``apps/mobile/src`` may import or reference an audio
    *capture* API. ``src/lib/voice.ts`` is designed so there is nothing to
    reference: it takes a recogniser that returns a **string**, so no
    buffer, blob or file handle appears anywhere in its types and there is
    nothing for a later edit to upload by accident. This rule keeps that
    true as the app grows.

``no-binary-body``
    No ``fetch`` in that tree may send a binary body — ``FormData``,
    ``Blob``, ``ArrayBuffer``, ``Uint8Array`` or a ``ReadableStream``. That
    is the only way audio could physically leave, and refusing the shape is
    stronger than refusing a named API, because a future SDK nobody has
    heard of still has to put the bytes in a request.

Why a denylist of API names is not the whole control
-----------------------------------------------------
Because a denylist is the wrong control on its own — the osquery renderer
blocked ``--``, ``/*`` and ``;`` and never ``'``. ``no-binary-body`` is the
structural half: it does not care what produced the bytes.

Deliberately scoped to ``apps/mobile/src``. The console records audio
nowhere and the services never see a microphone; widening this would add
false positives in file-upload paths that have nothing to do with voice.

Usage:
    python3 scripts/check_no_audio_egress.py
    python3 scripts/check_no_audio_egress.py --self-test

Exit codes: 0 clean, 1 findings.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from gate_toolkit import SELF_TEST_FLAG, repo_root, self_test_main  # noqa: E402

SCOPE = Path("apps/mobile/src")

#: Capture APIs. Each is a thing that produces audio bytes on a device.
_RECORDING = (
    r"expo-av",
    r"expo-audio",
    r"\bAudio\.Recording\b",
    r"react-native-audio",
    r"@react-native-voice/voice",
    r"getUserMedia",
    r"MediaRecorder",
    r"AVAudioRecorder",
    r"startRecording\s*\(",
)
_RECORDING_RE = re.compile("|".join(_RECORDING))

#: Speech SDKs that transcribe or synthesise **in somebody else's cloud**.
#:
#: Wave 2, Phase 9.1. The capture list above catches a module that holds
#: audio bytes. It does not catch the likelier shape: a vendor SDK that takes
#: the microphone itself and streams it to a hosted endpoint, with no `Blob`
#: and no `Audio.Recording` anywhere in this tree. Those are a one-line
#: import and they break the only promise this feature makes.
#:
#: `@react-native-voice/voice` is deliberately in the capture list rather
#: than here: it wraps the platform recogniser, which on Android falls back
#: to Google's servers unless `EXTRA_PREFER_OFFLINE` is set, so it is
#: cloud-capable by default and the gate refuses it outright.
_CLOUD_SPEECH = (
    r"@google-cloud/speech",
    r"@google-cloud/text-to-speech",
    r"microsoft-cognitiveservices-speech-sdk",
    r"@aws-sdk/client-transcribe",
    r"@aws-sdk/client-polly",
    r"@deepgram/sdk",
    r"assemblyai",
    r"elevenlabs",
    r"@speechmatics/",
    r"api\.openai\.com/v1/audio",
    r"speech\.googleapis\.com",
)
_CLOUD_SPEECH_RE = re.compile("|".join(_CLOUD_SPEECH))

#: Speech packages that run **on the device**, and are therefore permitted.
#:
#: Named rather than inferred. A gate that allowed anything not on the
#: denylist would pass the next hosted SDK nobody has added yet, which is the
#: wrong direction for a control whose whole claim is a negative.
ON_DEVICE_SPEECH: frozenset[str] = frozenset(
    {
        # Platform TTS. Speaks through the OS voice; no network leg.
        "expo-speech",
        # On-device Whisper via a bundled GGML model.
        "whisper.rn",
        # On-device model runtime.
        "react-native-executorch",
    }
)

#: Binary request bodies. The structural half: a future SDK nobody has heard
#: of still has to put the bytes somewhere, and this is where.
_BINARY_BODY_RE = re.compile(r"body\s*:\s*(?:new\s+)?(FormData|Blob|ArrayBuffer|Uint8Array|ReadableStream|File)\b")

#: `//` to end of line and `/* */`. A detector that matches prose is the
#: documented way a gate in this tree ends up grading a comment — this one's
#: sibling, `check_mcp_over_http.py`, reported a file for a sentence saying
#: it deliberately does not do the thing.
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)


def code_only(source: str) -> str:
    return _COMMENT_RE.sub(" ", source)


def violations_in(source: str, rel: str) -> list[str]:
    code = code_only(source)
    found: list[str] = []
    for match in _RECORDING_RE.finditer(code):
        line = code[: match.start()].count("\n") + 1
        found.append(
            f"no-recording-api: {rel}:{line}: references {match.group(0)!r}. "
            "The responder app transcribes on the device and sends text; it has no reason "
            "to hold audio bytes at all."
        )
    for match in _CLOUD_SPEECH_RE.finditer(code):
        line = code[: match.start()].count("\n") + 1
        found.append(
            f"no-cloud-speech: {rel}:{line}: references {match.group(0)!r}, which transcribes "
            "or synthesises in a hosted service. The responder app promises that audio never "
            f"leaves the device; the on-device packages are {sorted(ON_DEVICE_SPEECH)}."
        )
    for match in _BINARY_BODY_RE.finditer(code):
        line = code[: match.start()].count("\n") + 1
        found.append(
            f"no-binary-body: {rel}:{line}: sends a {match.group(1)} body. "
            "No request from the responder app may carry binary, because that is the only "
            "way audio could physically leave the device."
        )
    return found


def scan(root: Path) -> list[str]:
    scope = root / SCOPE
    if not scope.is_dir():
        return [f"{SCOPE} is absent — refusing to report a clean tree"]
    found: list[str] = []
    files = sorted(p for p in scope.rglob("*") if p.suffix in {".ts", ".tsx"})
    if not files:
        return [f"no TypeScript under {SCOPE} — refusing to report a clean tree"]
    for path in files:
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        found.extend(violations_in(source, str(path.relative_to(root))))
    return found


def main() -> int:
    root = repo_root()
    problems = scan(root)
    if problems:
        print("Audio could leave the responder app:\n", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        print(f"\n{len(problems)} problem(s).", file=sys.stderr)
        return 1
    count = len([p for p in (root / SCOPE).rglob("*") if p.suffix in {".ts", ".tsx"}])
    print(f"check_no_audio_egress: OK — {count} file(s) under {SCOPE}, no capture API and no binary request body")
    return 0


_CLEAN = """
export async function ask(q: string) {
  return fetch(url, { method: 'POST', body: JSON.stringify({ question: q }) });
}
"""
_RECORDS = "import { Audio } from 'expo-av';\nconst r = new Audio.Recording();\n"
_UPLOADS = "const fd = new FormData();\nawait fetch(url, { method: 'POST', body: FormData });\n"
_COMMENT_ONLY = "// We deliberately never call getUserMedia or send a Blob body.\nexport const x = 1;\n"
_CLOUD_STT = "import { SpeechClient } from '@google-cloud/speech';\nexport const c = new SpeechClient();\n"
_CLOUD_TTS = "import * as sdk from 'microsoft-cognitiveservices-speech-sdk';\nexport const s = sdk;\n"
_ON_DEVICE_TTS = "import * as Speech from 'expo-speech';\nSpeech.speak(answer);\n"
_ON_DEVICE_STT = "import { initWhisper } from 'whisper.rn';\nconst w = await initWhisper({ filePath: model });\n"


def _rule_self_test() -> list[tuple[str, bool]]:
    root = repo_root()
    return [
        ("the tree as committed is clean", not scan(root)),
        ("a JSON body carrying text is not reported", not violations_in(_CLEAN, "f.ts")),
        (
            "importing a recording API is reported",
            any("no-recording-api" in v for v in violations_in(_RECORDS, "f.ts")),
        ),
        (
            "a FormData body is reported",
            any("no-binary-body" in v for v in violations_in(_UPLOADS, "f.ts")),
        ),
        (
            "a comment saying the app does not do it is NOT reported",
            not violations_in(_COMMENT_ONLY, "f.ts"),
        ),
        (
            "a hosted speech-to-text SDK is reported",
            any("no-cloud-speech" in v for v in violations_in(_CLOUD_STT, "f.ts")),
        ),
        (
            "a hosted text-to-speech SDK is reported",
            any("no-cloud-speech" in v for v in violations_in(_CLOUD_TTS, "f.ts")),
        ),
        (
            "an on-device TTS package is NOT reported",
            not violations_in(_ON_DEVICE_TTS, "f.ts"),
        ),
        (
            "an on-device recogniser is NOT reported",
            not violations_in(_ON_DEVICE_STT, "f.ts"),
        ),
        (
            "the on-device allowlist and the cloud denylist do not overlap",
            not any(re.search(_CLOUD_SPEECH_RE, pkg) for pkg in ON_DEVICE_SPEECH),
        ),
        (
            "a Blob body is reported even with no recording API in the file",
            any("no-binary-body" in v for v in violations_in("await fetch(u, { body: new Blob([x]) });", "f.ts")),
        ),
    ]


if __name__ == "__main__":
    if SELF_TEST_FLAG in sys.argv[1:]:
        sys.exit(self_test_main(Path(__file__).name, extra=_rule_self_test()))
    sys.exit(main())
