"""`aisoc memory export` — produce a portable, signed memory pack.

Distills a memory pack from an analyst-override JSON file and exports it signed
(Ed25519) so an MSSP can bootstrap a new child tenant from a curated baseline.

Usage (from repo root):
    pnpm aisoc:memory:export -- --overrides overrides.json --out pack.json

The signing key is read from ``AISOC_MEMORY_SIGNING_KEY`` (base64 Ed25519
private key); if unset, an ephemeral key is generated and its public key is
printed so the recipient can pin it. With ``--demo`` a small synthetic override
set is used so the command runs with zero setup.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.memory.distill import distill
from app.memory.pack import export_pack


def _demo_row(category: str, connector: str, technique: str, verdict: str, summary: str) -> dict:
    return {
        "category": category,
        "connector_type": connector,
        "primary_technique": technique,
        "corrected_verdict": verdict,
        "summary": summary,
    }


_DEMO_OVERRIDES = [
    _demo_row("cloud", "aws_guardduty", "T1078", "false_positive", "Service-account console login in maintenance window"),
    _demo_row("cloud", "aws_guardduty", "T1078", "false_positive", "Same benign pattern"),
    _demo_row("endpoint", "crowdstrike", "T1486", "true_positive", "Confirmed ransomware encryption"),
    _demo_row("identity", "okta", "T1110", "false_positive", "User fat-fingered password, no compromise"),
]


def _load_key() -> str:
    env = os.environ.get("AISOC_MEMORY_SIGNING_KEY", "").strip()
    if env:
        return env
    priv = Ed25519PrivateKey.generate()
    pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    print(
        f"[aisoc memory] no AISOC_MEMORY_SIGNING_KEY set — generated an ephemeral key. Pin this public key on import:\n  {pub}",
        file=sys.stderr,
    )
    return base64.b64encode(priv.private_bytes_raw()).decode()


def main() -> int:
    parser = argparse.ArgumentParser(prog="aisoc memory export", description=__doc__)
    parser.add_argument("--overrides", help="Path to a JSON array of analyst-override rows.")
    parser.add_argument("--out", help="Write the signed pack here (default: stdout).")
    parser.add_argument("--demo", action="store_true", help="Use a bundled synthetic override set.")
    args = parser.parse_args()

    if args.demo or not args.overrides:
        overrides = _DEMO_OVERRIDES
    else:
        with open(args.overrides, encoding="utf-8") as fh:
            overrides = json.load(fh)

    pack = distill(overrides)
    signed = export_pack(pack, _load_key())

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(signed)
        print(f"[aisoc memory] wrote signed pack {pack.version} ({len(pack.priors)} priors) → {args.out}", file=sys.stderr)
    else:
        print(signed)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
