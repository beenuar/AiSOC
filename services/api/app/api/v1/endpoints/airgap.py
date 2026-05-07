"""Air-gap status endpoint — Tier 3.1 (air-gapped certification).

Exposes a snapshot of the current air-gap egress policy so operators can
verify zero-egress mode is engaged on every API pod without parsing logs
or shelling into the container. The endpoint is intentionally:

* **Unauthenticated.** It returns no secrets — just the boolean
  ``enabled`` flag, the operator-supplied allowlist, and the
  always-allowed private suffixes. An auditor or k8s liveness probe can
  hit it directly.
* **Cheap.** Pure in-memory read of the cached ``Settings`` object; safe
  to poll on a short interval.
* **A peer of /health.** ``/health`` already includes ``airgap_status()``
  so liveness checks pick it up automatically; this endpoint exists for
  the docs site (`apps/docs/docs/operations/airgap.md`) and for ops
  tooling that wants the snapshot without parsing the rest of the
  health envelope.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.core.airgap import airgap_status

router = APIRouter(prefix="/airgap", tags=["airgap"])


@router.get("/status", summary="Current air-gap egress policy")
async def get_airgap_status() -> dict[str, object]:
    """Return the live air-gap policy snapshot for this pod.

    Response shape::

        {
            "enabled": false,
            "allowlist": ["mirror.example.com"],
            "implicit_private_suffixes": [".local", ".internal", ...],
            "policy": "Air-gapped mode is OFF — outbound HTTP is unrestricted."
        }

    The ``policy`` field is a human-readable summary suitable for
    embedding in audit reports.
    """
    return airgap_status()
