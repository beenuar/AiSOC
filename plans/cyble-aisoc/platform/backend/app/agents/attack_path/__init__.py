"""Attack-Path Agent package (todo ``t2g-attack-path``).

The Attack-Path Agent is a *proactive*, scheduled service — not a
reactive sub-agent driven by an incoming alert. It fuses:

* Cyble ASM (external exposures, exposed services, known-CVE assets)
* Cloud IAM (principals, STS chains, K8s rolebindings) via the
  Connector SDK
* Identity (users, groups, OAuth grants, sessions)

into a single Pre-Attack Path Graph using the extended
:mod:`app.models.graph` schema (``EXPOSURE``, ``ROLE``, ``PERMISSION``,
``GROUP`` nodes; ``EXPOSED_AS``, ``CAN_ASSUME_ROLE``, ``HAS_PERMISSION``,
``MEMBER_OF``, ``CAN_REACH``, ``CAN_PRIVESC_TO`` edges).

It then ranks pre-attack paths from external exposure surface to
high-value cloud admin and creates proactive ``Case`` rows so the SOC
can fix toxic combinations *before* the adversary uses them.

Unlike sub-agents, the Attack-Path Agent does **not** inherit from
:class:`app.agents.base.BaseAgent`. Its tool surface is read-only and
it manages its own tenancy enforcement; it speaks directly to
connectors and to the graph memory layer.
"""
from __future__ import annotations

from app.agents.attack_path.agent import (
    AttackPath,
    AttackPathAgent,
    AttackPathScanResult,
)

__all__ = ["AttackPath", "AttackPathAgent", "AttackPathScanResult"]
