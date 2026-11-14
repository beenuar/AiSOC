"""CDR: Cloud Detection & Response sub-agent.

Specialized cloud-plane investigator + surgical responder. Where the
ITDR agent owns the IdP session/OAuth surface (Theme 2c), the CDR
agent owns the cloud control plane:

  * **IAM principal graph** — enumerate users/roles with attached
    policies, MFA state, last-used credentials. Flag abandoned
    long-lived access keys, over-privileged roles, and risky trust
    relationships.
  * **STS assume-role chain abuse** — pull recent AssumeRole sessions,
    score chain depth and source-IP/country/ASN anomalies, and trace
    the longest / most suspicious chain back to its origin principal.
    This is the canonical "attacker landed on a low-priv key and
    hopped through three roles to land in prod" pattern.
  * **Kubernetes RBAC anomalies** — surface RoleBindings and
    ClusterRoleBindings that bind default ServiceAccounts to
    cluster-admin, were created outside the change window, or are
    otherwise out of pattern.
  * **Surgical IAM containment** — three forward-only tools, never a
    broad sweep:
      - ``cloud.deactivate_access_key`` — kill one leaked key.
      - ``cloud.attach_deny_policy`` — explicit-Deny-* on one
        principal (when we can't pin down a specific key).
      - ``cloud.delete_k8s_rolebinding`` — delete one suspicious
        binding.
    We do **not** expose `delete-role` / `delete-user` / blanket
    `detach-all-policies` to the LLM — those blast radii are too big
    for an agent, even with HITL.

Containment is forward-only on purpose. See ``app/tools/cloud.py`` for
the per-tool rationale (no auto-rollback for any of the writes).

Handoff
-------
The CDR agent is normally invoked between Investigator and Responder
when the case has a cloud-plane signal (CloudTrail source, AssumeRole
in the title, IAM ARN as src_user, etc.). It returns to the
orchestrator with one of:

  * ``Handoff(to=RESPONDER)`` — cloud contained, but endpoint /
    network / identity work remains.
  * ``Handoff(to=REPORTER)`` — case was cloud-only and is now fully
    contained (or no cloud threat was found).
"""
from __future__ import annotations

import json
from typing import Any

from sqlmodel import select

from app.agents.base import AgentResult, BaseAgent, Handoff, HitlBlocked
from app.config import settings
from app.memory.scratchpad import scratchpad
from app.models.alert import Alert
from app.models.case import Case, Verdict
from app.models.trace import AgentName, TraceStep


# Anomaly thresholds. A session above this score is treated as part of
# an assume-role chain abuse pattern and is eligible for containment.
_STS_ANOMALY_THRESHOLD = 0.6
# Chain depth ≥ this hop count is "deep enough" that legitimate
# automation almost never produces it (most automation is 1 hop).
_CHAIN_DEPTH_THRESHOLD = 2
# K8s binding risk score above this → containment candidate.
_K8S_RISK_THRESHOLD = 0.7
# IAM access-key anomaly above this → deactivation candidate.
_KEY_ANOMALY_THRESHOLD = 0.6
# Hard cap on writes per case so a stalled LLM (or a hallucinated
# "every key looks bad") can't deactivate the whole account.
_MAX_WRITES_PER_CASE = 6


class CDRAgent(BaseAgent):
    """Cloud Detection & Response sub-agent."""

    name = AgentName.CDR
    role = (
        "Cloud-plane detection and response. Owns the IAM principal "
        "graph, STS assume-role chains, and Kubernetes RBAC. Performs "
        "surgical containment — one access key deactivated, one "
        "explicit-deny attached, one RoleBinding deleted — never broad "
        "policy sweeps. All writes route through the HITL gate."
    )
    allowed_tools = [
        # READ — build the picture
        "cloud.list_iam_principals",
        "cloud.get_iam_principal",
        "cloud.list_access_keys",
        "cloud.list_sts_sessions",
        "cloud.trace_assume_role_chain",
        "cloud.list_k8s_rolebindings",
        # WRITE_SIGNIFICANT — surgical containment (HITL-gated by base)
        "cloud.deactivate_access_key",
        "cloud.attach_deny_policy",
        "cloud.delete_k8s_rolebinding",
    ]

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        # Build the candidate principal list. Cloud-flavored alerts can
        # carry the principal in a few places:
        #   * ``src_user`` is sometimes an IAM ARN/username (CloudTrail
        #     normalizers do this).
        #   * Raw event payload often has explicit IAM/STS fields.
        #   * The upstream Investigator may have folded a principal
        #     into ``case.affected_users``.
        candidate_principals: list[str] = []
        if primary:
            for src in (
                primary.src_user,
                (primary.raw or {}).get("iam_principal"),
                (primary.raw or {}).get("user_identity"),
                (primary.raw or {}).get("assumed_role"),
            ):
                if src and src not in candidate_principals:
                    candidate_principals.append(str(src))
        for u in case.affected_users or []:
            if u and u not in candidate_principals and (
                "arn:" in u or "/" in u or u.startswith("i-")
            ):
                candidate_principals.append(u)

        self.trace(
            TraceStep.PLAN,
            f"CDR investigation; candidate principals={candidate_principals}",
            detail={
                "principals": candidate_principals,
                "verdict": getattr(case.verdict, "value", str(case.verdict)),
                "autonomy_level": settings.autonomy_level,
            },
        )

        case_blob = json.dumps(
            {
                "verdict": getattr(case.verdict, "value", str(case.verdict)),
                "severity": getattr(case.severity, "value", str(case.severity)),
                "confidence": case.confidence,
                "title": case.title,
                "affected_users": case.affected_users,
                "affected_hosts": case.affected_hosts,
                "iocs": case.iocs,
            },
            default=str,
        )
        alert_blob = _alert_to_json(primary)

        system_prompt = (
            "You are the CDR (Cloud Detection & Response) agent. Your "
            "job is to investigate cloud-plane compromise (IAM, STS, "
            "Kubernetes RBAC) and execute SURGICAL containment — never "
            "broad sweeps. The platform enforces a risk gate on every "
            "write tool; do not second-guess it, just request the "
            "action.\n"
            "\n"
            "PROCEDURE:\n"
            "  1. `cloud.list_iam_principals()` — pull the principal "
            "     graph. Note any abandoned credentials, missing MFA, "
            "     or unusually high risk_score.\n"
            "  2. `cloud.list_sts_sessions(hours=24)` — pull recent "
            "     AssumeRole sessions. Flag any with "
            f"     `anomaly_score>={_STS_ANOMALY_THRESHOLD}` OR "
            f"     `chain_depth>={_CHAIN_DEPTH_THRESHOLD}` (legitimate "
            "     automation is almost always 1 hop).\n"
            "  3. For the most suspicious session, call "
            "     `cloud.trace_assume_role_chain(session_id=...)` to "
            "     walk the chain back to the origin principal.\n"
            "  4. If the origin principal is an IAM user, call "
            "     `cloud.list_access_keys(user=...)` and identify the "
            "     key with the highest anomaly_score — that's the "
            "     leaked credential.\n"
            "  5. `cloud.list_k8s_rolebindings()` — surface any "
            f"     RoleBinding with `risk_score>={_K8S_RISK_THRESHOLD}`.\n"
            "\n"
            "CONTAINMENT POLICY:\n"
            "  * Prefer the narrowest write that resolves the threat:\n"
            "    - If you've identified the specific leaked key, "
            "      `cloud.deactivate_access_key(user=..., key_id=..., "
            "      reason=...)`. ONE key.\n"
            "    - If you can't pin down a specific key but the "
            "      principal is clearly compromised, "
            "      `cloud.attach_deny_policy(principal=..., reason=...)`. "
            "      This freezes the identity without deleting it "
            "      (preserves forensic state).\n"
            "    - If a K8s RoleBinding crosses the risk threshold, "
            "      `cloud.delete_k8s_rolebinding(name=..., "
            "      namespace=..., reason=...)`. ONE binding.\n"
            "  * Always include a one-sentence `reason` so the audit "
            "    trail explains *why* this specific resource was "
            "    contained.\n"
            "  * Do NOT call `cloud.attach_deny_policy` and "
            "    `cloud.deactivate_access_key` on the same principal "
            "    in the same case — pick the narrower one.\n"
            "\n"
            "STOP when the cloud surface is clean or you've issued the "
            "targeted writes. Return a 2–4 sentence summary naming "
            "each principal / key / binding you contained and why."
        )
        user_msg = (
            f"Case:\n{case_blob}\n\n"
            f"Primary alert:\n{alert_blob}\n\n"
            f"Candidate principals: {candidate_principals}\n\n"
            "Investigate cloud-plane compromise and execute targeted "
            "containment. Stop when the cloud surface is clean."
        )

        try:
            final_text, _msgs = await self.tool_use_loop(
                system=system_prompt,
                user=user_msg,
                max_turns=12,
                max_tokens=1200,
            )
        except HitlBlocked as exc:
            # Analyst denied a containment write. Persist what we've
            # learned so far and hand back to the orchestrator — this
            # is not a crash, it's a human decision.
            self.trace(
                TraceStep.DECISION,
                f"CDR halted: HITL denied containment ({exc.state})",
                detail={"hitl_state": exc.state, "reason": exc.reason},
            )
            final_text = ""
        except Exception as exc:  # pragma: no cover — defensive
            self.trace(
                TraceStep.ERROR,
                f"LLM loop failed: {exc}; falling back to deterministic CDR sweep",
                detail={"error": str(exc)},
            )
            final_text = ""
            await _deterministic_cdr_sweep(self, candidate_principals)

        # Always run a deterministic read-only sweep with sensible
        # defaults. This guarantees the audit trail has a baseline
        # snapshot of the cloud surface regardless of how well the
        # LLM picked tool arguments — critical for mock-LLM runs and
        # for cases where the LLM filters too narrowly.
        await _deterministic_cdr_sweep(self, candidate_principals)

        # Summarize what *actually* happened by reading the tool-call
        # scratchpad. The LLM's narration is logged as rationale, but
        # the audit trail is the ledger of tool results.
        flagged_sessions: list[dict[str, Any]] = []
        suspicious_keys: list[dict[str, Any]] = []
        flagged_bindings: list[dict[str, Any]] = []
        deactivated_keys: list[str] = []
        denied_principals: list[str] = []
        deleted_bindings: list[str] = []
        chain_origins: list[str] = []
        suspicious_principals: list[str] = []

        for r in scratchpad.get(self.case_id, "tool_results", []) or []:
            tool = r["tool"]
            res = r["result"] or {}
            if tool == "cloud.list_sts_sessions":
                for s in res.get("sessions", []) or []:
                    if (
                        (s.get("anomaly_score") or 0) >= _STS_ANOMALY_THRESHOLD
                        or (s.get("chain_depth") or 0) >= _CHAIN_DEPTH_THRESHOLD
                    ):
                        flagged_sessions.append(s)
            elif tool == "cloud.trace_assume_role_chain":
                if res.get("suspicious") and res.get("origin_principal"):
                    chain_origins.append(res["origin_principal"])
            elif tool == "cloud.list_iam_principals":
                for p in res.get("principals", []) or []:
                    if (p.get("risk_score") or 0) >= 0.7:
                        if p.get("arn"):
                            suspicious_principals.append(p["arn"])
            elif tool == "cloud.list_access_keys":
                user = res.get("user")
                for k in res.get("keys", []) or []:
                    if (k.get("anomaly_score") or 0) >= _KEY_ANOMALY_THRESHOLD:
                        enriched = dict(k)
                        enriched.setdefault("user", user)
                        suspicious_keys.append(enriched)
            elif tool == "cloud.list_k8s_rolebindings":
                for b in res.get("bindings", []) or []:
                    if (b.get("risk_score") or 0) >= _K8S_RISK_THRESHOLD:
                        flagged_bindings.append(b)
            elif tool == "cloud.deactivate_access_key" and res.get("deactivated"):
                if res.get("key_id"):
                    deactivated_keys.append(res["key_id"])
            elif tool == "cloud.attach_deny_policy" and res.get("attached"):
                if res.get("principal"):
                    denied_principals.append(res["principal"])
            elif tool == "cloud.delete_k8s_rolebinding" and res.get("deleted"):
                if res.get("name"):
                    deleted_bindings.append(res["name"])

        if final_text:
            self.trace(
                TraceStep.THINK,
                final_text[:400],
                detail={"llm_rationale": final_text},
            )

        # Deterministic backstop: if the LLM identified threats but
        # didn't contain them (stalled, hit max_turns, only enumerated),
        # request the highest-priority writes ourselves. Each call
        # still routes through the HITL gate; this is not a bypass.
        await _deterministic_contain_backstop(
            self,
            suspicious_keys=suspicious_keys,
            chain_origins=chain_origins,
            suspicious_principals=suspicious_principals,
            flagged_bindings=flagged_bindings,
            already_deactivated=set(deactivated_keys),
            already_denied=set(denied_principals),
            already_deleted=set(deleted_bindings),
            deactivated_keys=deactivated_keys,
            denied_principals=denied_principals,
            deleted_bindings=deleted_bindings,
        )

        # Decide handoff. CDR is narrow-scope; never closes a case on
        # its own — Reporter does that.
        cloud_signals = bool(
            flagged_sessions
            or suspicious_keys
            or flagged_bindings
            or chain_origins
        )
        contained = bool(
            deactivated_keys or denied_principals or deleted_bindings
        )

        if cloud_signals and not contained:
            handoff_to = AgentName.RESPONDER
            reason = (
                "Cloud threat detected but not contained from CDR. "
                "Responder should sweep endpoint/identity-side and "
                "analyst will decide on broader containment."
            )
        elif cloud_signals and contained:
            if case.verdict == Verdict.TRUE_POSITIVE and case.affected_hosts:
                handoff_to = AgentName.RESPONDER
                reason = (
                    "Cloud contained (targeted writes). Endpoints "
                    "still on case — Responder for host containment."
                )
            else:
                handoff_to = AgentName.REPORTER
                reason = (
                    "Cloud threat contained via targeted writes; no "
                    "remaining endpoint surface — report and close."
                )
        else:
            handoff_to = AgentName.RESPONDER
            reason = "No cloud-plane threat; defer to Responder."

        self.trace(
            TraceStep.DECISION,
            (
                f"CDR summary: {len(flagged_sessions)} suspicious STS sessions, "
                f"{len(suspicious_keys)} keys, {len(flagged_bindings)} bindings; "
                f"deactivated {len(deactivated_keys)} keys, "
                f"denied {len(denied_principals)} principals, "
                f"deleted {len(deleted_bindings)} bindings"
            ),
            detail={
                "flagged_sessions": [
                    s.get("session_id") for s in flagged_sessions
                ],
                "suspicious_keys": [
                    {"user": k.get("user"), "key_id": k.get("key_id")}
                    for k in suspicious_keys
                ],
                "flagged_bindings": [
                    b.get("name") for b in flagged_bindings
                ],
                "deactivated_keys": deactivated_keys,
                "denied_principals": denied_principals,
                "deleted_bindings": deleted_bindings,
                "handoff_to": handoff_to.value
                if hasattr(handoff_to, "value")
                else str(handoff_to),
            },
        )

        # Stamp the most actionable IOCs (the origin principal ARNs and
        # any specifically deactivated key IDs) back onto the case so
        # the Reporter / Hunter can pivot on them. Wide principal arns
        # are deduped against the existing IOC list.
        new_iocs: list[str] = []
        for arn in chain_origins:
            if arn:
                new_iocs.append(arn)
        for arn in denied_principals:
            if arn:
                new_iocs.append(arn)
        if new_iocs:
            case.iocs = list({*case.iocs, *new_iocs})
            self.db.add(case)
            self.db.commit()

        summary = (
            f"CDR: flagged {len(flagged_sessions)} sessions / "
            f"{len(suspicious_keys)} keys / {len(flagged_bindings)} bindings; "
            f"contained {len(deactivated_keys)} keys / "
            f"{len(denied_principals)} principals / "
            f"{len(deleted_bindings)} bindings."
        )

        return AgentResult(
            summary=summary,
            handoff=Handoff(to=handoff_to, reason=reason),
            case_updates={
                "cdr": {
                    "flagged_sessions": [
                        s.get("session_id") for s in flagged_sessions
                    ],
                    "suspicious_keys": [
                        {
                            "user": k.get("user"),
                            "key_id": k.get("key_id"),
                        }
                        for k in suspicious_keys
                    ],
                    "flagged_bindings": [
                        b.get("name") for b in flagged_bindings
                    ],
                    "deactivated_keys": deactivated_keys,
                    "denied_principals": denied_principals,
                    "deleted_bindings": deleted_bindings,
                    "chain_origins": sorted(set(chain_origins)),
                }
            },
        )


# ── Helpers ────────────────────────────────────────────────────────────


def _alert_to_json(alert: Alert | None) -> str:
    if alert is None:
        return "{}"
    payload = {
        "title": alert.title,
        "description": alert.description,
        "src_ip": alert.src_ip,
        "src_user": alert.src_user,
        "src_host": alert.src_host,
        "source": alert.source,
        "iam_principal": (alert.raw or {}).get("iam_principal"),
        "assumed_role": (alert.raw or {}).get("assumed_role"),
        "event_name": (alert.raw or {}).get("event_name"),
    }
    return json.dumps({k: v for k, v in payload.items() if v}, default=str)


async def _deterministic_cdr_sweep(
    agent: "CDRAgent", principals: list[str]
) -> None:
    """Fallback enumeration if the LLM loop crashed before any READ call.

    Read-only; never writes. The write decision is intentionally left
    to the LLM-driven path OR the deterministic backstop below, both
    of which run *after* this. The point of the sweep is to make sure
    the audit trail still has a snapshot of the cloud surface even
    when the model crashes.
    """
    try:
        await agent.call_tool("cloud.list_iam_principals", {})
    except Exception:  # pragma: no cover — best-effort
        pass
    sessions_res: dict[str, Any] | None = None
    try:
        sessions_res = await agent.call_tool(
            "cloud.list_sts_sessions", {"hours": 24}
        )
    except Exception:  # pragma: no cover — best-effort
        pass
    try:
        await agent.call_tool("cloud.list_k8s_rolebindings", {})
    except Exception:  # pragma: no cover — best-effort
        pass
    # If we know a principal up front, pull its keys too — most of the
    # CDR write paths start from a specific access_key_id.
    for p in principals[:2]:
        try:
            await agent.call_tool(
                "cloud.list_access_keys", {"user": _basename(p)}
            )
        except Exception:  # pragma: no cover — best-effort
            pass
    # Walk the chain on the top anomalous sessions so chain_origins
    # gets populated and the deny-backstop knows which principal to
    # freeze.
    for s in (sessions_res or {}).get("sessions", [])[:3]:
        sid = s.get("session_id")
        if not sid:
            continue
        if (s.get("anomaly_score") or 0) < 0.6 and (s.get("chain_depth") or 0) < 2:
            continue
        try:
            await agent.call_tool(
                "cloud.trace_assume_role_chain", {"session_id": sid}
            )
        except Exception:  # pragma: no cover — best-effort
            pass


async def _deterministic_contain_backstop(
    agent: "CDRAgent",
    *,
    suspicious_keys: list[dict[str, Any]],
    chain_origins: list[str],
    suspicious_principals: list[str],
    flagged_bindings: list[dict[str, Any]],
    already_deactivated: set[str],
    already_denied: set[str],
    already_deleted: set[str],
    deactivated_keys: list[str],
    denied_principals: list[str],
    deleted_bindings: list[str],
) -> None:
    """Request the highest-priority writes if the LLM enumerated but
    didn't act. Each call routes through HITL → audit; this function
    is deterministic glue, not a bypass of the gate.

    Only fires when verdict is TRUE_POSITIVE; for borderline / benign
    cases we leave containment to the human in the loop.
    """
    case = agent.db.get(Case, agent.case_id)
    if case.verdict != Verdict.TRUE_POSITIVE:
        return

    budget = _MAX_WRITES_PER_CASE - (
        len(already_deactivated) + len(already_denied) + len(already_deleted)
    )
    if budget <= 0:
        return

    # 1. Deactivate suspicious keys first — narrowest containment.
    suspicious_keys_sorted = sorted(
        suspicious_keys,
        key=lambda k: k.get("anomaly_score") or 0,
        reverse=True,
    )
    for k in suspicious_keys_sorted:
        if budget <= 0:
            break
        kid = k.get("key_id")
        user = k.get("user")
        if not kid or not user or kid in already_deactivated:
            continue
        try:
            res = await agent.call_tool(
                "cloud.deactivate_access_key",
                {
                    "user": user,
                    "key_id": kid,
                    "reason": "CDR backstop: anomalous access key",
                },
                rationale="CDR deterministic backstop after LLM stall",
                blast_radius={"keys": 1, "scope": "single-key"},
            )
            if (res or {}).get("deactivated"):
                deactivated_keys.append(kid)
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            continue

    # 2. Explicit-deny on origin principals if we walked a suspicious
    #    chain back to one. We only deny principals we haven't already
    #    surgically contained at the key level.
    keys_users_done = {
        f.get("user") for f in suspicious_keys_sorted if f.get("key_id") in set(deactivated_keys)
    }
    deny_targets: list[str] = []
    for arn in chain_origins + suspicious_principals:
        if not arn or arn in already_denied or arn in deny_targets:
            continue
        if _basename(arn) in keys_users_done:
            # Already contained at key level — don't pile on a deny.
            continue
        deny_targets.append(arn)

    for arn in deny_targets:
        if budget <= 0:
            break
        try:
            res = await agent.call_tool(
                "cloud.attach_deny_policy",
                {
                    "principal": arn,
                    "reason": "CDR backstop: suspicious STS chain origin",
                },
                rationale="CDR deterministic backstop after LLM stall",
                blast_radius={"principals": 1, "scope": "single-principal"},
            )
            if (res or {}).get("attached"):
                denied_principals.append(arn)
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            continue

    # 3. Finally, prune the worst K8s RoleBindings. Forward-only —
    #    operators must re-apply from GitOps if needed.
    bindings_sorted = sorted(
        flagged_bindings,
        key=lambda b: b.get("risk_score") or 0,
        reverse=True,
    )
    for b in bindings_sorted:
        if budget <= 0:
            break
        name = b.get("name")
        if not name or name in already_deleted:
            continue
        try:
            res = await agent.call_tool(
                "cloud.delete_k8s_rolebinding",
                {
                    "name": name,
                    "namespace": b.get("namespace"),
                    "reason": "CDR backstop: high-risk RoleBinding",
                },
                rationale="CDR deterministic backstop after LLM stall",
                blast_radius={"bindings": 1, "scope": "single-binding"},
            )
            if (res or {}).get("deleted"):
                deleted_bindings.append(name)
                budget -= 1
        except HitlBlocked:
            return
        except Exception:  # pragma: no cover — defensive
            continue


def _basename(arn_or_name: str) -> str:
    """Best-effort principal-name extraction from an ARN or path.

    ``arn:aws:iam::123:user/alice`` → ``alice``
    ``role/automation`` → ``automation``
    ``alice`` → ``alice``

    Used so the LLM can hand us either form and our backstop still
    calls ``cloud.list_access_keys(user="alice")`` correctly.
    """
    if "/" in arn_or_name:
        return arn_or_name.rsplit("/", 1)[-1]
    if ":" in arn_or_name:
        return arn_or_name.rsplit(":", 1)[-1]
    return arn_or_name
