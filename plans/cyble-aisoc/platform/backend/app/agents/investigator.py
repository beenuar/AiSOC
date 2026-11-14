"""Investigator: deep evidence gathering, driven by LLM tool-use.

The Investigator gets a richer system prompt (process trees, dark-web, ASM,
brand intel, email analysis are all on the table) and the LLM decides which
threads to pull. As with Triager, the **verdict** stays deterministic — it's
computed from the gathered evidence so the audit log is reproducible.
"""
from __future__ import annotations

import json
from typing import Any

from sqlmodel import select

from app.agents.base import AgentResult, BaseAgent, Handoff
from app.memory.scratchpad import scratchpad
from app.models.alert import Alert
from app.models.case import Case, Verdict
from app.models.trace import AgentName, TraceStep


class InvestigatorAgent(BaseAgent):
    name = AgentName.INVESTIGATOR
    role = (
        "Deep evidence gathering. Process tree, network telemetry, dark-web context, "
        "ASM context. Produces verdict with confidence and IOC list."
    )
    allowed_tools = [
        "siem.search_events",
        "edr.get_process_tree",
        "cti.enrich_ioc",
        "cti.darkweb_search",
        "cti.brand_intel",
        "cti.asm_lookup",
        "email.analyze_message",
        "idp.get_user",
        # Live forensics escalation path — READ-class only. Containment
        # (forensics.kill_process, DESTRUCTIVE) belongs to Responder under
        # HITL, never to the Investigator.
        "forensics.collect_artifact",
        "forensics.run_hunt",
        "forensics.fetch_file",
        # Asset/CMDB lookup so the LLM can weigh criticality before
        # deciding whether deep-forensics is worth the latency cost.
        "asset.get_context",
    ]

    async def run(self) -> AgentResult:
        case = self.db.get(Case, self.case_id)
        # Defense-in-depth tenant filter: alerts attached to this case
        # should share its tenant by construction, but we filter on the
        # column anyway so a stale row can't leak cross-tenant context.
        alerts = self.db.exec(
            select(Alert)
            .where(Alert.case_id == self.case_id)
            .where(Alert.tenant_id == self.tenant_id)
        ).all()
        primary = alerts[0] if alerts else None

        self.trace(
            TraceStep.PLAN,
            "LLM-directed investigation: process tree, lateral signals, dark-web/ASM/brand context",
            detail={"primary_alert": primary.title if primary else None},
        )

        alert_blob = _alert_to_json(primary)

        system_prompt = (
            "You are the Investigator agent in a SOC. You build the case file: "
            "process tree, lateral movement, dark-web exposure, ASM context, "
            "brand impersonation, and email analysis when relevant.\n"
            "Strategy:\n"
            "- If a host is present, ALWAYS pull `edr.get_process_tree` first.\n"
            "- Run `siem.search_events` on the strongest entity to look for "
            "  lateral movement / repeat actors.\n"
            "- Use `cti.darkweb_search` when there's a username, email, or domain "
            "  worth checking for exposure.\n"
            "- Use `cti.asm_lookup` on the tenant's external surface for context.\n"
            "- Use `cti.brand_intel` only if you see signs of phishing / brand abuse.\n"
            "- Use `email.analyze_message` only if the alert is mail-related.\n"
            "- Use `asset.get_context` when host criticality / owner matters "
            "  for the response decision.\n"
            "Deep-forensics escalation (LIVE endpoint via Velociraptor):\n"
            "- Only escalate to forensics when EDR telemetry is shallow OR the "
            "  host criticality demands it OR you need an artifact EDR can't "
            "  return (registry hive, prefetch, scheduled tasks, on-disk file).\n"
            "- `forensics.collect_artifact` pulls a named VQL artifact "
            "  (Windows.System.Pslist, Windows.Persistence.PermanentWMIEvents, "
            "  Linux.Sys.BashShell, etc.) from a specific host. Use when you "
            "  need ground-truth state, not EDR's interpretation.\n"
            "- `forensics.run_hunt` fans an artifact across a label/host set "
            "  for retro-hunt / blast-radius. Use sparingly — it touches many "
            "  endpoints. Prefer label_selector over wide host_ids lists.\n"
            "- `forensics.fetch_file` retrieves an actual file body (binary, "
            "  config, log) for offline analysis. Use only when a hash or "
            "  path is already in evidence; never on user-controlled paths.\n"
            "- Forensics is slow (seconds–minutes) and noisy on the endpoint. "
            "  Do NOT call it on clearly-benign cases. If you call it, "
            "  justify it in your final rationale.\n"
            "- Aim for 3–6 distinct tool calls (more is fine if deep-forensics "
            "  is on). Stop when the picture is clear.\n"
            "When you stop, return a 2–4 sentence rationale describing what you found."
        )
        user_msg = (
            f"Primary alert:\n{alert_blob}\n\n"
            "Investigate. Decide which tools matter. Stop when you have enough "
            "to recommend a verdict (TP / borderline / benign)."
        )

        try:
            final_text, _msgs = await self.tool_use_loop(
                system=system_prompt,
                user=user_msg,
                max_turns=8,
                max_tokens=900,
            )
        except Exception as exc:  # pragma: no cover - defensive
            self.trace(
                TraceStep.ERROR,
                f"LLM tool-use loop failed: {exc}; falling back to deterministic playbook",
                detail={"error": str(exc)},
            )
            final_text = ""
            await _deterministic_investigate(self, primary)

        results = scratchpad.get(self.case_id, "tool_results", []) or []
        if not results and primary is not None:
            await _deterministic_investigate(self, primary)
            results = scratchpad.get(self.case_id, "tool_results", []) or []

        suspicious: list[str] = []
        iocs: list[str] = []
        deep_forensics_used = False
        for r in results:
            tool = r["tool"]
            res = r["result"]
            if tool == "edr.get_process_tree":
                for entry in _walk_tree(res.get("tree", [])):
                    if entry.get("suspicious"):
                        suspicious.append(f"process:{entry['name']}/{entry['pid']}")
            elif tool == "cti.enrich_ioc":
                ioc = res.get("ioc")
                if res.get("threat_score", 0) >= 50 and ioc:
                    iocs.append(ioc)
            elif tool == "cti.darkweb_search":
                if res.get("hits"):
                    suspicious.append(f"darkweb:{len(res['hits'])} hits")
            elif tool == "cti.brand_intel":
                if res.get("typosquats") or res.get("phishing_hits"):
                    suspicious.append("brand:typosquat/phish")
            elif tool == "email.analyze_message":
                if res.get("verdict") in {"malicious", "phishing"}:
                    suspicious.append("email:malicious")
            elif tool == "forensics.collect_artifact":
                # Live-endpoint artifact came back. Any non-empty row set on
                # a persistence / process / scheduled-task artifact is
                # ground-truth evidence — heavier than the EDR's
                # interpretation because we just read the host directly.
                deep_forensics_used = True
                row_count = (
                    res.get("row_count")
                    or len(res.get("rows") or [])
                    or 0
                )
                artifact = (res.get("artifact") or "").lower()
                if row_count > 0:
                    # Persistence-class artifacts: even a single row is
                    # high-signal. Process listings need more rows before
                    # they tell us anything new.
                    persistence_markers = (
                        "persistence",
                        "scheduledtasks",
                        "scheduled_tasks",
                        "services",
                        "autoruns",
                        "wmieventconsumer",
                    )
                    if any(m in artifact for m in persistence_markers):
                        suspicious.append(
                            f"forensics:{res.get('artifact', 'artifact')} "
                            f"({row_count} rows)"
                        )
                    elif row_count >= 5:
                        suspicious.append(
                            f"forensics:{res.get('artifact', 'artifact')} "
                            f"({row_count} rows)"
                        )
            elif tool == "forensics.run_hunt":
                # Retro-hunt: blast-radius signal. If more than a couple of
                # hosts came back positive we treat it as a confirmed
                # lateral pattern, not a single-host event.
                deep_forensics_used = True
                hits = res.get("host_hits") or res.get("hosts") or []
                if isinstance(hits, list) and len(hits) >= 2:
                    suspicious.append(f"forensics-hunt:{len(hits)} hosts")
            elif tool == "forensics.fetch_file":
                # We pulled a real file off the host. Note that we did the
                # work; the file's own evil-ness will surface via a later
                # cti.enrich_ioc on its hash. We don't double-count here.
                deep_forensics_used = True
                if res.get("sha256") and res.get("sha256") not in iocs:
                    # Track the hash as a candidate IOC so downstream agents
                    # can enrich it; we don't bump suspicion off the hash
                    # alone until enrichment scores it.
                    iocs.append(res["sha256"])

        if final_text:
            self.trace(
                TraceStep.THINK,
                final_text[:400],
                detail={"llm_rationale": final_text},
            )

        # Verdict logic (deterministic over gathered evidence). Live
        # forensics evidence is ground-truth (we read the host directly via
        # Velociraptor, not via the EDR's interpretation), so when it's
        # present we tighten confidence and we let a single corroborating
        # IOC or forensics-hunt hit be enough to clear the TP bar — the
        # forensic artifact itself already counts as independent evidence.
        forensics_suspicion = sum(
            1 for s in suspicious if s.startswith("forensics")
        )
        if len(suspicious) >= 2 and iocs:
            verdict = Verdict.TRUE_POSITIVE
            confidence = 0.95 if deep_forensics_used else 0.92
            handoff_to = AgentName.RESPONDER
            reason = (
                "Confirmed malicious activity"
                + (" (corroborated by live host forensics)" if deep_forensics_used else "")
                + ". Containment required."
            )
        elif deep_forensics_used and forensics_suspicion >= 1 and (iocs or suspicious):
            # Forensics confirmed something on the host. Even without a
            # second classical signal we treat this as TP because the
            # evidence came from the host itself, not from an inference.
            verdict = Verdict.TRUE_POSITIVE
            confidence = 0.88
            handoff_to = AgentName.RESPONDER
            reason = (
                "Live host forensics confirms suspicious artifact on endpoint. "
                "Containment required."
            )
        elif suspicious:
            verdict = Verdict.NEEDS_HUMAN
            confidence = 0.7 if deep_forensics_used else 0.65
            handoff_to = AgentName.RESPONDER
            reason = "Likely TP but borderline. HITL on response actions."
        else:
            verdict = Verdict.BENIGN
            confidence = 0.78
            handoff_to = AgentName.REPORTER
            reason = "No corroborating evidence; closing as benign with explanation."

        # Identity routing: if the case has a user entity AND the verdict
        # warrants response (TP or borderline), insert ITDR between
        # Investigator and Responder so the session graph + OAuth grants are
        # checked and surgically contained *before* generic endpoint
        # containment runs. ITDR will hand back to Responder (if hosts are
        # also implicated) or Reporter (identity-only case).
        has_identity = bool(primary and primary.src_user) or bool(case.affected_users)
        # Cloud routing: if the case looks cloud-plane (AWS/GCP/Azure source,
        # IAM/STS principal in src_user, K8s entity in raw), insert CDR so
        # IAM principal graph + STS chains + K8s rolebindings are walked and
        # surgically contained before any generic endpoint Responder pass.
        has_cloud = _alert_looks_cloud(primary)
        # SaaS routing: M365 OAuth abuse, Workspace public-share leak,
        # GitHub secret-exposure, Salesforce admin MFA off, Slack
        # external-bot installs all live on the SaaS surface, not the
        # IdP/cloud/endpoint surface. SaaS Posture handles them.
        has_saas = _alert_looks_saas(primary)
        # Phishing routing: messages from email connectors (Proofpoint /
        # M365 / Workspace mail), reported-phish queues, or alerts whose
        # raw payload carries email primitives (headers, links, message_id)
        # belong to the Phishing Triage deep specialist. We route there
        # ahead of ITDR/CDR/SaaS because the deciding signals (header
        # alignment, brand impersonation, kit fingerprint) all live inside
        # the email itself; the broader lateral / identity check only
        # makes sense after the message is classified.
        has_phishing = _alert_looks_phishing(primary)
        if has_phishing and verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_HUMAN):
            handoff_to = AgentName.PHISHING_TRIAGE
            reason = (
                "Email-derived alert "
                f"(source={primary.source if primary else ''}); "
                "Phishing Triage for header analysis, URL detonation, and "
                "brand-impersonation scoring before broader response."
            )
        elif has_cloud and verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_HUMAN):
            handoff_to = AgentName.CDR
            reason = (
                "Cloud-plane entity on case "
                f"(source={primary.source if primary else ''}, "
                f"principal={primary.src_user if primary else ''}); "
                "CDR for IAM/STS graph + K8s rolebinding review before "
                "endpoint response."
            )
        elif has_saas and verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_HUMAN):
            handoff_to = AgentName.SAAS_POSTURE
            reason = (
                "SaaS-plane entity on case "
                f"(source={primary.source if primary else ''}); "
                "SaaS Posture for app/share/grant review before "
                "endpoint response."
            )
        elif has_identity and verdict in (Verdict.TRUE_POSITIVE, Verdict.NEEDS_HUMAN):
            handoff_to = AgentName.ITDR
            reason = (
                f"Identity entity on case ({primary.src_user if primary else ''}); "
                "ITDR for session graph + OAuth grant review before endpoint response."
            )

        self.trace(
            TraceStep.DECISION,
            f"Verdict={verdict.value} confidence={confidence:.2f}",
            detail={"suspicious_signals": suspicious, "iocs": iocs},
        )

        case.verdict = verdict
        case.confidence = confidence
        case.iocs = list(set(case.iocs + iocs))
        if primary and primary.src_host:
            case.affected_hosts = list(set(case.affected_hosts + [primary.src_host]))
        if primary and primary.src_user:
            case.affected_users = list(set(case.affected_users + [primary.src_user]))
        self.db.add(case)
        self.db.commit()

        return AgentResult(
            summary=f"Investigation complete: {verdict.value}",
            handoff=Handoff(to=handoff_to, reason=reason),
        )


def _walk_tree(nodes):
    for n in nodes or []:
        yield n
        yield from _walk_tree(n.get("children") or [])


def _alert_to_json(alert: Alert | None) -> str:
    if alert is None:
        return "{}"
    payload = {
        "title": alert.title,
        "description": alert.description,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_host": alert.src_host,
        "src_user": alert.src_user,
        "file_hash": alert.file_hash,
        "process_name": getattr(alert, "process_name", None),
    }
    return json.dumps({k: v for k, v in payload.items() if v}, default=str)


def _alert_looks_cloud(alert: Alert | None) -> bool:
    """Heuristic: does this alert touch the cloud control-plane?

    Signals we accept (any is enough):
      - source vendor is a known cloud/k8s source (e.g. cloudtrail,
        guardduty, aws, gcp, azure, kubernetes/eks/gke/aks).
      - src_user looks like an IAM/STS principal ARN
        (arn:aws:iam::..., arn:aws:sts::...) or a GCP/Azure principal hint.
      - raw payload carries a cloud-typed hint (`cloud_provider`,
        `iam_principal`, `assumed_role`, `k8s_namespace`, etc.).

    We're conservative on purpose: ITDR is the right home for pure IdP
    cases (Okta/AAD user sessions); CDR is only invoked when the alert
    actually has cloud control-plane context worth walking.
    """
    if alert is None:
        return False

    source = (alert.source or "").lower()
    cloud_sources = {
        "cloudtrail",
        "guardduty",
        "aws",
        "aws-cloudtrail",
        "gcp",
        "gcp-audit",
        "azure",
        "azure-activity",
        "kubernetes",
        "k8s",
        "eks",
        "gke",
        "aks",
    }
    if any(token in source for token in cloud_sources):
        return True

    principal = (alert.src_user or "").lower()
    if principal.startswith("arn:aws:iam::") or principal.startswith("arn:aws:sts::"):
        return True
    # GCP service accounts look like name@project.iam.gserviceaccount.com;
    # Azure managed identities surface as objectId GUIDs on AAD events but
    # those flow through the ITDR path — keep this conservative.
    if principal.endswith(".iam.gserviceaccount.com"):
        return True

    raw = alert.raw or {}
    cloud_hints = (
        "cloud_provider",
        "iam_principal",
        "assumed_role",
        "assume_role_chain",
        "k8s_namespace",
        "k8s_rolebinding",
    )
    if any(key in raw for key in cloud_hints):
        return True

    return False


def _alert_looks_saas(alert: Alert | None) -> bool:
    """Heuristic: does this alert touch a SaaS posture surface?

    Signals (any is enough):
      - source vendor is one of the v1 SSPM providers (m365, workspace,
        google, salesforce, github, slack) or a known SSPM connector
        name (e.g. ``saas``, ``sspm``, ``adaptive-shield``).
      - raw payload carries a SaaS-typed hint (``saas_provider``,
        ``oauth_app_id``, ``share_id``, ``third_party_grant``, etc.).
      - title hints at SaaS OAuth abuse / public-link sharing.

    Intentionally conservative — IdP user-session work stays with ITDR,
    cloud-plane IAM work stays with CDR. SaaS Posture only fires when
    the alert is clearly about app inventory, third-party grants, or
    external sharing.
    """
    if alert is None:
        return False

    source = (alert.source or "").lower()
    saas_sources = {
        "m365",
        "office365",
        "o365",
        "workspace",
        "google-workspace",
        "gws",
        "salesforce",
        "sfdc",
        "github",
        "gh",
        "slack",
        "saas",
        "sspm",
    }
    if any(token in source for token in saas_sources):
        return True

    raw = alert.raw or {}
    saas_hints = (
        "saas_provider",
        "oauth_app_id",
        "oauth_grant_id",
        "third_party_grant",
        "share_id",
        "sharing_link",
        "external_collaborator",
        "repo_visibility",
        "slack_app_id",
    )
    if any(key in raw for key in saas_hints):
        return True

    title = (alert.title or "").lower()
    saas_title_hints = (
        "oauth grant",
        "oauth consent",
        "illicit consent",
        "public share",
        "public link",
        "external share",
        "third-party app",
        "exposed secret",
        "repo went public",
    )
    if any(hint in title for hint in saas_title_hints):
        return True

    return False


def _alert_looks_phishing(alert: Alert | None) -> bool:
    """Heuristic: does this alert look like a suspicious email report?

    Signals (any is enough):
      - source vendor is an email-security connector (proofpoint, mimecast,
        m365-defender, gws-mail) or a reported-phish queue.
      - raw payload carries email primitives (message_id, from, links,
        spf/dkim/dmarc verdicts).
      - title hints at phishing / suspicious mail / brand impersonation.

    We route on signal, not on verdict — even a "suspicious"-class alert
    benefits from the deep header / URL / brand pass before any analyst
    decision. SaaS/Cloud/IdP routing still wins if the alert also carries
    those signals, because they're typically post-compromise outcomes.
    """
    if alert is None:
        return False

    source = (alert.source or "").lower()
    email_sources = {
        "proofpoint",
        "mimecast",
        "abnormal",
        "ironscales",
        "m365-defender",
        "defender-office",
        "exchange-online",
        "gws-mail",
        "google-mail",
        "phishtank",
        "reported-phish",
        "user-reported",
        "phish-report",
        "email",
        "mail",
    }
    if any(token in source for token in email_sources):
        return True

    raw = alert.raw or {}
    email_hints = (
        "message_id",
        "messageId",
        "internet_message_id",
        "from_address",
        "envelope_from",
        "return_path",
        "spf",
        "dkim",
        "dmarc",
        "subject",
        "links",
    )
    if any(key in raw for key in email_hints):
        return True

    title = (alert.title or "").lower()
    description = (alert.description or "").lower()
    phish_title_hints = (
        "phish",
        "phishing",
        "suspicious email",
        "suspicious mail",
        "reported message",
        "credential harvest",
        "lookalike domain",
        "brand impersonation",
        "homoglyph",
        "typosquat",
    )
    if any(hint in title or hint in description for hint in phish_title_hints):
        return True

    return False


async def _deterministic_investigate(
    agent: "InvestigatorAgent", primary: Alert | None
) -> None:
    """Fallback playbook if the LLM declines to act."""
    if primary is None:
        return
    tree_was_shallow = False
    if primary.src_host:
        edr_res = await agent.call_tool(
            "edr.get_process_tree",
            {"host": primary.src_host, "process_name": primary.process_name or ""},
        )
        # "Shallow" = EDR returned nothing or one-deep summary. Either the
        # endpoint hasn't streamed telemetry yet, the agent is offline, or
        # the EDR is hiding LOLBins under summarised parents. In all three
        # cases the right next move is a live read.
        tree = (edr_res or {}).get("tree") if isinstance(edr_res, dict) else None
        if not tree or (isinstance(tree, list) and len(tree) <= 1):
            tree_was_shallow = True

        await agent.call_tool(
            "siem.search_events",
            {"entity": primary.src_host, "entity_type": "host", "minutes": 120},
        )

        # Pull asset/CMDB context so we know whether the host is worth the
        # deep-forensics cost (crown-jewel vs. dev laptop).
        asset_ctx: dict[str, Any] = {}
        try:
            asset_ctx = await agent.call_tool(
                "asset.get_context",
                {"identifier": primary.src_host},
            ) or {}
        except Exception:
            asset_ctx = {}
        criticality = str(asset_ctx.get("criticality") or "").lower()
        host_is_critical = criticality in {"critical", "high"}

        # ── Deep-forensics escalation (deterministic path) ───────────────
        # Only escalate when EDR is shallow OR the host is high-value. We
        # default to a generic process listing because it's cheap, single-
        # host, and gives us ground-truth process state when the EDR is
        # blind. If a process name is in the alert we narrow on it.
        if tree_was_shallow or host_is_critical:
            artifact_name = "Generic.System.Pslist"
            params: dict[str, Any] = {}
            if primary.process_name:
                params["process_regex"] = primary.process_name
            try:
                await agent.call_tool(
                    "forensics.collect_artifact",
                    {
                        "host": primary.src_host,
                        "artifact": artifact_name,
                        "parameters": params,
                        "timeout_s": 120,
                    },
                    rationale=(
                        "EDR telemetry shallow" if tree_was_shallow
                        else f"host criticality={criticality}"
                    ),
                )
            except Exception:
                # Forensics platform may not be configured for this tenant.
                # That's fine — the rest of the playbook still runs and the
                # case proceeds without ground-truth host data.
                pass

    if primary.src_user:
        await agent.call_tool(
            "cti.darkweb_search",
            {"query": primary.src_user, "days": 60},
        )
    await agent.call_tool("cti.asm_lookup", {"domain": "cyble.com"})
