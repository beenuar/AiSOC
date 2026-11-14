"""Kind-specific connector contracts.

Each `BaseXxxConnector` pins the operation surface a tool handler in
`app/tools/<kind>.py` is allowed to call. Concrete vendor connectors
(e.g. `SplunkSiemConnector`) inherit one of these and implement the
methods.

The signatures here mirror exactly what the existing mock tool handlers
in `app/tools/{siem,edr,idp,email_tool}.py` already accept and return,
so swapping mocks for real connectors is a pure routing change with no
contract change at the LLM tool surface.
"""
from __future__ import annotations

from abc import abstractmethod
from typing import Any

from app.connectors.sdk.base import BaseConnector, ConnectorKind


class BaseSiemConnector(BaseConnector):
    """SIEM family (Splunk, Microsoft Sentinel, Elastic, Chronicle, …)."""

    kind: ConnectorKind = ConnectorKind.SIEM

    @abstractmethod
    async def search_events(
        self, *, entity: str, entity_type: str, minutes: int = 60
    ) -> dict[str, Any]:
        """Return events around `entity` (host/user/ip) within `minutes`.

        Return shape matches `app/tools/siem.py:siem_search_events` —
        `{entity, entity_type, window_minutes, events: [{ts, type, ...}]}`.
        """
        raise NotImplementedError

    @abstractmethod
    async def get_related_alerts(self, *, entity: str, hours: int = 24) -> dict[str, Any]:
        """Return other alerts touching `entity` within `hours`."""
        raise NotImplementedError


class BaseEdrConnector(BaseConnector):
    """EDR family (CrowdStrike Falcon, SentinelOne, Microsoft Defender, …)."""

    kind: ConnectorKind = ConnectorKind.EDR

    @abstractmethod
    async def get_process_tree(
        self, *, host: str, process_name: str | None = None
    ) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def isolate_host(self, *, host: str, reason: str) -> dict[str, Any]:
        """Network-isolate `host`. Reversible via `release_host`."""
        raise NotImplementedError

    @abstractmethod
    async def release_host(self, *, host: str) -> dict[str, Any]:
        """Reverse a prior `isolate_host`. Used by the t1-reverse-actions handler."""
        raise NotImplementedError

    @abstractmethod
    async def quarantine_file(self, *, sha256: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def kill_process(self, *, host: str, pid: int) -> dict[str, Any]:
        raise NotImplementedError

    # ── Reverse actions (t1-reverse-actions) ───────────────────────────
    # `restore_file` un-quarantines a hash fleet-wide. Concrete (not
    # abstract) so vendor connectors that pre-date rollback still load;
    # those connectors raise here and the rollback service records the
    # failure in the paired ToolCall audit row.
    # NOTE: `kill_process` is intentionally NOT paired with a reverse —
    # you cannot resurrect a process. The rollback service must refuse
    # to enqueue rollbacks for DESTRUCTIVE actions.
    async def restore_file(self, *, sha256: str) -> dict[str, Any]:
        """Reverse a prior `quarantine_file`. Override in concrete connectors."""
        raise NotImplementedError(
            f"{type(self).__name__}.restore_file is not implemented"
        )


class BaseIdpConnector(BaseConnector):
    """Identity provider family (Okta, Entra ID, Ping, JumpCloud, …)."""

    kind: ConnectorKind = ConnectorKind.IDP

    @abstractmethod
    async def get_user(self, *, user: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def revoke_sessions(self, *, user: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def disable_user(self, *, user: str, reason: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def reset_password(self, *, user: str) -> dict[str, Any]:
        raise NotImplementedError

    # ── Reverse actions (t1-reverse-actions) ───────────────────────────
    # Concrete (not abstract) so existing vendor connectors that predate
    # the rollback subsystem still load. They raise at call time, which
    # the rollback service surfaces as `success=False` with a clear
    # provider-not-implemented error in the audit trail.
    async def enable_user(self, *, user: str) -> dict[str, Any]:
        """Reverse a prior `disable_user`. Override in concrete connectors."""
        raise NotImplementedError(
            f"{type(self).__name__}.enable_user is not implemented"
        )

    # ── ITDR surface (t2c-itdr) ────────────────────────────────────────
    # These power the Identity Threat Detection & Response sub-agent:
    # session graph traversal, OAuth-grant discovery, AitM detection,
    # and *targeted* (per-session / per-grant) revocation rather than
    # the blunt fleet-wide ``revoke_sessions``.
    #
    # All are concrete (not abstract) so legacy connectors keep loading;
    # they raise ``NotImplementedError`` at call time, which surfaces
    # cleanly as a `success=False` audit row.
    async def list_user_sessions(self, *, user: str) -> dict[str, Any]:
        """List active sessions for ``user``.

        Return shape:
            ``{user, sessions: [{session_id, ts_created, last_seen,
            src_ip, country, asn, user_agent, mfa_method,
            anomaly_score, suspected_aitm}], count}``

        The ``suspected_aitm`` flag is connector-best-effort (e.g. Okta
        risk signals, Entra "atypical travel" + "unfamiliar sign-in"),
        not the final ITDR verdict — the sub-agent fuses these with
        cross-source signals before deciding.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_user_sessions is not implemented"
        )

    async def revoke_session(
        self, *, user: str, session_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Revoke a *single* session — the targeted-revoke primitive.

        ``reason`` is a short audit-trail string (e.g. "ITDR backstop:
        AitM-suspected session") that the connector should attach to the
        provider's audit log when supported.

        Forward-only (no inverse exists). Return shape:
        ``{user, session_id, revoked: bool, ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.revoke_session is not implemented"
        )

    async def list_oauth_grants(self, *, user: str) -> dict[str, Any]:
        """List OAuth/OIDC consent grants made by ``user``.

        Powers OAuth-application discovery and "illicit consent grant"
        detection (a top phishing-to-cloud pivot). Return shape:
        ``{user, grants: [{grant_id, client_id, app_name, scopes,
        granted_at, last_used, publisher_verified, risk_score}]}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_oauth_grants is not implemented"
        )

    async def revoke_oauth_grant(
        self, *, user: str, grant_id: str, reason: str | None = None
    ) -> dict[str, Any]:
        """Revoke a single OAuth consent grant.

        ``reason`` is a short audit-trail string the connector should
        attach to the provider's audit log when supported.

        Forward-only — the user (or admin) must explicitly re-consent
        to restore access. Return shape:
        ``{user, grant_id, revoked: bool, ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.revoke_oauth_grant is not implemented"
        )

    async def list_oauth_apps(self) -> dict[str, Any]:
        """List OAuth applications registered in the tenant.

        Surfaces high-risk apps (un-verified publisher, broad scopes,
        recently registered) for the sub-agent's app-discovery pass.
        Return shape:
        ``{apps: [{client_id, app_name, publisher, publisher_verified,
        scopes_requested, total_users_granted, first_seen}]}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_oauth_apps is not implemented"
        )


class BaseCloudConnector(BaseConnector):
    """Cloud control-plane family (AWS today; GCP, Azure on roadmap).

    Powers the Cloud Detection & Response (CDR) sub-agent — Theme 2d.
    The surface intentionally mirrors the *targeted-revoke* philosophy of
    :class:`BaseIdpConnector`:

      * Reads enumerate the IAM principal graph and active sessions.
      * Writes are *surgical* — deactivate a single access key, attach an
        explicit-deny policy to one principal, kill one Kubernetes
        RoleBinding — never "delete role" / "delete user". The CDR
        agent's whole point is to contain a compromised identity without
        taking down the rest of the account.

    All methods are concrete (not abstract) so connectors written before
    this sub-agent existed still load; they raise ``NotImplementedError``
    at call time and the tool layer surfaces that as ``success=False``.
    """

    kind: ConnectorKind = ConnectorKind.CLOUD

    # ── IAM principal graph (read) ────────────────────────────────────
    async def list_iam_principals(
        self, *, limit: int = 200
    ) -> dict[str, Any]:
        """Enumerate IAM users and roles in the account.

        Return shape:
            ``{principals: [{principal_id, principal_type: 'user'|'role',
            name, arn, created_at, last_used, mfa_enabled, tags,
            attached_policies: [..], risk_score}], count}``

        ``risk_score`` is connector-best-effort (e.g. unused-for-90d,
        wildcard policy attached, no MFA on console user) — the CDR
        agent fuses these with cross-source signals before deciding.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_iam_principals is not implemented"
        )

    async def get_iam_principal(
        self, *, principal: str
    ) -> dict[str, Any]:
        """Detailed view of a single principal (user or role).

        Return shape:
            ``{principal_id, principal_type, name, arn, attached_policies,
            inline_policies, access_keys: [{key_id, status, created_at,
            last_used}], assumed_by: [..principal_arns..], can_assume:
            [..role_arns..], tags}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.get_iam_principal is not implemented"
        )

    async def list_access_keys(
        self, *, user: str
    ) -> dict[str, Any]:
        """List access keys for an IAM user.

        Return shape:
            ``{user, keys: [{key_id, status: 'Active'|'Inactive',
            created_at, last_used, last_used_service, last_used_region,
            anomaly_score}]}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_access_keys is not implemented"
        )

    # ── STS / session graph (read) ────────────────────────────────────
    async def list_sts_sessions(
        self, *, principal: str | None = None, hours: int = 24
    ) -> dict[str, Any]:
        """Recent STS AssumeRole sessions, optionally filtered to one principal.

        Powers assume-role-chain abuse detection (A → assumes B → assumes
        C). Return shape:
            ``{sessions: [{session_id, started_at, source_principal,
            assumed_role, source_ip, country, asn, user_agent,
            mfa_used, chain_depth, anomaly_score}], count}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_sts_sessions is not implemented"
        )

    async def trace_assume_role_chain(
        self, *, session_id: str
    ) -> dict[str, Any]:
        """Walk an STS AssumeRole chain back to its origin principal.

        Return shape:
            ``{session_id, chain: [{principal_arn, action, ts}],
            origin_principal, depth, suspicious: bool, reasons: [..]}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.trace_assume_role_chain is not implemented"
        )

    # ── Kubernetes RBAC (read) ────────────────────────────────────────
    async def list_k8s_rolebindings(
        self, *, namespace: str | None = None
    ) -> dict[str, Any]:
        """List Kubernetes RoleBindings / ClusterRoleBindings.

        Surfaces over-privileged or anomalous bindings (e.g. ServiceAccount
        bound to cluster-admin, recently-created binding to a default SA).
        Return shape:
            ``{bindings: [{name, namespace, kind: 'RoleBinding'|
            'ClusterRoleBinding', role_ref, subjects: [..], created_at,
            risk_score, reasons: [..]}], count}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_k8s_rolebindings is not implemented"
        )

    # ── Targeted containment (write, no inverse) ─────────────────────
    # All three writes are WRITE_SIGNIFICANT, not WRITE_REVERSIBLE.
    # ``deactivate_access_key`` *technically* has an inverse (Activate),
    # but in a real compromise the analyst should rotate, not reactivate
    # — so we leave it forward-only at the tool layer and let HITL
    # decide on re-activation as a fresh approved action.
    async def deactivate_access_key(
        self,
        *,
        user: str,
        key_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Set an IAM access key to ``Inactive`` (does not delete it).

        Surgical containment — kill the leaked key without touching the
        user's console password, other keys, or attached roles. Return
        shape: ``{user, key_id, deactivated: bool, ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.deactivate_access_key is not implemented"
        )

    async def attach_deny_policy(
        self,
        *,
        principal: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Attach an explicit-Deny-* policy to a single principal.

        The canonical "freeze this identity" containment when we can't
        identify *which* credential is in the attacker's hand. Explicit
        deny beats every other allow — so this halts the principal
        without deleting it (preserves forensic state). Return shape:
            ``{principal, policy_arn, attached: bool, ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.attach_deny_policy is not implemented"
        )

    async def delete_k8s_rolebinding(
        self,
        *,
        name: str,
        namespace: str | None = None,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Delete a single suspicious RoleBinding / ClusterRoleBinding.

        Forward-only — operators must re-create from GitOps if needed.
        Return shape: ``{name, namespace, kind, deleted: bool, ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.delete_k8s_rolebinding is not implemented"
        )


class BaseSaaSConnector(BaseConnector):
    """SaaS Security Posture family (M365, Workspace, Salesforce, GitHub, Slack).

    Powers SaaS Security Posture Management (SSPM) — Theme 2e. One
    SaaS connector multiplexes across all SaaS providers in scope for
    the tenant (M365, Google Workspace, Salesforce, GitHub, Slack in
    v1) via a ``provider`` parameter on every call. This deliberately
    differs from the SIEM/EDR/IDP families where vendor is fixed at
    connector construction — SSPM is unavoidably multi-provider, and
    the agent needs a single tool surface to pivot across them.

    The shape mirrors the *targeted-remediation* philosophy of the IDP
    and CDR connectors:

      * Reads enumerate connected SaaS apps, public shares, third-party
        OAuth/integrations, and admin-config posture.
      * Writes are *surgical* — revoke one OAuth grant, remove one
        external collaborator from one resource, lock one public share
        — never "disable app" / "delete all external shares".

    All methods are concrete (not abstract) so connectors written before
    this sub-agent existed still load; they raise ``NotImplementedError``
    at call time and the tool layer surfaces that as ``success=False``.

    Provider strings (canonical, lowercase):
      ``m365``, ``workspace``, ``salesforce``, ``github``, ``slack``.
    Connectors should accept any of these and reject unknown providers
    with a clear ``ConnectorError``.
    """

    kind: ConnectorKind = ConnectorKind.SAAS

    # ── Application inventory (read) ──────────────────────────────────
    async def list_applications(
        self, *, provider: str | None = None
    ) -> dict[str, Any]:
        """Enumerate connected SaaS applications.

        With ``provider=None``, fans out across every provider configured
        for the tenant. With ``provider="m365"`` etc., returns only that
        provider's apps. Return shape:
            ``{applications: [{app_id, provider, name, vendor,
            installed_at, scopes, install_user_count, publisher_verified,
            risk_score, reasons: [..]}], count}``.

        ``risk_score`` is connector-best-effort (un-verified publisher,
        broad scopes, dormant app, recently-installed by non-admin) —
        the agent fuses these with cross-source signals.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_applications is not implemented"
        )

    # ── Misconfiguration / posture (read) ─────────────────────────────
    async def list_misconfigurations(
        self, *, provider: str | None = None
    ) -> dict[str, Any]:
        """Surface admin-config posture drift per provider.

        Examples: MFA-not-enforced for admins, legacy auth allowed,
        Workspace "less-secure apps" enabled, Salesforce IP-restriction
        off for sysadmin profile, GitHub branch-protection disabled on
        main, Slack "anyone can create app" enabled. Return shape:
            ``{findings: [{provider, control_id, control_name, severity:
            'low'|'medium'|'high'|'critical', current_value,
            recommended_value, evidence_url, last_checked,
            remediation_hint}], count}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_misconfigurations is not implemented"
        )

    # ── External sharing inventory (read) ─────────────────────────────
    async def list_external_shares(
        self, *, provider: str | None = None, limit: int = 200
    ) -> dict[str, Any]:
        """Enumerate externally-shared resources across providers.

        Powers "public Drive folder", "anonymous-link OneDrive doc",
        "public GitHub repo with secret", "Slack public channel with
        external guests" discovery. Return shape:
            ``{shares: [{share_id, provider, resource_type, resource_name,
            resource_url, shared_with: 'public'|'anyone-with-link'|
            'external-domain', external_principals: [..], created_at,
            last_accessed, contains_sensitive: bool, risk_score,
            reasons: [..]}], count}``.

        ``contains_sensitive`` is provider-best-effort (DLP signals,
        SaaS-side label matches) — the agent treats it as a hint, not a
        verdict.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_external_shares is not implemented"
        )

    # ── Third-party / OAuth integration inventory (read) ──────────────
    async def list_third_party_integrations(
        self, *, provider: str | None = None
    ) -> dict[str, Any]:
        """List third-party OAuth integrations / installed apps.

        SSPM's most important signal — broad-scoped grants from
        un-verified publishers are the #1 SaaS attack path. Return shape:
            ``{integrations: [{grant_id, provider, app_id, app_name,
            publisher, publisher_verified, scopes, granted_by_user,
            granted_at, last_used, total_users_granted, risk_score,
            reasons: [..]}], count}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.list_third_party_integrations "
            "is not implemented"
        )

    # ── Targeted remediations (write, forward-only) ───────────────────
    # All writes are WRITE_SIGNIFICANT. Re-grant / re-share is a fresh
    # forward decision (a new HITL-approved action), not an undo, so the
    # rollback service deliberately won't auto-reverse these.
    async def revoke_third_party_integration(
        self,
        *,
        provider: str,
        grant_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Revoke a single third-party OAuth grant on one provider.

        Forward-only — re-consent requires a fresh approved action.
        Return shape:
            ``{provider, grant_id, revoked: bool, ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.revoke_third_party_integration "
            "is not implemented"
        )

    async def restrict_external_share(
        self,
        *,
        provider: str,
        share_id: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Restrict a single external share (kill the link / lock to internal).

        Surgical — does not delete the resource, just tightens the
        share-scope to org-internal. Return shape:
            ``{provider, share_id, restricted: bool, new_scope,
            ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.restrict_external_share is not implemented"
        )

    async def remove_external_collaborator(
        self,
        *,
        provider: str,
        resource_id: str,
        external_principal: str,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Remove one external principal from one resource.

        Lower-blast-radius alternative to ``restrict_external_share`` —
        used when the share itself is fine but a specific external
        identity needs to be ejected (e.g. an ex-vendor email still on a
        live Drive folder). Return shape:
            ``{provider, resource_id, external_principal, removed: bool,
            ticket}``.
        """
        raise NotImplementedError(
            f"{type(self).__name__}.remove_external_collaborator "
            "is not implemented"
        )


class BaseEmailConnector(BaseConnector):
    """Email security family (Proofpoint, Microsoft 365, Mimecast, …)."""

    kind: ConnectorKind = ConnectorKind.EMAIL

    @abstractmethod
    async def analyze_message(self, *, message_id: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def clawback_message(self, *, message_id: str) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    async def block_sender(self, *, sender: str) -> dict[str, Any]:
        raise NotImplementedError

    # ── Reverse actions (t1-reverse-actions) ───────────────────────────
    # `restore_message` is best-effort: most providers only restore from
    # quarantine, not from purged-recipient-mailbox. The reverse handler
    # records whatever the provider returns and lets HITL judge whether
    # that's good enough. `unblock_sender` is straightforward.
    async def restore_message(self, *, message_id: str) -> dict[str, Any]:
        """Reverse a prior `clawback_message`. Override in concrete connectors."""
        raise NotImplementedError(
            f"{type(self).__name__}.restore_message is not implemented"
        )

    async def unblock_sender(self, *, sender: str) -> dict[str, Any]:
        """Reverse a prior `block_sender`. Override in concrete connectors."""
        raise NotImplementedError(
            f"{type(self).__name__}.unblock_sender is not implemented"
        )


class BaseForensicsConnector(BaseConnector):
    """Live endpoint forensics family (Velociraptor, KAPE, GRR, Wazuh FIM).

    Powers the Live Endpoint Forensics sub-agent — Theme 2j. Distinct
    from :class:`BaseEdrConnector` in two important ways:

      * **Pull, not push.** EDR ships always-on telemetry and offers
        containment. Forensics is *on-demand*: you ask the endpoint for
        a process listing, an autoruns dump, a registry hive, an MFT
        slice — and it runs that collection *now*, often taking
        seconds-to-minutes.
      * **Deep, not shallow.** EDR sees what its sensor sees. Forensics
        artifacts (Velociraptor VQL, KAPE targets, GRR flows) read
        directly from the live OS — registry, NTFS journal, prefetch,
        in-memory process maps — answering the post-containment "what
        actually happened on this box" question.

    Operations:

      * ``collect_artifact`` — run a single named artifact on one host.
      * ``run_hunt`` — fan an artifact out to many endpoints at once,
        bounded by a label or asset-group selector.
      * ``fetch_file`` — pull a specific file off the endpoint for
        offline analysis (chain-of-custody hash returned).
      * ``terminate_process`` — kill a single PID. Overlaps with
        ``BaseEdrConnector.kill_process`` deliberately: when EDR isn't
        deployed but Velociraptor is, the forensics path becomes the
        containment path of last resort.

    Reads (``collect_artifact``, ``run_hunt``, ``fetch_file``) are
    ``READ`` risk-class — they don't mutate the endpoint and only
    return data. ``terminate_process`` is ``DESTRUCTIVE`` (you cannot
    resurrect a process) and is never paired with a reverse action.

    All methods are abstract — there is no legacy forensics connector
    to keep loading, so concrete vendors must implement the full
    surface.
    """

    kind: ConnectorKind = ConnectorKind.FORENSICS

    @abstractmethod
    async def collect_artifact(
        self,
        *,
        host: str,
        artifact: str,
        parameters: dict[str, Any] | None = None,
        timeout_s: int = 300,
    ) -> dict[str, Any]:
        """Run one named artifact against one host and return results.

        ``artifact`` is a vendor-namespaced identifier (e.g. Velociraptor's
        ``Windows.System.Pslist`` or ``Linux.Sys.BashShell``). Connectors
        should treat unknown artifacts as a clean ``ConnectorError``,
        not a 500.

        Return shape:
            ``{host, artifact, flow_id, started_at, completed_at,
            status: 'completed'|'failed'|'timeout', rows: [..],
            row_count, total_uploaded_bytes, error}``.
        """
        raise NotImplementedError

    @abstractmethod
    async def run_hunt(
        self,
        *,
        artifact: str,
        label_selector: str | None = None,
        host_ids: list[str] | None = None,
        parameters: dict[str, Any] | None = None,
        timeout_s: int = 600,
    ) -> dict[str, Any]:
        """Fan an artifact out to many endpoints concurrently.

        Exactly one of ``label_selector`` / ``host_ids`` must be set —
        Velociraptor uses VQL label expressions (``label =~ 'prod'``),
        KAPE uses hostname globs, GRR uses fleetspeak labels. Connectors
        normalise to a label string at the wire level.

        Return shape:
            ``{hunt_id, artifact, started_at, scheduled_clients,
            completed_clients, error_clients, status: 'running'|
            'completed'|'cancelled', results_summary: {row_count,
            unique_hosts}}``.

        Long-running by design — connectors should return as soon as
        the hunt is *scheduled* and let the agent poll via a follow-up
        ``collect_artifact``-on-server-side or vendor-specific status
        tool. v1 mock blocks until completion for determinism.
        """
        raise NotImplementedError

    @abstractmethod
    async def fetch_file(
        self,
        *,
        host: str,
        path: str,
        max_size_mb: int = 100,
    ) -> dict[str, Any]:
        """Pull a file off the endpoint for offline analysis.

        Chain-of-custody matters here — connectors must return the
        SHA-256 of the bytes uploaded *as the endpoint saw them*, plus a
        download URL or vault reference the agent can hand to a malware
        sandbox.

        Return shape:
            ``{host, path, size_bytes, sha256, vault_url, fetched_at,
            truncated: bool}``.

        ``truncated`` is ``True`` when the file exceeded ``max_size_mb``
        and only a prefix was uploaded — Velociraptor honors this via
        ``UploadFile`` parameters.
        """
        raise NotImplementedError

    @abstractmethod
    async def terminate_process(
        self,
        *,
        host: str,
        pid: int,
        reason: str | None = None,
    ) -> dict[str, Any]:
        """Kill a single PID on the endpoint.

        Forensics-path containment of last resort — used when EDR isn't
        deployed but Velociraptor is, or when EDR refuses to kill the
        PID for product-side policy reasons. ``DESTRUCTIVE`` risk class
        at the tool layer: no inverse exists.

        Return shape:
            ``{host, pid, terminated: bool, ticket, error}``.
        """
        raise NotImplementedError


__all__ = [
    "BaseSiemConnector",
    "BaseEdrConnector",
    "BaseIdpConnector",
    "BaseCloudConnector",
    "BaseSaaSConnector",
    "BaseEmailConnector",
    "BaseForensicsConnector",
]
