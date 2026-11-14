"""
Detection Pack — Threat-and-anomaly conditions
==============================================

Depth plan 3.5: *"Pair anomaly signals with threat conditions into rules,
for example a first-seen country with an MFA factor reset, or a rare client
family with access-key creation. They are ordinary rules that read baseline
fields, so they carry the same replay proof."*

What makes this family different, and why it is counted separately
------------------------------------------------------------------
Every other native rule answers "did this happen". These answer "did this
happen, **and is it unusual for this principal**". The second half comes
from the depth plan 3.4 baseline store
(`services/fusion/app/services/baselines.py`), which puts `baseline_*`
scores into the match namespace alongside the connector's own fields.

That pairing is the point. On its own, `CreateAccessKey` is a thing
platform engineers do several times a week, and alerting on it produces a
queue nobody reads. On its own, "this principal is using an unusual client"
is a curiosity. Together they describe a specific thing worth waking
someone for: *the credential-minting call arrived over a path this account
has never used*.

Counted as its own family in `scripts/project_stats.py` because the claim
is different. "2,511 executable detections" says a rule can fire on a
well-formed event; a threat-and-anomaly rule additionally needs a warmed
baseline for the principal, so a fresh install has the rule and not yet the
signal. Folding these into the headline would overstate what a day-one
deployment detects.

Fixtures are hand-authored, and the negative is the benign twin
---------------------------------------------------------------
The `S()` auto-fixture path is deliberately **not** used here. It
synthesises the positive from the rule's own clause, which makes replay
tautological, and it builds the negative by flipping one field to a
sentinel — 423 of the existing negatives invert by prefixing `not-` to the
expected value, so the rule passes its negative by failing to match a value
no log source would ever emit. That measures nothing about false positives.

Every fixture below is written by hand, and every negative is the **benign
twin of its positive**: the same threat action, by a principal for whom it
is routine. The pair differs only in the baseline score, which is exactly
the clause these rules are about. A rule that fired on both would be a rule
that is not really reading the baseline.

Thresholds
----------
`0.95` rarity means the principal has done this on under 5% of their
observed activity, over a history of at least `MIN_OBSERVATIONS` events.
`3.0` on a volume or peer z-score is three standard deviations from that
principal's — or that group's — own normal. Both are deliberately strict:
this family exists to be the half of a pair that makes a noisy threat
condition worth alerting on, and a loose anomaly threshold would hand the
noise straight back.
"""

from __future__ import annotations

from typing import Any

#: Rarity at or above which a value counts as unusual for the principal.
RARE = 0.95

#: Standard deviations at or above which a volume or peer figure counts as
#: a deviation.
DEVIATION = 3.0


def TA(
    *,
    slug: str,
    name: str,
    severity: str,
    mitre: list[str],
    product: str,
    service: str,
    when: dict[str, Any],
    positive: dict[str, Any],
    negative: dict[str, Any],
    fp: list[str],
    playbook: str = "tpl-triage",
    description: str | None = None,
) -> dict[str, Any]:
    """A threat-and-anomaly spec. Fixtures are required, never synthesised.

    `S()` in `detection_specs_part3_helpers` defaults both fixtures from the
    clause. That is the right trade for a flat vendor-field rule and the
    wrong one here: the whole content of these rules is the relationship
    between a threat condition and a baseline score, and a fixture derived
    from the clause cannot test a relationship it was copied from.
    """
    if not positive or not negative:
        raise ValueError(f"{slug}: both fixtures must be hand-authored")
    return {
        "slug": slug,
        "name": name,
        "severity": severity,
        "mitre": [t.lower() for t in mitre],
        "log_source": {"product": product, "service": service},
        "fields": sorted(_fields_of(when)),
        "match_when": when,
        "fp": list(fp),
        "playbook": playbook,
        "positive": dict(positive),
        "negative": dict(negative),
        **({"description": description} if description else {}),
    }


def _fields_of(clause: Any) -> set[str]:
    """Field names a clause reads, with the operator suffix stripped."""
    from detection_specs_part3_helpers import split_op  # type: ignore[import-not-found]  # noqa: PLC0415

    out: set[str] = set()
    if isinstance(clause, dict):
        for key, value in clause.items():
            if key in {"any_of", "all_of", "not"}:
                out |= _fields_of(value)
                continue
            out.add(split_op(key)[0])
    elif isinstance(clause, list):
        for item in clause:
            out |= _fields_of(item)
    return out


THREAT_ANOMALY: list[dict] = [
    # ---------------------------------------------------------------
    # AWS — credential and policy actions over an unusual path (6)
    # ---------------------------------------------------------------
    TA(
        slug="ta-aws-access-key-created-from-rare-client",
        name="AWS Access Key Created From a Client This Principal Has Never Used",
        severity="high",
        mitre=["t1098.001", "t1078.004"],
        product="aws",
        service="iam",
        when={"eventName": "CreateAccessKey", "baseline_client_family_rarity_gte": RARE},
        positive={
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "user": "dana.k@example.com",
            "user_agent": "python-requests/2.31.0",
            "src_ip": "203.0.113.44",
            "baseline_client_family_rarity": 0.985,
        },
        # The platform engineer who mints keys from the CLI every week. Same
        # call, same service, routine client — the pairing must not fire.
        negative={
            "eventName": "CreateAccessKey",
            "eventSource": "iam.amazonaws.com",
            "user": "dana.k@example.com",
            "user_agent": "aws-cli/2.15.17 Python/3.11.6 Darwin/23.4.0",
            "src_ip": "198.51.100.17",
            "baseline_client_family_rarity": 0.04,
        },
        fp=[
            "A new build agent or CI runner adopting a different SDK will look novel once",
            "An engineer moving from the console to the CLI for the first time",
        ],
        playbook="tpl-credential-compromise",
    ),
    TA(
        slug="ta-aws-policy-attached-by-rare-actor-action",
        name="AWS Policy Attached by a Principal Who Does Not Normally Attach Policies",
        severity="high",
        mitre=["t1098.003"],
        product="aws",
        service="iam",
        when={
            "eventName_in": ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"],
            "baseline_action_rarity_gte": RARE,
        },
        positive={
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "user": "svc-reporting@example.com",
            "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess",
            "baseline_action_rarity": 0.998,
        },
        # The identity team's own automation, which attaches policies all day.
        negative={
            "eventName": "AttachUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "user": "svc-iam-provisioner@example.com",
            "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
            "baseline_action_rarity": 0.012,
        },
        fp=["Account vending and IAM bootstrap runs", "A new provisioning service account's first week"],
        playbook="tpl-privilege-escalation",
    ),
    TA(
        slug="ta-aws-api-call-from-rare-country",
        name="AWS Control-Plane Call From a Country This Principal Has Never Used",
        severity="medium",
        mitre=["t1078.004"],
        product="aws",
        service="cloudtrail",
        when={"eventSource": "iam.amazonaws.com", "baseline_location_rarity_gte": RARE},
        positive={
            "eventName": "ListAccessKeys",
            "eventSource": "iam.amazonaws.com",
            "user": "dana.k@example.com",
            "country": "KZ",
            "baseline_location_rarity": 0.996,
        },
        negative={
            "eventName": "ListAccessKeys",
            "eventSource": "iam.amazonaws.com",
            "user": "dana.k@example.com",
            "country": "US",
            "baseline_location_rarity": 0.01,
        },
        fp=["Travel", "A VPN egress or cloud NAT in another region", "A relocated contractor"],
    ),
    TA(
        slug="ta-aws-volume-spike-on-s3-reads",
        name="AWS S3 Read Volume Far Above This Principal's Normal",
        severity="high",
        mitre=["t1530"],
        product="aws",
        service="s3",
        when={"eventSource": "s3.amazonaws.com", "baseline_principal_volume_z_gte": DEVIATION},
        positive={
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "user": "mara.l@example.com",
            "resource": "arn:aws:s3:::finance-exports",
            "baseline_principal_volume_z": 9.4,
        },
        # The nightly ETL account, whose volume is high and entirely normal
        # *for it* — which is the distinction a per-principal baseline draws
        # and a global threshold cannot.
        negative={
            "eventName": "GetObject",
            "eventSource": "s3.amazonaws.com",
            "user": "svc-etl-nightly@example.com",
            "resource": "arn:aws:s3:::finance-exports",
            "baseline_principal_volume_z": 0.3,
        },
        fp=["A genuine bulk export or migration", "A first full backup after onboarding"],
        playbook="tpl-data-exfiltration",
    ),
    TA(
        slug="ta-aws-rare-resource-touched-by-principal",
        name="AWS Resource This Principal Has Never Touched",
        severity="medium",
        mitre=["t1580"],
        product="aws",
        service="cloudtrail",
        when={
            "eventName_startswith_any": ["Delete", "Put", "Modify"],
            "baseline_resource_rarity_gte": RARE,
        },
        positive={
            "eventName": "DeleteBucketPolicy",
            "eventSource": "s3.amazonaws.com",
            "user": "mara.l@example.com",
            "resource": "arn:aws:s3:::prod-audit-logs",
            "baseline_resource_rarity": 0.991,
        },
        negative={
            "eventName": "PutObject",
            "eventSource": "s3.amazonaws.com",
            "user": "mara.l@example.com",
            "resource": "arn:aws:s3:::mara-scratch",
            "baseline_resource_rarity": 0.07,
        },
        fp=["A project handover", "An engineer joining a new service team"],
    ),
    TA(
        slug="ta-aws-peer-deviation-on-privileged-call",
        name="AWS Privileged Call Volume Far Above This Principal's Peer Group",
        severity="medium",
        mitre=["t1078.004"],
        product="aws",
        service="iam",
        when={"eventSource": "iam.amazonaws.com", "baseline_peer_deviation_gte": DEVIATION},
        positive={
            "eventName": "CreateUser",
            "eventSource": "iam.amazonaws.com",
            "user": "rob.t@example.com",
            "group": "platform-engineering",
            "baseline_peer_deviation": 6.8,
        },
        negative={
            "eventName": "CreateUser",
            "eventSource": "iam.amazonaws.com",
            "user": "rob.t@example.com",
            "group": "platform-engineering",
            "baseline_peer_deviation": 0.6,
        },
        fp=["A team of one, where the peer group is the principal", "An on-call week"],
    ),
    # ---------------------------------------------------------------
    # Identity — Okta and Entra (7)
    # ---------------------------------------------------------------
    TA(
        slug="ta-okta-mfa-reset-from-rare-country",
        name="MFA Factor Reset From a Country This Principal Has Never Used",
        severity="critical",
        mitre=["t1556.006", "t1098.005"],
        product="okta",
        service="identity",
        # The plan's own first example. An MFA reset is the single most
        # useful thing an account-takeover does, and help desks do it daily
        # — so the location half is what separates the two.
        when={
            "event_type_in": ["user.mfa.factor.reset_all", "user.mfa.factor.deactivate"],
            "baseline_location_rarity_gte": RARE,
        },
        positive={
            "event_type": "user.mfa.factor.reset_all",
            "user": "priya.n@example.com",
            "target_user": "priya.n@example.com",
            "country": "NG",
            "outcome": "SUCCESS",
            "baseline_location_rarity": 0.997,
        },
        # The service desk in the office that resets factors every morning.
        negative={
            "event_type": "user.mfa.factor.reset_all",
            "user": "servicedesk@example.com",
            "target_user": "priya.n@example.com",
            "country": "GB",
            "outcome": "SUCCESS",
            "baseline_location_rarity": 0.02,
        },
        fp=["A user travelling and locked out", "A help desk operating from a second region"],
        playbook="tpl-account-takeover",
    ),
    TA(
        slug="ta-okta-admin-role-granted-rare-action",
        name="Admin Role Granted by a Principal Who Does Not Normally Grant Roles",
        severity="critical",
        mitre=["t1098.003"],
        product="okta",
        service="identity",
        when={
            "event_type_in": ["user.account.privilege.grant", "group.privilege.grant"],
            "baseline_action_rarity_gte": RARE,
        },
        positive={
            "event_type": "user.account.privilege.grant",
            "user": "ken.o@example.com",
            "target_user": "contractor-7@example.com",
            "role": "SUPER_ADMIN",
            "outcome": "SUCCESS",
            "baseline_action_rarity": 0.999,
        },
        negative={
            "event_type": "user.account.privilege.grant",
            "user": "iam-admin@example.com",
            "target_user": "newhire-22@example.com",
            "role": "READ_ONLY_ADMIN",
            "outcome": "SUCCESS",
            "baseline_action_rarity": 0.03,
        },
        fp=["A delegated admin covering for the usual owner", "Quarterly access review remediation"],
        playbook="tpl-privilege-escalation",
    ),
    TA(
        slug="ta-okta-login-from-rare-client-family",
        name="Sign-In From a Client Family This Principal Has Never Used",
        severity="medium",
        mitre=["t1078.004", "t1550"],
        product="okta",
        service="identity",
        when={"event_type": "user.session.start", "baseline_client_family_rarity_gte": RARE},
        positive={
            "event_type": "user.session.start",
            "user": "priya.n@example.com",
            "user_agent": "okta-sdk-golang/2.18.0",
            "outcome": "SUCCESS",
            "baseline_client_family_rarity": 0.993,
        },
        negative={
            "event_type": "user.session.start",
            "user": "priya.n@example.com",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Chrome/124.0",
            "outcome": "SUCCESS",
            "baseline_client_family_rarity": 0.05,
        },
        fp=["A new laptop or phone", "A browser major-version bump", "A newly adopted SDK"],
    ),
    TA(
        slug="ta-okta-rare-action-on-identity-provider",
        name="Identity-Provider Change by a Principal Who Does Not Normally Make Them",
        severity="critical",
        mitre=["t1556.007"],
        product="okta",
        service="identity",
        when={
            "event_type_startswith": "system.idp",
            "baseline_action_rarity_gte": RARE,
        },
        positive={
            "event_type": "system.idp.lifecycle.create",
            "user": "ken.o@example.com",
            "outcome": "SUCCESS",
            "baseline_action_rarity": 0.999,
        },
        negative={
            "event_type": "system.idp.lifecycle.update",
            "user": "sso-platform-admin@example.com",
            "outcome": "SUCCESS",
            "baseline_action_rarity": 0.08,
        },
        fp=["A federation migration", "An identity team member's first IdP change"],
        playbook="tpl-account-takeover",
    ),
    TA(
        slug="ta-entra-conditional-access-change-rare-action",
        name="Conditional Access Policy Changed by a Rare Actor",
        severity="critical",
        mitre=["t1556.009", "t1484.002"],
        product="azure",
        service="entra",
        when={
            "operation_contains": "conditional access policy",
            "baseline_action_rarity_gte": RARE,
        },
        positive={
            "operation": "Update conditional access policy",
            "user": "helpdesk-tier1@example.com",
            "result": "success",
            "baseline_action_rarity": 0.997,
        },
        negative={
            "operation": "Update conditional access policy",
            "user": "secops-ca-owner@example.com",
            "result": "success",
            "baseline_action_rarity": 0.02,
        },
        fp=["A planned policy rollout", "A delegated owner during a change freeze exception"],
        playbook="tpl-privilege-escalation",
    ),
    TA(
        slug="ta-entra-signin-volume-spike",
        name="Entra Sign-In Volume Far Above This Principal's Normal",
        severity="high",
        mitre=["t1110.003"],
        product="azure",
        service="entra",
        when={"event_type": "signin", "baseline_principal_volume_z_gte": DEVIATION},
        positive={
            "event_type": "signin",
            "user": "priya.n@example.com",
            "result": "failure",
            "baseline_principal_volume_z": 12.1,
        },
        negative={
            "event_type": "signin",
            "user": "priya.n@example.com",
            "result": "success",
            "baseline_principal_volume_z": 0.8,
        },
        fp=["A misconfigured client retrying", "A device re-enrolment loop"],
    ),
    TA(
        slug="ta-identity-peer-deviation-on-group-change",
        name="Group Membership Changes Far Above the Principal's Peer Group",
        severity="medium",
        mitre=["t1098"],
        product="identity",
        service="directory",
        when={
            "event_type_contains": "group.user_membership",
            "baseline_peer_deviation_gte": DEVIATION,
        },
        positive={
            "event_type": "group.user_membership.add",
            "user": "ken.o@example.com",
            "group": "finance",
            "outcome": "SUCCESS",
            "baseline_peer_deviation": 7.2,
        },
        negative={
            "event_type": "group.user_membership.add",
            "user": "ken.o@example.com",
            "group": "finance",
            "outcome": "SUCCESS",
            "baseline_peer_deviation": 0.4,
        },
        fp=["A reorganisation", "Bulk onboarding at the start of a quarter"],
    ),
    # ---------------------------------------------------------------
    # SaaS — Workspace, M365, Slack, Salesforce (6)
    # ---------------------------------------------------------------
    TA(
        slug="ta-saas-oauth-app-volume-spike",
        name="OAuth Application Activity Far Above Its Own Normal",
        severity="high",
        mitre=["t1550.001", "t1530"],
        product="google-workspace",
        service="oauth",
        # Keyed on the application rather than the user: a rogue grant acts
        # *as* a user, so the user's own volume stays unremarkable while the
        # application's does not.
        #
        # The `event_type` clause is not decoration. The first draft of this
        # rule carried the volume clause alone, which makes it a bare
        # anomaly — and the plan is explicit that an anomaly is a typed
        # signal and not an alert on its own. The family's own replay gate
        # caught it.
        when={"event_type": "oauth_token_event", "baseline_oauth_app_volume_z_gte": DEVIATION},
        positive={
            "event_type": "oauth_token_event",
            "user": "mara.l@example.com",
            "application": "Third-Party Backup Helper",
            "baseline_oauth_app_volume_z": 11.7,
        },
        negative={
            "event_type": "oauth_token_event",
            "user": "mara.l@example.com",
            "application": "Google Drive for Desktop",
            "baseline_oauth_app_volume_z": 0.5,
        },
        fp=["A legitimate integration's first sync", "A vendor rolling out a new feature"],
        playbook="tpl-data-exfiltration",
    ),
    TA(
        slug="ta-workspace-rare-admin-action",
        name="Workspace Admin Action This Principal Has Never Performed",
        severity="high",
        mitre=["t1098"],
        product="google-workspace",
        service="admin",
        when={"event_type": "admin", "baseline_action_rarity_gte": RARE},
        positive={
            "event_type": "admin",
            "event_name": "CREATE_DATA_TRANSFER_REQUEST",
            "user": "ken.o@example.com",
            "baseline_action_rarity": 0.998,
        },
        negative={
            "event_type": "admin",
            "event_name": "CHANGE_USER_ORGANIZATION_UNIT",
            "user": "workspace-admin@example.com",
            "baseline_action_rarity": 0.06,
        },
        fp=["A new administrator's first month", "A delegated admin covering leave"],
    ),
    TA(
        slug="ta-workspace-drive-download-volume-spike",
        name="Drive Download Volume Far Above This Principal's Normal",
        severity="high",
        mitre=["t1530"],
        product="google-workspace",
        service="drive",
        when={"event_type": "drive", "baseline_principal_volume_z_gte": DEVIATION},
        positive={
            "event_type": "drive",
            "event_name": "download",
            "user": "mara.l@example.com",
            "resource": "Q4-Pipeline-Export.xlsx",
            "baseline_principal_volume_z": 8.9,
        },
        negative={
            "event_type": "drive",
            "event_name": "download",
            "user": "mara.l@example.com",
            "resource": "Team-Offsite-Agenda.docx",
            "baseline_principal_volume_z": 0.7,
        },
        fp=["A departing employee's sanctioned export", "An offline-sync client's first pass"],
        playbook="tpl-data-exfiltration",
    ),
    TA(
        slug="ta-m365-mailbox-rule-from-rare-client",
        name="Mailbox Rule Created From a Client This Principal Has Never Used",
        severity="high",
        mitre=["t1114.003", "t1564.008"],
        product="m365",
        service="exchange",
        when={
            "operation_in": ["New-InboxRule", "Set-InboxRule"],
            "baseline_client_family_rarity_gte": RARE,
        },
        positive={
            "operation": "New-InboxRule",
            "user": "priya.n@example.com",
            "user_agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0; Pro)",
            "clientAppUsed": "Exchange Web Services",
            "result": "success",
            "baseline_client_family_rarity": 0.994,
        },
        negative={
            "operation": "New-InboxRule",
            "user": "priya.n@example.com",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/124.0",
            "clientAppUsed": "Browser",
            "result": "success",
            "baseline_client_family_rarity": 0.03,
        },
        fp=["A newly installed desktop client", "A mobile mail app added to an account"],
        playbook="tpl-account-takeover",
    ),
    TA(
        slug="ta-slack-rare-admin-action",
        name="Slack Workspace Admin Action This Principal Has Never Performed",
        severity="medium",
        mitre=["t1098"],
        product="slack",
        service="audit",
        when={
            "action_startswith_any": ["workspace_", "organization_", "app_"],
            "baseline_action_rarity_gte": RARE,
        },
        positive={
            "action": "organization_public_channel_export_enabled",
            "user": "ken.o@example.com",
            "baseline_action_rarity": 0.999,
        },
        negative={
            "action": "workspace_member_joined",
            "user": "ken.o@example.com",
            "baseline_action_rarity": 0.02,
        },
        fp=["A workspace migration", "A new workspace owner's first changes"],
    ),
    TA(
        slug="ta-salesforce-report-export-volume-spike",
        name="Salesforce Export Volume Far Above This Principal's Normal",
        severity="high",
        mitre=["t1530"],
        product="salesforce",
        service="audit",
        when={
            "event_type_in": ["ReportExport", "BulkApi"],
            "baseline_principal_volume_z_gte": DEVIATION,
        },
        positive={
            "event_type": "ReportExport",
            "user": "sales-ops-intern@example.com",
            "resource": "All Accounts and Contacts",
            "baseline_principal_volume_z": 10.2,
        },
        negative={
            "event_type": "ReportExport",
            "user": "svc-datawarehouse@example.com",
            "resource": "Nightly Pipeline Snapshot",
            "baseline_principal_volume_z": 0.2,
        },
        fp=["Quarter-end reporting", "A sanctioned CRM migration"],
        playbook="tpl-data-exfiltration",
    ),
    # ---------------------------------------------------------------
    # Code — GitHub and GitLab (3)
    # ---------------------------------------------------------------
    TA(
        slug="ta-github-rare-action-on-org-settings",
        name="GitHub Organisation Setting Changed by a Rare Actor",
        severity="high",
        mitre=["t1098", "t1195.001"],
        product="github",
        service="audit",
        when={"action_startswith": "org.", "baseline_action_rarity_gte": RARE},
        positive={
            "action": "org.update_default_repository_permission",
            "user": "contractor-7",
            "baseline_action_rarity": 0.998,
        },
        negative={
            "action": "org.add_member",
            "user": "platform-owner",
            "baseline_action_rarity": 0.04,
        },
        fp=["A new organisation owner", "A one-off policy change during onboarding"],
    ),
    TA(
        slug="ta-github-clone-volume-spike",
        name="Repository Clone Volume Far Above This Principal's Normal",
        severity="high",
        mitre=["t1213.003"],
        product="github",
        service="audit",
        when={
            "action_in": ["git.clone", "repo.download_zip"],
            "baseline_principal_volume_z_gte": DEVIATION,
        },
        positive={
            "action": "git.clone",
            "user": "contractor-7",
            "resource": "example-org/payments-core",
            "baseline_principal_volume_z": 14.3,
        },
        negative={
            "action": "git.clone",
            "user": "ci-runner-bot",
            "resource": "example-org/payments-core",
            "baseline_principal_volume_z": 0.1,
        },
        fp=["A fresh developer workstation setup", "A CI fleet scaling up"],
        playbook="tpl-data-exfiltration",
    ),
    TA(
        slug="ta-gitlab-token-action-from-rare-country",
        name="GitLab Token Action From a Country This Principal Has Never Used",
        severity="high",
        mitre=["t1098.001"],
        product="gitlab",
        service="audit",
        when={
            "event_type_contains": "token",
            "baseline_location_rarity_gte": RARE,
        },
        positive={
            "event_type": "personal_access_token_created",
            "user": "rob.t",
            "country": "VN",
            "baseline_location_rarity": 0.998,
        },
        negative={
            "event_type": "personal_access_token_created",
            "user": "rob.t",
            "country": "DE",
            "baseline_location_rarity": 0.02,
        },
        fp=["Travel", "A relocated contributor", "A VPN egress"],
    ),
    # ---------------------------------------------------------------
    # Kubernetes (2)
    # ---------------------------------------------------------------
    TA(
        slug="ta-k8s-rare-verb-by-service-account",
        name="Kubernetes Verb This Service Account Has Never Used",
        severity="high",
        mitre=["t1609", "t1078.003"],
        product="kubernetes",
        service="audit",
        when={
            "action_in": ["create", "delete", "patch"],
            "resource_contains": "clusterrolebinding",
            "baseline_action_rarity_gte": RARE,
        },
        positive={
            "action": "create",
            "resource": "rbac.authorization.k8s.io/clusterrolebindings",
            "user": "system:serviceaccount:default:metrics-reader",
            "baseline_action_rarity": 0.999,
        },
        negative={
            "action": "create",
            "resource": "rbac.authorization.k8s.io/clusterrolebindings",
            "user": "system:serviceaccount:kube-system:cluster-provisioner",
            "baseline_action_rarity": 0.05,
        },
        fp=["A cluster bootstrap", "An operator installing its own RBAC on first run"],
        playbook="tpl-privilege-escalation",
    ),
    TA(
        slug="ta-k8s-exec-volume-spike",
        name="Pod Exec Volume Far Above This Principal's Normal",
        severity="medium",
        mitre=["t1609"],
        product="kubernetes",
        service="audit",
        when={
            "resource_contains": "pods/exec",
            "baseline_principal_volume_z_gte": DEVIATION,
        },
        positive={
            "action": "create",
            "resource": "pods/exec",
            "user": "contractor-7@example.com",
            "baseline_principal_volume_z": 7.6,
        },
        negative={
            "action": "create",
            "resource": "pods/exec",
            "user": "sre-oncall@example.com",
            "baseline_principal_volume_z": 0.9,
        },
        fp=["An incident response shift", "A debugging session on a failing deployment"],
    ),
]
