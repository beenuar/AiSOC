"""
Detection Pack v1 - Part 3 / Application (40 new specs)
=======================================================

Native application-layer detection rules covering web-app attacks, SaaS
collaboration tools, DevOps/CI pipelines and API misuse. These extend the
application rules in ``detection_specs.APPLICATION`` (~25 stable rules).
"""

from __future__ import annotations

from detection_specs_part3_helpers import (  # type: ignore[import-not-found]
    FP_PENTEST,
    FP_TUNING,
    S,
)


# ---------------------------------------------------------------------------
# Web-app attacks (15)
# ---------------------------------------------------------------------------
WEB_APP_RULES: list[dict] = [
    S(slug="app-ssti-pattern", name="Server-Side Template Injection Pattern In Request",
      severity="high", mitre=["t1190"], product="waf", service="http",
      when={"event_type": "http_request", "body_contains_any": ["{{7*7}}", "${7*7}", "{%7*7%}", "<%= 7*7 %>"]},
      fp=[FP_PENTEST], playbook="tpl-initial-access"),
    S(slug="app-xxe-pattern", name="XML External Entity Reference In Request Body",
      severity="high", mitre=["t1190"], product="waf", service="http",
      when={"event_type": "http_request", "body_contains_any": ["<!ENTITY", "SYSTEM \"file://", "SYSTEM \"http://"]},
      fp=["Approved XML SOAP integration"], playbook="tpl-initial-access"),
    S(slug="app-nosql-injection", name="NoSQL Injection Operator In Request",
      severity="high", mitre=["t1190"], product="waf", service="http",
      when={"event_type": "http_request", "body_contains_any": ["$ne\":", "$gt\":", "$where\":", "$regex\":"]},
      fp=[FP_PENTEST], playbook="tpl-initial-access"),
    S(slug="app-graphql-introspection", name="GraphQL Introspection Query Against Production",
      severity="medium", mitre=["t1213"], product="api-gateway", service="http",
      when={"event_type": "http_request", "uri": "/graphql", "body_contains": "__schema", "environment": "prod"},
      fp=["Approved schema documentation generator"], playbook="tpl-discovery"),
    S(slug="app-graphql-deep-recursion", name="GraphQL Query With Excessive Recursion Depth",
      severity="medium", mitre=["t1499"], product="api-gateway", service="http",
      when={"event_type": "http_request", "uri": "/graphql", "query_depth_gt": 10},
      fp=["Sanctioned bulk export"], playbook="tpl-impact"),
    S(slug="app-jndi-log4shell", name="JNDI LDAP Lookup Pattern (Log4Shell-Style)",
      severity="critical", mitre=["t1190"], product="waf", service="http",
      when={"event_type": "http_request", "any_header_value_contains_any": ["${jndi:ldap://", "${jndi:rmi://", "${jndi:dns://"]},
      fp=[FP_PENTEST], playbook="tpl-initial-access"),
    S(slug="app-spring4shell-pattern", name="Spring4Shell Class Loader Manipulation Pattern",
      severity="critical", mitre=["t1190"], product="waf", service="http",
      when={"event_type": "http_request", "body_contains_any": ["class.module.classloader", "class.classLoader"]},
      fp=[FP_PENTEST], playbook="tpl-initial-access"),
    S(slug="app-deserialization-rce-marker", name="Java/.NET Deserialization Marker In Body",
      severity="critical", mitre=["t1059"], product="waf", service="http",
      when={"event_type": "http_request", "body_contains_any": ["rO0AB", "AAEAAAD/////AQAAAAAAAAAM", "TypeObject"]},
      fp=["Inter-service signed payload (allow-listed)"], playbook="tpl-initial-access"),
    S(slug="app-cookie-tampered-hmac", name="Session Cookie Failed HMAC Verification",
      severity="medium", mitre=["t1185"], product="application", service="auth",
      when={"event_type": "session_validate", "hmac_valid": False},
      fp=["Stale cookie after key rotation"], playbook="tpl-credential-access"),
    S(slug="app-account-enum-reset", name="High Volume Of Password Reset Requests From Single IP",
      severity="medium", mitre=["t1110"], product="application", service="auth",
      when={"event_type": "password_reset_request", "count_5min_per_ip_gt": 30},
      fp=["Internal load test"], playbook="tpl-credential-access"),
    S(slug="app-websocket-origin-bypass", name="WebSocket Upgrade From Cross-Origin Header",
      severity="medium", mitre=["t1190"], product="application", service="ws",
      when={"event_type": "ws_upgrade", "origin_matches_allowed_list": False},
      fp=["Newly added integration partner (update allow-list)"], playbook="tpl-initial-access"),
    S(slug="app-crlf-header-injection", name="CRLF Sequence In HTTP Header Value",
      severity="high", mitre=["t1190"], product="waf", service="http",
      when={"event_type": "http_request", "any_header_value_contains_any": ["%0d%0a", "\\r\\n"]},
      fp=[FP_PENTEST], playbook="tpl-defense-evasion"),
    S(slug="app-subdomain-takeover-cname", name="CNAME Pointing To Deleted SaaS Tenant",
      severity="high", mitre=["t1583.001"], product="dns", service="resolver",
      when={"event_type": "dns_response", "qtype": "CNAME", "target_endswith_any": [".herokudns.com", ".github.io", ".azurewebsites.net"], "target_resolves": False},
      fp=["Pending tenant migration (verify ticket)"], playbook="tpl-initial-access"),
    S(slug="app-cors-wildcard-with-creds", name="CORS Response With Wildcard Origin And Credentials Allowed",
      severity="medium", mitre=["t1190"], product="application", service="http",
      when={"event_type": "http_response", "header_access_control_allow_origin": "*", "header_access_control_allow_credentials": "true"},
      fp=["Public unauthenticated API"], playbook="tpl-defense-evasion"),
    S(slug="app-csp-disabled", name="Content-Security-Policy Header Removed From Production Response",
      severity="medium", mitre=["t1190"], product="application", service="http",
      when={"event_type": "http_response", "csp_header_present": False, "environment": "prod"},
      fp=["Public marketing pages exempt from CSP"], playbook="tpl-defense-evasion"),
]


# ---------------------------------------------------------------------------
# DevOps / CI / supply-chain (12)
# ---------------------------------------------------------------------------
DEVOPS_RULES: list[dict] = [
    S(slug="app-ci-workflow-modified-by-non-owner", name="CI Workflow Modified By Account Without CODEOWNER Approval",
      severity="high", mitre=["t1199"], product="github", service="repo",
      when={"event_type": "push", "path_contains": ".github/workflows/", "approver_role_neq": "codeowner"},
      fp=["Bootstrap of new repository"], playbook="tpl-supply-chain"),
    S(slug="app-self-hosted-runner-external", name="Self-Hosted Runner Registered From External IP",
      severity="critical", mitre=["t1199"], product="github", service="actions",
      when={"event_type": "runner_register", "ip_is_internal": False},
      fp=["Approved partner-hosted runner"], playbook="tpl-supply-chain"),
    S(slug="app-build-signing-key-rotated", name="Build Artifact Signing Key Rotated Outside Maintenance Window",
      severity="high", mitre=["t1554"], product="ci", service="signing",
      when={"event_type": "key_rotation", "in_change_window": False},
      fp=["Emergency key rotation (must be ticketed)"], playbook="tpl-supply-chain"),
    S(slug="app-helm-chart-untrusted-repo", name="Helm Install From Unknown Chart Repository",
      severity="high", mitre=["t1195.002"], product="kubernetes", service="helm",
      when={"event_type": "helm_install", "repo_url_endswith_in_allow_list": False},
      fp=["Pilot of new vendor chart"], playbook="tpl-supply-chain"),
    S(slug="app-terraform-destroy-prod", name="terraform destroy Run Targeting Production Workspace",
      severity="critical", mitre=["t1485"], product="terraform", service="cli",
      when={"event_type": "terraform_run", "command": "destroy", "workspace_in": ["prod", "production"]},
      fp=["Authorised infra teardown"], playbook="tpl-impact"),
    S(slug="app-secret-published-to-slack", name="Newly Created Secret Has Slack Webhook Pattern",
      severity="high", mitre=["t1078"], product="vault", service="secrets",
      when={"event_type": "secret_create", "value_contains": "hooks.slack.com/services/"},
      fp=["Approved alerting webhook"], playbook="tpl-credential-access"),
    S(slug="app-deploy-key-added-github", name="SSH Deploy Key Added To GitHub Repository",
      severity="medium", mitre=["t1098.004"], product="github", service="repo",
      when={"event_type": "deploy_key.create"},
      fp=["Sanctioned automation onboarding"], playbook="tpl-persistence"),
    S(slug="app-npm-package-publish-new-account", name="NPM Package Published From New Account",
      severity="high", mitre=["t1195.002"], product="npm", service="registry",
      when={"event_type": "package_publish", "publisher_account_age_days_lt": 14, "package_visibility": "public"},
      fp=["New maintainer onboarding"], playbook="tpl-supply-chain"),
    S(slug="app-pypi-package-publish-new-ip", name="PyPI Package Published From New IP",
      severity="medium", mitre=["t1195.002"], product="pypi", service="registry",
      when={"event_type": "package_publish", "publisher_ip_seen_before": False},
      fp=["New maintainer onboarding"], playbook="tpl-supply-chain"),
    S(slug="app-docker-insecure-registry-flag", name="Docker Daemon Started With --insecure-registry Flag",
      severity="medium", mitre=["t1195.002"], product="docker", service="dockerd",
      when={"event_type": "daemon_config", "insecure_registries_count_gt": 0},
      fp=["Internal mirror without TLS (deprecated, must be ticketed)"], playbook="tpl-supply-chain"),
    S(slug="app-image-critical-cve-pushed", name="Container Image With Critical CVE Pushed To Prod Registry",
      severity="high", mitre=["t1525"], product="container-registry", service="scan",
      when={"event_type": "scan_result", "cvss_max_gte": 9.0, "registry_environment": "prod"},
      fp=["Approved exception (must be ticketed)"], playbook="tpl-supply-chain"),
    S(slug="app-protected-branch-disabled", name="Branch Protection Disabled On Protected Branch",
      severity="high", mitre=["t1098.004"], product="github", service="repo",
      when={"event_type_in": ["protected_branch.policy_override", "protected_branch.destroy"]},
      fp=[FP_TUNING], playbook="tpl-supply-chain"),
]


# ---------------------------------------------------------------------------
# SaaS / collaboration (12)
# ---------------------------------------------------------------------------
SAAS_RULES: list[dict] = [
    S(slug="app-salesforce-mass-export", name="Salesforce Mass Data Export Initiated",
      severity="high", mitre=["t1530"], product="salesforce", service="audit",
      when={"event_type": "DataExport", "row_count_gt": 100000},
      fp=["Approved data migration"], playbook="tpl-exfiltration"),
    S(slug="app-salesforce-sandbox-refresh-anomaly", name="Salesforce Sandbox Refreshed Outside Change Window",
      severity="medium", mitre=["t1199"], product="salesforce", service="audit",
      when={"event_type": "SandboxRefresh", "in_change_window": False},
      fp=["Emergency sandbox refresh (must be ticketed)"], playbook="tpl-defense-evasion"),
    S(slug="app-workday-bank-info-changed", name="Workday Banking Info Changed Without HR Ticket",
      severity="high", mitre=["t1098"], product="workday", service="audit",
      when={"event_type": "BankAccountChange", "linked_ticket": False},
      fp=["Self-service change with valid step-up auth"], playbook="tpl-impact"),
    S(slug="app-zoom-recording-shared-external", name="Zoom Cloud Recording Shared Externally",
      severity="medium", mitre=["t1530"], product="zoom", service="audit",
      when={"event_type": "recording_share", "share_type": "external"},
      fp=["Customer-facing webinar recording"], playbook="tpl-exfiltration"),
    S(slug="app-box-public-link-mass-create", name="Box Created Many Public Links In Short Window",
      severity="high", mitre=["t1567.002"], product="box", service="audit",
      when={"event_type": "shared_link.create", "access": "open", "count_5min_per_user_gt": 20},
      fp=["Marketing campaign content drop"], playbook="tpl-exfiltration"),
    S(slug="app-notion-workspace-export", name="Notion Workspace Exported By Non-Admin",
      severity="high", mitre=["t1530"], product="notion", service="audit",
      when={"event_type": "workspace.export", "actor_is_admin": False},
      fp=["Approved knowledge migration"], playbook="tpl-exfiltration"),
    S(slug="app-confluence-space-export-bulk", name="Confluence Bulk Space Export",
      severity="medium", mitre=["t1530"], product="confluence", service="audit",
      when={"event_type": "space.export", "size_bytes_gt": 524288000},
      fp=["Approved knowledge migration"], playbook="tpl-exfiltration"),
    S(slug="app-servicenow-record-export-bulk", name="ServiceNow Bulk Record Export",
      severity="medium", mitre=["t1530"], product="servicenow", service="audit",
      when={"event_type": "record_export", "row_count_gt": 50000},
      fp=["Approved reporting workflow"], playbook="tpl-exfiltration"),
    S(slug="app-slack-file-shared-external", name="Slack File Shared To External Channel",
      severity="medium", mitre=["t1567.002"], product="slack", service="audit",
      when={"event_type": "file_shared", "channel_type": "external"},
      fp=["Approved partner connect channel"], playbook="tpl-exfiltration"),
    S(slug="app-slack-channel-public-conversion", name="Slack Private Channel Converted To Public",
      severity="medium", mitre=["t1213"], product="slack", service="audit",
      when={"event_type": "channel_convert_to_public"},
      fp=["Approved transparency policy"], playbook="tpl-defense-evasion"),
    S(slug="app-onedrive-anonymous-link-sensitive", name="OneDrive Anonymous Sharing Link Created For Sensitive File",
      severity="high", mitre=["t1567.002"], product="m365", service="audit",
      when={"event_type": "AnonymousLinkCreated", "sensitivity_label_in": ["Confidential", "Highly Confidential"]},
      fp=["Approved external review"], playbook="tpl-exfiltration"),
    S(slug="app-sharepoint-guest-tenantwide", name="SharePoint Tenant-Wide Guest Access Enabled",
      severity="high", mitre=["t1078.004"], product="m365", service="audit",
      when={"event_type": "TenantSettingChanged", "setting": "SharingCapability", "value": "ExternalUserSharingOnly"},
      fp=["Approved tenant-level policy update"], playbook="tpl-defense-evasion"),
]


# ---------------------------------------------------------------------------
# API misuse (1)
# ---------------------------------------------------------------------------
API_RULES: list[dict] = [
    S(slug="app-graphql-mutation-anonymous", name="GraphQL Mutation Executed By Anonymous Caller",
      severity="high", mitre=["t1190"], product="api-gateway", service="http",
      when={"event_type": "graphql_op", "op_type": "mutation", "actor_authenticated": False},
      fp=["Public mutation endpoint (allow-listed: subscribe / contact)"], playbook="tpl-initial-access"),
]


# ---------------------------------------------------------------------------
# Aggregate
# ---------------------------------------------------------------------------
APPLICATION_EXTRA: list[dict] = (
    WEB_APP_RULES
    + DEVOPS_RULES
    + SAAS_RULES
    + API_RULES
)


__all__ = [
    "APPLICATION_EXTRA",
    "WEB_APP_RULES",
    "DEVOPS_RULES",
    "SAAS_RULES",
    "API_RULES",
]
