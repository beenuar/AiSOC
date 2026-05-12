"""
Known capability vocabulary for live actions.

This is a deliberate mirror of the ``Capability`` enum defined in
``services/connectors/app/connectors/base.py``. We mirror instead of
importing because:

  * Each AiSOC service is independently deployable. A hard import from
    ``services.actions`` into ``services.connectors`` would couple two
    deploy units that today have no dependency.
  * The mirror is small (a flat ``frozenset[str]``), trivially diffable
    in PRs, and used only for soft validation at registration time.

Adding a capability:
  1. Add it to ``Capability`` in ``services/connectors/app/connectors/base.py``.
  2. Add the same string here.
  3. CI check (``services/actions/tests/test_capability_mirror.py``)
     compares the two sets and fails the build if they drift.

Plugins MAY register executors for capabilities outside this set — we
log a warning instead of refusing, because forcing a plugin author to
also patch the core service would defeat the point of having a plugin
SDK. The warning lets us notice drift in production.
"""

from __future__ import annotations

# Mirror of services/connectors/app/connectors/base.py::Capability values.
# Keep alphabetical within each group to make diffs obvious.
KNOWN_CAPABILITIES: frozenset[str] = frozenset(
    {
        # READ
        "pull_alerts",
        "pull_audit",
        "pull_file",
        "pull_logs",
        "pull_pcap",
        # QUERY
        "query_logs",
        "query_processes",
        # PIVOT
        "pivot_domain",
        "pivot_hash",
        "pivot_host",
        "pivot_ip",
        "pivot_user",
        # ENRICH
        "enrich_asset",
        "enrich_domain",
        "enrich_host",
        "enrich_ioc",
        "enrich_user",
        "enrich_vuln",
        # CONTAIN / REMEDIATE
        "block_domain",
        "block_hash",
        "block_user_signin",
        "disable_user",
        "isolate_host",
        "kill_process",
        "quarantine_file",
        "reset_password",
        "revoke_session",
        "revoke_token",
        "unisolate_host",
        # WS-E live action verbs
        "allow_ip",
        "block_ioc",
        "block_ip",
        "create_notable_event",
        "force_mfa",
        "run_av_scan",
        "run_script",
        "search_siem",
        "suspend_session",
        "sync_detection_rule",
        "update_watcher",
        # TICKET
        "push_case",
        "push_status",
        # AUDIT
        "read_audit_trail",
    }
)
