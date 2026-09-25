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
  3. CI check (``scripts/check_action_contract.py``, ``check_capability_mirror``)
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
        # Reverse verbs. Added because the action contract names them as
        # the rollback for quarantine_file, disable_user, block_domain and
        # block_ioc — and a declared reverse that is not in the vocabulary
        # is worse than none, because the rollback path believes it has one.
        "allow_domain",
        "allow_hash",
        "allow_ioc",
        "enable_user",
        "restore_file",
        # WS-E live action verbs
        "allow_ip",
        "block_ioc",
        "block_ip",
        "create_notable_event",
        "force_mfa",
        "run_av_scan",
        "run_script",
        "get_host",
        "get_detections",
        "get_user_activity",
        "search_siem",
        "suspend_session",
        "sync_detection_rule",
        # The return leg of a two-way SIEM integration: AiSOC's verdict
        # written back onto the vendor finding that produced the alert.
        "update_alert_disposition",
        "update_watcher",
        # Alert lifecycle. Executors with three vendor arms each existed for
        # both of these while neither verb appeared here, in the contracts or
        # in the live-action registry, so governed dispatch answered
        # executor_not_found for code that worked.
        "ack_alert",
        "suppress_alert",
        # EVIDENCE. An ActionType with no executor anywhere, proposed by name
        # on the C2 / exfiltration path — so the most serious incidents got a
        # recommendation that answered "No executor found for action type".
        "capture_forensics",
        # HUMAN-IN-THE-LOOP. A working executor no adapter reached, because
        # its honest result ("prompt delivered, nobody has answered") had no
        # LiveActionStatus to land in.
        "chatops_verify",
        # TICKET
        "push_case",
        "push_status",
        "create_ticket",
        # NOTIFY
        "notify",
        # AUDIT
        "read_audit_trail",
    }
)
