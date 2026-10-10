# SQL for the patch-window promotion job (docs/cve-patch-policy.md rule 5).
# Kept module-level (not inline in coroutines) so tests can pin the
# statements and a reviewer can diff the policy in one place. The inventory
# insert/touch statements live in app.vulnerabilities (sync_findings owns
# them); this module only owns the tracked->overdue->promoted->resolved
# lifecycle and the grouped-alert upsert.

from __future__ import annotations

#: Mark a patch window's tracked findings overdue once their due date has
#: passed. Only ``tracked`` rows flip — ``promoted`` rows already have an
#: alert, and rows with ``remediated_at`` set are done. Runs inside the
#: promotion job's transaction so an alert is never created for a row the
#: same sweep did not mark overdue.
MARK_OVERDUE_SQL = """
    UPDATE asset_vulnerabilities
       SET patch_status = 'overdue'
     WHERE tenant_id = CAST(:tenant_id AS uuid)
       AND remediated_at IS NULL
       AND patch_status = 'tracked'
       AND patch_due_date IS NOT NULL
       AND patch_due_date < (NOW() AT TIME ZONE 'UTC')::date
"""

#: The promotion candidate set: one row per CVE (the CVE is the unit an
#: analyst tracks; hosts roll up into ``affected_hosts``) that is
#: open AND (overdue, CVSS>9, KEV-listed, or actively exploited) —
#: exactly the policy's rule-5 exception path. ``MAX``/``bool_or``
#: aggregates pick the worst-case representation; the per-CVE grouping is
#: why 1 CVE on 4 hosts is one alert instead of four.
#:
#: KEV join note: ``threat_intel_iocs`` is live-empty on this stack, so
#: the EXISTS clause contributes nothing today — it is the seam the 093
#: KEV seed worker feeds when it lands. ``is_exploited`` is the exploited
#: signal that works right now.
PROMOTE_CANDIDATES_SQL = """
    SELECT v.cve_id,
           MAX(v.cvss_score)                        AS cvss_score,
           bool_or(v.is_exploited)                  AS is_exploited,
           MIN(v.patch_due_date)                    AS patch_due_date,
           jsonb_agg(DISTINCT a.name ORDER BY a.name) AS affected_hosts,
           count(DISTINCT v.asset_id)               AS host_count
      FROM asset_vulnerabilities v
      JOIN assets a
        ON a.tenant_id = v.tenant_id AND a.id = v.asset_id
     WHERE v.tenant_id = CAST(:tenant_id AS uuid)
       AND v.remediated_at IS NULL
       AND (
             v.patch_status IN ('overdue', 'promoted')
             OR (v.cvss_score IS NOT NULL AND v.cvss_score > 9)
             OR v.is_exploited
             OR EXISTS (
                    SELECT 1 FROM threat_intel_iocs i
                     WHERE i.tenant_id = v.tenant_id
                       AND i.ioc_type = 'cve'
                       AND lower(i.value) = lower(v.cve_id)
                       AND i.is_active
                       AND i.false_positive = false
                 )
           )
     GROUP BY v.cve_id
"""

#: Close a promoted alert when its CVE is remediated: the alert follows the
#: CVE's open/closed state, so the patch day clears the queue without an
#: analyst touching 500 windows (policy §Alert lifecycle). Column names are
#: the live schema (``resolved_at``/``disposition`` — there is no
#: ``closed_at``/``resolution`` on ``alerts``).
RESOLVE_REMEDIATED_SQL = """
    UPDATE alerts al
       SET status = 'resolved',
           resolved_at = NOW(),
           disposition = 'remediated: all assets patched (patch-window policy)'
     WHERE al.tenant_id = CAST(:tenant_id AS uuid)
       AND al.status NOT IN ('resolved', 'closed')
       AND al.idempotency_key LIKE 'vuln-promo:%'
       AND NOT EXISTS (
             SELECT 1 FROM asset_vulnerabilities v
              WHERE v.tenant_id = al.tenant_id
                AND v.remediated_at IS NULL
                AND lower(v.cve_id) = split_part(al.idempotency_key, ':', 2)
           )
"""

#: One grouped alert per CVE (upsert). The conflict target is the partial
#: unique index uq_alerts_tenant_idempotency — the same idempotency
#: discipline the alert sink uses for scanner alerts, so re-promoting an
#: already-open CVE touches ``last_seen`` instead of minting a duplicate.
#: ``ON CONFLICT ... DO UPDATE`` bumps metadata only when something
#: meaningful changed (more hosts, new exploit status), keeping ``status``
#: sticky: a promoted alert that an analyst moved to ``investigating`` must
#: not snap back to ``new`` on the next sweep.
UPSERT_ALERT_SQL = """
    INSERT INTO alerts (
        tenant_id, connector_type, category, title, description,
        severity, status, event_time, first_seen, last_seen,
        affected_hosts, tags, ocsf_class_uid, idempotency_key,
        connector_id, raw_event
    ) VALUES (
        CAST(:tenant_id AS uuid), 'inventory', 'vulnerability',
        :title, :description, :severity, 'new', NOW(), NOW(), NOW(),
        :affected_hosts::jsonb, :tags::jsonb, 2001, :idempotency_key,
        :connector_id, :raw_event::jsonb
    )
    ON CONFLICT (tenant_id, idempotency_key) WHERE idempotency_key IS NOT NULL
    DO UPDATE SET
        last_seen    = NOW(),
        affected_hosts = EXCLUDED.affected_hosts,
        severity     = EXCLUDED.severity,
        description  = EXCLUDED.description,
        tags         = EXCLUDED.tags
"""

#: After a CVE's alert row exists, mark its contributing rows promoted so
#: the next sweep does not re-count them as fresh candidates.
MARK_PROMOTED_SQL = """
    UPDATE asset_vulnerabilities
       SET patch_status = 'promoted'
     WHERE tenant_id = CAST(:tenant_id AS uuid)
       AND remediated_at IS NULL
       AND lower(cve_id) = :cve_id
       AND patch_status IN ('tracked', 'overdue')
"""


#: Public surface: the scheduler and tests import these names. Public (not
#: underscore) because cross-module use of private names is what made an
#: automated pass report them "unused globals" — the module is the SQL's
#: only home, and its consumers are in-repo and explicit.
__all__ = [
    "MARK_OVERDUE_SQL",
    "PROMOTE_CANDIDATES_SQL",
    "RESOLVE_REMEDIATED_SQL",
    "UPSERT_ALERT_SQL",
    "MARK_PROMOTED_SQL",
]
