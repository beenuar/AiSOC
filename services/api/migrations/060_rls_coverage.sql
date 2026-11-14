-- Row-level security for every tenant-scoped table in this chain, and a
-- repair for the seven policies that were wired to a session variable
-- nothing sets.
--
-- Why this migration exists
-- -------------------------
-- The repository's stated design is that tenant isolation is enforced at the
-- query layer *with RLS as defence in depth*. Measured against the tree, 31 of
-- 95 tenant-scoped tables carried a policy. On the other 64 the query
-- predicate was the only thing between two customers, so one missing
-- ``WHERE tenant_id`` was a leak rather than something a second layer caught.
-- 002_rls.sql covered six tables and every migration since added tables
-- without adding policies.
--
-- What this does NOT change
-- -------------------------
-- The query predicate stays the primary control. Nothing here relaxes a
-- filter, and ``scripts/check_tenant_query_predicates.py`` still requires one
-- on every statement. Two independent layers is the point; this is the second.
--
-- Seven policies that were already wrong
-- --------------------------------------
-- Verified against postgres:16-alpine as a non-superuser, fresh session, no
-- tenant context — i.e. exactly how a background worker connects:
--
--   external_assets, external_asset_drift  current_setting('app.current_tenant_id')
--                                          with no missing_ok argument, so the
--                                          query raises
--                                          "unrecognized configuration parameter"
--                                          instead of returning rows.
--   alert_sla_events, tenant_sla_config    read app.tenant_id — a GUC no code
--                                          path sets — so they return zero rows.
--   custom_parsers, retention_policies     read app.current_tenant, same.
--   compliance_evidence                    reads the right GUC but has no
--                                          "IS NULL" arm, so an unset context
--                                          returns zero rows.
--
-- None of this was observable because the application bypasses RLS entirely
-- (see below), which is precisely why a policy nobody exercises is worse than
-- no policy: it reads as protection in a schema dump.
--
-- The canonical predicate
-- -----------------------
--   USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL)
--
-- ``current_tenant_id()`` (002_rls.sql) reads app.current_tenant_id and
-- returns NULL when it is unset. The "OR ... IS NULL" arm is deliberate and
-- pre-existing: a session that never ran ``SET LOCAL app.current_tenant_id``
-- sees everything, because the ingest, fusion, scheduler and purge workers all
-- operate cross-tenant by design and would otherwise silently process nothing.
-- Fail-open on an unset context, fail-closed on a set one.
--
-- Read this as the honest statement of the guarantee: RLS engages only on a
-- session that established a tenant. Those are ``TenantDBSession`` in the API,
-- ``_set_rls_context`` in the agents ledger / hunt store / LLM resolver, and
-- the per-hunt rebind in the hunt scheduler. On every other connection these
-- policies are inert by design and the query predicate is the only control.
--
-- The role the application connects as
-- ------------------------------------
-- A superuser, or a role with BYPASSRLS, ignores policies even with FORCE ROW
-- LEVEL SECURITY. docker-compose and the CI services both run the API as
-- POSTGRES_USER=aisoc, which the postgres image creates as a superuser, so
-- today **every policy in this database — the 31 that existed and the 49 added
-- here — is bypassed**. Measured, not assumed: with two alerts seeded one per
-- tenant and the context set to tenant A, `aisoc` sees 2 and `aisoc_app` sees 1.
--
-- This migration does not change the connection role, because doing so needs a
-- password and a grant review that belong to a deployment, not to a schema
-- change. It makes the policies correct and provable so that switching the
-- role is the only remaining step. ``apps/docs/docs/operations/security.md``
-- documents that step, and tests/isolation/test_postgres_rls.py proves the
-- policies isolate by connecting as a non-superuser.
--
-- Excluded on purpose
-- -------------------
--   users     002_rls.sql excluded it so authentication can resolve a
--             principal before any tenant exists, and platform-admin user
--             administration in tenants.py is cross-tenant by design. Both
--             still read through a plain session, so a policy here would be
--             inert anyway — but stating the exclusion is better than leaving
--             a reader to infer it from an absence.
--   tenants   has no tenant_id column; it is the tenant.
--
-- Two API ORM models — case_tasks, case_timeline — declare a tenant_id but no
-- migration creates their tables, so there is nothing here to protect. They
-- are reported by the isolation suite rather than silently skipped.

-- ─── 1. Repair the policies that read a session variable nothing sets ────────
-- Dropped by the name each migration actually used: these predate the
-- <table>_tenant convention and carry four different names between them.

DROP POLICY IF EXISTS tenant_isolation ON alert_sla_events;
DROP POLICY IF EXISTS alert_sla_events_tenant ON alert_sla_events;
ALTER TABLE alert_sla_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_sla_events FORCE ROW LEVEL SECURITY;
CREATE POLICY alert_sla_events_tenant ON alert_sla_events
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS compliance_evidence_tenant_isolation ON compliance_evidence;
DROP POLICY IF EXISTS compliance_evidence_tenant ON compliance_evidence;
ALTER TABLE compliance_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE compliance_evidence FORCE ROW LEVEL SECURITY;
CREATE POLICY compliance_evidence_tenant ON compliance_evidence
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS custom_parsers_tenant ON custom_parsers;
ALTER TABLE custom_parsers ENABLE ROW LEVEL SECURITY;
ALTER TABLE custom_parsers FORCE ROW LEVEL SECURITY;
CREATE POLICY custom_parsers_tenant ON custom_parsers
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS easm_drift_tenant_isolation ON external_asset_drift;
DROP POLICY IF EXISTS external_asset_drift_tenant ON external_asset_drift;
ALTER TABLE external_asset_drift ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_asset_drift FORCE ROW LEVEL SECURITY;
CREATE POLICY external_asset_drift_tenant ON external_asset_drift
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS easm_tenant_isolation ON external_assets;
DROP POLICY IF EXISTS external_assets_tenant ON external_assets;
ALTER TABLE external_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE external_assets FORCE ROW LEVEL SECURITY;
CREATE POLICY external_assets_tenant ON external_assets
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS retention_policies_tenant ON retention_policies;
ALTER TABLE retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_policies FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_policies_tenant ON retention_policies
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

DROP POLICY IF EXISTS tenant_isolation ON tenant_sla_config;
DROP POLICY IF EXISTS tenant_sla_config_tenant ON tenant_sla_config;
ALTER TABLE tenant_sla_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_sla_config FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_sla_config_tenant ON tenant_sla_config
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ─── 2. A policy on every remaining tenant-scoped table in this chain ────────

ALTER TABLE aisoc_action_records ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_action_records FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_action_records_tenant ON aisoc_action_records;
CREATE POLICY aisoc_action_records_tenant ON aisoc_action_records
    USING (tenant_id = current_tenant_id()::text OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_analyst_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_analyst_feedback FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_analyst_feedback_tenant ON aisoc_analyst_feedback;
CREATE POLICY aisoc_analyst_feedback_tenant ON aisoc_analyst_feedback
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_autonomy_thresholds ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_autonomy_thresholds FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_autonomy_thresholds_tenant ON aisoc_autonomy_thresholds;
CREATE POLICY aisoc_autonomy_thresholds_tenant ON aisoc_autonomy_thresholds
    USING (tenant_id = current_tenant_id()::text OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_business_context_rule_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_business_context_rule_sets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_business_context_rule_sets_tenant ON aisoc_business_context_rule_sets;
CREATE POLICY aisoc_business_context_rule_sets_tenant ON aisoc_business_context_rule_sets
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_case_comments ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_case_comments FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_case_comments_tenant ON aisoc_case_comments;
CREATE POLICY aisoc_case_comments_tenant ON aisoc_case_comments
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_case_tasks ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_case_tasks FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_case_tasks_tenant ON aisoc_case_tasks;
CREATE POLICY aisoc_case_tasks_tenant ON aisoc_case_tasks
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_cases FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_cases_tenant ON aisoc_cases;
CREATE POLICY aisoc_cases_tenant ON aisoc_cases
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_compliance_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_compliance_evidence FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_compliance_evidence_tenant ON aisoc_compliance_evidence;
CREATE POLICY aisoc_compliance_evidence_tenant ON aisoc_compliance_evidence
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_context_statements ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_context_statements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_context_statements_tenant ON aisoc_context_statements;
CREATE POLICY aisoc_context_statements_tenant ON aisoc_context_statements
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_dead_letters ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_dead_letters FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_dead_letters_tenant ON aisoc_dead_letters;
CREATE POLICY aisoc_dead_letters_tenant ON aisoc_dead_letters
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_hunt_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_hunt_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_hunt_runs_tenant ON aisoc_hunt_runs;
CREATE POLICY aisoc_hunt_runs_tenant ON aisoc_hunt_runs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_hunts ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_hunts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_hunts_tenant ON aisoc_hunts;
CREATE POLICY aisoc_hunts_tenant ON aisoc_hunts
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_institutional_memory ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_institutional_memory FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_institutional_memory_tenant ON aisoc_institutional_memory;
CREATE POLICY aisoc_institutional_memory_tenant ON aisoc_institutional_memory
    USING (tenant_id = current_tenant_id()::text OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_kb_documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_kb_documents FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_kb_documents_tenant ON aisoc_kb_documents;
CREATE POLICY aisoc_kb_documents_tenant ON aisoc_kb_documents
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_outcome_suppressions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_outcome_suppressions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_outcome_suppressions_tenant ON aisoc_outcome_suppressions;
CREATE POLICY aisoc_outcome_suppressions_tenant ON aisoc_outcome_suppressions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_phishing_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_phishing_submissions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_phishing_submissions_tenant ON aisoc_phishing_submissions;
CREATE POLICY aisoc_phishing_submissions_tenant ON aisoc_phishing_submissions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE aisoc_run_costs ENABLE ROW LEVEL SECURITY;
ALTER TABLE aisoc_run_costs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS aisoc_run_costs_tenant ON aisoc_run_costs;
CREATE POLICY aisoc_run_costs_tenant ON aisoc_run_costs
    USING (tenant_id = current_tenant_id()::text OR current_tenant_id() IS NULL);

ALTER TABLE alert_asset_correlations ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_asset_correlations FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alert_asset_correlations_tenant ON alert_asset_correlations;
CREATE POLICY alert_asset_correlations_tenant ON alert_asset_correlations
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE alert_identity_links ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_identity_links FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS alert_identity_links_tenant ON alert_identity_links;
CREATE POLICY alert_identity_links_tenant ON alert_identity_links
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE asset_vulnerabilities ENABLE ROW LEVEL SECURITY;
ALTER TABLE asset_vulnerabilities FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS asset_vulnerabilities_tenant ON asset_vulnerabilities;
CREATE POLICY asset_vulnerabilities_tenant ON asset_vulnerabilities
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE assets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS assets_tenant ON assets;
CREATE POLICY assets_tenant ON assets
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE case_timeline_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_timeline_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS case_timeline_events_tenant ON case_timeline_events;
CREATE POLICY case_timeline_events_tenant ON case_timeline_events
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE identity_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_edges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_edges_tenant ON identity_edges;
CREATE POLICY identity_edges_tenant ON identity_edges
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE identity_nodes ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_nodes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS identity_nodes_tenant ON identity_nodes;
CREATE POLICY identity_nodes_tenant ON identity_nodes
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE insider_indicators ENABLE ROW LEVEL SECURITY;
ALTER TABLE insider_indicators FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS insider_indicators_tenant ON insider_indicators;
CREATE POLICY insider_indicators_tenant ON insider_indicators
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE insider_peer_groups ENABLE ROW LEVEL SECURITY;
ALTER TABLE insider_peer_groups FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS insider_peer_groups_tenant ON insider_peer_groups;
CREATE POLICY insider_peer_groups_tenant ON insider_peer_groups
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE marketplace_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE marketplace_entitlements FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS marketplace_entitlements_tenant ON marketplace_entitlements;
CREATE POLICY marketplace_entitlements_tenant ON marketplace_entitlements
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE marketplace_installs ENABLE ROW LEVEL SECURITY;
ALTER TABLE marketplace_installs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS marketplace_installs_tenant ON marketplace_installs;
CREATE POLICY marketplace_installs_tenant ON marketplace_installs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE marketplace_publishers ENABLE ROW LEVEL SECURITY;
ALTER TABLE marketplace_publishers FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS marketplace_publishers_tenant ON marketplace_publishers;
CREATE POLICY marketplace_publishers_tenant ON marketplace_publishers
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE marketplace_submissions ENABLE ROW LEVEL SECURITY;
ALTER TABLE marketplace_submissions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS marketplace_submissions_tenant ON marketplace_submissions;
CREATE POLICY marketplace_submissions_tenant ON marketplace_submissions
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE mssp_tenant_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE mssp_tenant_metrics FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mssp_tenant_metrics_tenant ON mssp_tenant_metrics;
CREATE POLICY mssp_tenant_metrics_tenant ON mssp_tenant_metrics
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE oauth_app_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_app_credentials FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oauth_app_credentials_tenant ON oauth_app_credentials;
CREATE POLICY oauth_app_credentials_tenant ON oauth_app_credentials
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE oauth_states ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_states FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS oauth_states_tenant ON oauth_states;
CREATE POLICY oauth_states_tenant ON oauth_states
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE organization_member_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_member_tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_member_tenants_tenant ON organization_member_tenants;
CREATE POLICY organization_member_tenants_tenant ON organization_member_tenants
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE organization_tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE organization_tenants FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS organization_tenants_tenant ON organization_tenants;
CREATE POLICY organization_tenants_tenant ON organization_tenants
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE passkey_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS passkey_challenges_tenant ON passkey_challenges;
CREATE POLICY passkey_challenges_tenant ON passkey_challenges
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE posture_drift_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_drift_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS posture_drift_events_tenant ON posture_drift_events;
CREATE POLICY posture_drift_events_tenant ON posture_drift_events
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE posture_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_findings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS posture_findings_tenant ON posture_findings;
CREATE POLICY posture_findings_tenant ON posture_findings
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE posture_scan_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE posture_scan_runs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS posture_scan_runs_tenant ON posture_scan_runs;
CREATE POLICY posture_scan_runs_tenant ON posture_scan_runs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE published_replays ENABLE ROW LEVEL SECURITY;
ALTER TABLE published_replays FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS published_replays_tenant ON published_replays;
CREATE POLICY published_replays_tenant ON published_replays
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE remediation_gate_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_gate_log FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_gate_log_tenant ON remediation_gate_log;
CREATE POLICY remediation_gate_log_tenant ON remediation_gate_log
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE remediation_maturity ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_maturity FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_maturity_tenant ON remediation_maturity;
CREATE POLICY remediation_maturity_tenant ON remediation_maturity
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE remediation_whitelist ENABLE ROW LEVEL SECURITY;
ALTER TABLE remediation_whitelist FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS remediation_whitelist_tenant ON remediation_whitelist;
CREATE POLICY remediation_whitelist_tenant ON remediation_whitelist
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE report_artefacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_artefacts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS report_artefacts_tenant ON report_artefacts;
CREATE POLICY report_artefacts_tenant ON report_artefacts
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE report_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE report_templates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS report_templates_tenant ON report_templates;
CREATE POLICY report_templates_tenant ON report_templates
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE threat_actors ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_actors FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS threat_actors_tenant ON threat_actors;
CREATE POLICY threat_actors_tenant ON threat_actors
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE threat_intel_feeds ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_feeds FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS threat_intel_feeds_tenant ON threat_intel_feeds;
CREATE POLICY threat_intel_feeds_tenant ON threat_intel_feeds
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE threat_intel_iocs ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intel_iocs FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS threat_intel_iocs_tenant ON threat_intel_iocs;
CREATE POLICY threat_intel_iocs_tenant ON threat_intel_iocs
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

ALTER TABLE user_risk_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_risk_profiles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS user_risk_profiles_tenant ON user_risk_profiles;
CREATE POLICY user_risk_profiles_tenant ON user_risk_profiles
    USING (tenant_id = current_tenant_id() OR current_tenant_id() IS NULL);

-- ─── 3. Refuse to finish having protected less than was claimed ─────────────
--
-- Spelled out above as 56 literal ALTER/CREATE POLICY statements rather than a
-- loop over information_schema, for two reasons. A reviewer can see exactly
-- which tables were given a policy and with which predicate; and
-- ``scripts/check_tenant_query_predicates.py`` derives its RLS inventory by
-- reading these files, so a policy created inside a PL/pgSQL EXECUTE is a
-- policy the gate cannot see — it would go on reporting 64 unprotected tables
-- while the database had 1.
--
-- This block asserts the outcome rather than repeating the list: every table
-- in this database that carries a tenant_id must now have RLS, FORCE and a
-- policy, or the migration fails and nothing is recorded as applied.

DO $$
DECLARE
    gap text;
BEGIN
    SELECT string_agg(c.relname, ', ' ORDER BY c.relname) INTO gap
      FROM pg_class c
      JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public'
       AND c.relkind = 'r'
       AND c.relname <> 'users'
       AND EXISTS (SELECT 1 FROM pg_attribute a
                    WHERE a.attrelid = c.oid AND a.attname = 'tenant_id' AND NOT a.attisdropped)
       AND (NOT c.relrowsecurity
            OR NOT c.relforcerowsecurity
            OR NOT EXISTS (SELECT 1 FROM pg_policies p
                            WHERE p.schemaname = 'public' AND p.tablename = c.relname));
    IF gap IS NOT NULL THEN
        RAISE EXCEPTION
            '060_rls_coverage: these tenant-scoped tables still lack RLS, FORCE or a policy: %', gap;
    END IF;
END
$$;
