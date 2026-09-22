// Package graph implements the ingest-side graph writer (T1.1).
//
// Every normalised OCSF event flowing through the Kafka ingest path is
// projected into the AiSOC entity graph (Neo4j) before fusion sees it. The
// graph writer is the foundation for downstream reasoning:
//
//   - T1.2 — versioned config snapshots tied to {ts, snapshot_id}
//   - T2.1 — pre-fetched investigation context bundle
//   - T3.2 — Effective Permissions UI
//   - T3.3 — Attack Chains UI
//   - T6.1 — hosted SaaS managed waitlist
//
// This file owns the *versioned* schema vocabulary so connectors and UI can
// pin against a stable contract. Bumping “SchemaVersion“ is a breaking
// signal: it means the graph writer is producing a new shape and downstream
// consumers must opt in.
package graph

// SchemaVersion is the identifier stamped on every node and event-edge. It
// lets downstream services pin to a known shape and lets us migrate without
// breaking older queries — a query that needs the v1.0 vocabulary can filter
// on `schema_version = "v1.0"`.
//
// IMPORTANT: bump this any time the canonical node/edge enums below change.
// Keep the format “vMAJOR.MINOR“.
//
// v1.1 (context depth) is strictly additive. It adds the four dimensions an
// investigation needs but could not previously traverse:
//
//	identity  Employee -> Department -> manager chain, so an alert on an
//	          account resolves to a person, their team, and who to escalate to.
//	          Accounts alone cannot answer "is this expected for this person".
//	asset     Vulnerability and Application, so an alert on a host carries what
//	          is exploitable on it and what it runs.
//	cloud     CloudAccount and Secret, so a compromised workload resolves to a
//	          blast radius rather than a resource id.
//	business  Application criticality, data classification and business owner,
//	          which is what turns a severity into a priority.
//	threat    IOC -> Malware -> Campaign -> ThreatActor -> Technique, so an
//	          indicator resolves to who is likely behind it and what they do next.
//
// Every v1.0 label and relationship is unchanged, so a consumer pinned to
// v1.0 keeps working and simply does not see the new vocabulary.
const SchemaVersion = "v1.1"

// NodeLabel is the canonical entity type — matches the Neo4j label.
type NodeLabel string

// Canonical node labels for v1.0. Each label corresponds 1:1 to the entity
// vocabulary used in the v8.0 plan. New labels MUST go through a schema bump.
const (
	NodeIdentity       NodeLabel = "Identity"
	NodePermission     NodeLabel = "Permission"
	NodeRole           NodeLabel = "Role"
	NodePolicy         NodeLabel = "Policy"
	NodeResource       NodeLabel = "Resource"
	NodeConfiguration  NodeLabel = "Configuration"
	NodeEndpoint       NodeLabel = "Endpoint"
	NodeUser           NodeLabel = "User"
	NodeServiceAccount NodeLabel = "ServiceAccount"
	NodeRepo           NodeLabel = "Repo"
	NodeContainer      NodeLabel = "Container"
	NodeImage          NodeLabel = "Image"
	NodeNetworkPath    NodeLabel = "NetworkPath"
	NodeSaaSApp        NodeLabel = "SaaSApp"
	NodeAlert          NodeLabel = "Alert"
	NodeCase           NodeLabel = "Case"
	NodeDetection      NodeLabel = "Detection"

	// ── v1.1: identity depth ──────────────────────────────────────────
	// The person behind the accounts. An Identity is an account; an
	// Employee is who holds it, which is what lets an investigation ask
	// whether behaviour on one account is consistent with the same human's
	// behaviour on another.
	NodeEmployee   NodeLabel = "Employee"
	NodeDepartment NodeLabel = "Department"

	// ── v1.1: asset depth ─────────────────────────────────────────────
	NodeVulnerability NodeLabel = "Vulnerability"
	NodeApplication   NodeLabel = "Application"

	// ── v1.1: cloud depth ─────────────────────────────────────────────
	NodeCloudAccount NodeLabel = "CloudAccount"
	// Secret is a *reference*, never a value: name, store, rotation age.
	// The graph must be safe to hand to an agent.
	NodeSecret NodeLabel = "Secret"

	// ── v1.1: threat depth ────────────────────────────────────────────
	// These are the global reference labels. They are deliberately not
	// tenant-scoped, and tenant_deletion.py exempts them from an
	// offboarding purge.
	NodeIOC         NodeLabel = "IOC"
	NodeMalware     NodeLabel = "Malware"
	NodeCampaign    NodeLabel = "Campaign"
	NodeThreatActor NodeLabel = "ThreatActor"
	NodeTechnique   NodeLabel = "Technique"
	NodeTactic      NodeLabel = "Tactic"
)

// AllNodeLabels is the canonical, ordered enumeration of v1.0 labels. Used by
// the schema-publication tool (T1.3) and by downstream consumers that need to
// validate they understand every label they see on the wire.
var AllNodeLabels = []NodeLabel{
	NodeIdentity,
	NodePermission,
	NodeRole,
	NodePolicy,
	NodeResource,
	NodeConfiguration,
	NodeEndpoint,
	NodeUser,
	NodeServiceAccount,
	NodeRepo,
	NodeContainer,
	NodeImage,
	NodeNetworkPath,
	NodeSaaSApp,
	NodeAlert,
	NodeCase,
	NodeDetection,
	NodeEmployee,
	NodeDepartment,
	NodeVulnerability,
	NodeApplication,
	NodeCloudAccount,
	NodeSecret,
	NodeIOC,
	NodeMalware,
	NodeCampaign,
	NodeThreatActor,
	NodeTechnique,
	NodeTactic,
}

// GlobalNodeLabels are reference entities shared across tenants: MITRE
// technique and tactic vocabulary, and public threat intel. They carry no
// tenant_id, tenant-scoped reads must exempt them explicitly, and an
// offboarding purge must not remove them.
var GlobalNodeLabels = []NodeLabel{
	NodeTechnique,
	NodeTactic,
	NodeMalware,
	NodeCampaign,
	NodeThreatActor,
	// A CVE is the same fact in every tenant. What is tenant-specific is
	// the AFFECTED_BY edge from a scoped Resource.
	NodeVulnerability,
}

// RelType is a relationship type — matches the Neo4j relationship label.
type RelType string

// Canonical relationship types for v1.0. Same compatibility rules as labels.
const (
	RelAssumedBy     RelType = "ASSUMED_BY"
	RelHasPermission RelType = "HAS_PERMISSION"
	RelGrants        RelType = "GRANTS"
	RelOwns          RelType = "OWNS"
	RelConfiguredAs  RelType = "CONFIGURED_AS"
	RelDeployedFrom  RelType = "DEPLOYED_FROM"
	RelAccesses      RelType = "ACCESSES"
	RelPeerOf        RelType = "PEER_OF"
	RelTriggered     RelType = "TRIGGERED"
	RelOccurredOn    RelType = "OCCURRED_ON"
	RelMemberOf      RelType = "MEMBER_OF"
	RelDeploys       RelType = "DEPLOYS"
	RelReadsFrom     RelType = "READS_FROM"
	RelWritesTo      RelType = "WRITES_TO"
	// RelEffectivePermission is the cached output of the T3.2 resolver —
	// materialised by `services/api/app/services/effective_permissions/`
	// rather than by the ingest writer itself. Listed here so it travels
	// with the canonical vocabulary and so the schema drift gate keeps the
	// YAML, the Go enums, and the live database in lockstep.
	RelEffectivePermission RelType = "EFFECTIVE_PERMISSION"

	// ── v1.1: identity depth ──────────────────────────────────────────
	// Employee -> Identity. One person, many accounts: corporate SSO, a
	// break-glass admin, a personal-looking service account. Joining them
	// is what makes "this user also did X in another system" answerable.
	RelAuthenticatesAs RelType = "AUTHENTICATES_AS"
	RelBelongsTo       RelType = "BELONGS_TO" // Employee -> Department
	RelManages         RelType = "MANAGES"    // Employee -> Employee

	// ── v1.1: asset depth ─────────────────────────────────────────────
	RelAffectedBy RelType = "AFFECTED_BY" // Resource -> Vulnerability
	RelRuns       RelType = "RUNS"        // Resource -> Application

	// ── v1.1: cloud depth ─────────────────────────────────────────────
	RelInAccount RelType = "IN_ACCOUNT" // Resource -> CloudAccount
	RelStores    RelType = "STORES"     // Resource -> Secret

	// ── v1.1: business depth ──────────────────────────────────────────
	// Application -> Employee. Who is accountable for the service, which
	// is who an escalation actually goes to.
	RelOwnedBy RelType = "OWNED_BY"

	// ── v1.1: threat depth ────────────────────────────────────────────
	RelObservedIOC   RelType = "OBSERVED_IOC"   // Alert -> IOC
	RelIndicates     RelType = "INDICATES"      // IOC -> Malware
	RelPartOf        RelType = "PART_OF"        // Malware -> Campaign
	RelAttributedTo  RelType = "ATTRIBUTED_TO"  // Campaign -> ThreatActor
	RelUsesTechnique RelType = "USES_TECHNIQUE" // Malware|ThreatActor -> Technique
	RelMapsTo        RelType = "MAPS_TO"        // Alert|Detection -> Technique
	RelInTactic      RelType = "IN_TACTIC"      // Technique -> Tactic
)

// AllRelTypes is the canonical, ordered enumeration of v1.0 relationships.
var AllRelTypes = []RelType{
	RelAssumedBy,
	RelHasPermission,
	RelGrants,
	RelOwns,
	RelConfiguredAs,
	RelDeployedFrom,
	RelAccesses,
	RelPeerOf,
	RelTriggered,
	RelOccurredOn,
	RelMemberOf,
	RelDeploys,
	RelReadsFrom,
	RelWritesTo,
	RelEffectivePermission,
	RelAuthenticatesAs,
	RelBelongsTo,
	RelManages,
	RelAffectedBy,
	RelRuns,
	RelInAccount,
	RelStores,
	RelOwnedBy,
	RelObservedIOC,
	RelIndicates,
	RelPartOf,
	RelAttributedTo,
	RelUsesTechnique,
	RelMapsTo,
	RelInTactic,
}

// ChangeType describes a graph mutation that downstream consumers want to
// react to. Published on the “security.graph_updates“ topic so the realtime
// service (T1.4) can stream into the UI without re-querying Neo4j.
type ChangeType string

const (
	ChangeUpsertNode ChangeType = "upsert_node"
	ChangeUpsertEdge ChangeType = "upsert_edge"
)
