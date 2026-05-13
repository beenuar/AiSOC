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
// pin against a stable contract. Bumping ``SchemaVersion`` is a breaking
// signal: it means the graph writer is producing a new shape and downstream
// consumers must opt in.
package graph

// SchemaVersion is the identifier stamped on every node and event-edge. It
// lets downstream services pin to a known shape and lets us migrate without
// breaking older queries — a query that needs the v1.0 vocabulary can filter
// on `schema_version = "v1.0"`.
//
// IMPORTANT: bump this any time the canonical node/edge enums below change.
// Keep the format ``vMAJOR.MINOR``.
const SchemaVersion = "v1.0"

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
}

// RelType is a relationship type — matches the Neo4j relationship label.
type RelType string

// Canonical relationship types for v1.0. Same compatibility rules as labels.
const (
	RelAssumedBy            RelType = "ASSUMED_BY"
	RelHasPermission        RelType = "HAS_PERMISSION"
	RelGrants               RelType = "GRANTS"
	RelOwns                 RelType = "OWNS"
	RelConfiguredAs         RelType = "CONFIGURED_AS"
	RelDeployedFrom         RelType = "DEPLOYED_FROM"
	RelAccesses             RelType = "ACCESSES"
	RelPeerOf               RelType = "PEER_OF"
	RelTriggered            RelType = "TRIGGERED"
	RelOccurredOn           RelType = "OCCURRED_ON"
	RelMemberOf             RelType = "MEMBER_OF"
	RelDeploys              RelType = "DEPLOYS"
	RelReadsFrom            RelType = "READS_FROM"
	RelWritesTo             RelType = "WRITES_TO"
	// RelEffectivePermission is the cached output of the T3.2 resolver —
	// materialised by `services/api/app/services/effective_permissions/`
	// rather than by the ingest writer itself. Listed here so it travels
	// with the canonical vocabulary and so the schema drift gate keeps the
	// YAML, the Go enums, and the live database in lockstep.
	RelEffectivePermission RelType = "EFFECTIVE_PERMISSION"
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
}

// ChangeType describes a graph mutation that downstream consumers want to
// react to. Published on the ``security.graph_updates`` topic so the realtime
// service (T1.4) can stream into the UI without re-querying Neo4j.
type ChangeType string

const (
	ChangeUpsertNode ChangeType = "upsert_node"
	ChangeUpsertEdge ChangeType = "upsert_edge"
)
