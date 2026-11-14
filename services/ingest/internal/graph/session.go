package graph

import (
	"strings"
	"time"
)

// The graph half of depth plan 2.4.
//
// Why this is a post-pass and not a line in each extractor
// ---------------------------------------------------------
// Same reason `applyActivityProperties` is: the session is a property of the
// event, not of the connector. Put it inside the five extractors and the
// sixth one somebody writes ships without it, and nobody notices until a
// traversal comes back missing sessions for one source.
//
// Why the graph is not the authority
// -----------------------------------
// ADR-0010. Neo4j measured 696.8 MiB resident for 20,000 sessions, which is
// 42.2% of what the CORE profile has left at the moment it is triaging an
// alert, so the authoritative session row is in Postgres and the graph keeps
// the nodes for `full`, where traversal is the point. The id below is the
// *same* deterministic uuid the Postgres row carries, computed from the same
// three parts by the fusion consumer and stamped onto the event before this
// runs — so the two stores agree without either waiting on the other.
//
// An event that reaches the graph without that stamp (a replay, or a
// deployment with the alert sink off) still gets a node keyed on the vendor's
// own value. That node is correct and joins to nothing, which is the honest
// outcome: the grouping is known and the row it would join to does not exist.

// applySessionGraph adds the Session node and its edges for one event.
//
// It reads `activity.session` and derives nothing. `session.go` in the
// activity package is the only producer of a session key; this is one of its
// three consumers, and `scripts/check_session_projection.py` fails the build
// if a second site starts deriving one.
func applySessionGraph(ev *Event, ocsf map[string]interface{}) {
	act, ok := ocsf["activity"].(map[string]interface{})
	if !ok {
		// The projection is a struct on the normalizer's own path and a map
		// once it has been through JSON. Both reach here depending on
		// whether the graph writer runs in-process or off the topic.
		act = structToMap(ocsf["activity"])
		if act == nil {
			return
		}
	}
	session := childMap(act, "session")
	if session == nil {
		return
	}

	key := strings.TrimSpace(asString(session["key"]))
	kind := strings.TrimSpace(asString(session["key_kind"]))
	if key == "" || kind == "" {
		// No vendor key and no derived one. An event with no session is a
		// real answer; inventing a node of one here would make "what else
		// did this session touch" answerable with a number that means
		// nothing.
		return
	}

	// The natural key is the vendor's own value namespaced by source, because
	// an Okta session id and a GitHub token hash share no namespace. The
	// Postgres uuid rides as a property rather than as the key: it is absent
	// on a replayed event, and a MERGE on an empty key would collapse every
	// such event onto one node.
	source := sessionSource(ocsf)
	natural := source + "|" + key

	props := map[string]interface{}{
		"session_key": key,
		"key_kind":    kind,
		"source":      source,
		// Written even when empty, for the same reason `actor_kind` is: a
		// Cypher `IS NULL` cannot tell "this deployment does not stamp ids"
		// from "this session has no row".
		"id":           strings.TrimSpace(asString(session["id"])),
		"last_seen_at": ev.TS.UTC().Format(time.RFC3339),
	}
	if v := strings.TrimSpace(asString(session["key_source"])); v != "" {
		props["key_source"] = v
	}
	if v := strings.TrimSpace(asString(session["principal"])); v != "" {
		props["principal"] = v
	}
	if v := strings.TrimSpace(asString(session["originating_human"])); v != "" {
		props["originating_human"] = v
	}

	ev.Nodes = append(ev.Nodes, Node{
		Label:      NodeSession,
		NaturalKey: natural,
		TenantID:   ev.TenantID,
		Properties: props,
	})

	// Identity -> Session. Attached to whichever principal node the
	// extractors already produced rather than to a new one, so the session
	// hangs off the same account every other edge in this event does.
	for _, node := range ev.Nodes {
		if node.Label != NodeUser && node.Label != NodeServiceAccount && node.Label != NodeIdentity {
			continue
		}
		ev.Edges = append(ev.Edges, Edge{
			Type:      RelOpenedSession,
			FromLabel: node.Label, FromKey: node.NaturalKey,
			ToLabel: NodeSession, ToKey: natural,
			Properties: map[string]interface{}{
				"ts":              ev.TS.UTC().Format(time.RFC3339),
				"source_event_id": ev.EventID,
				"snapshot_id":     ev.SnapshotID,
			},
		})
		break
	}

	// Session -> Session, the assumed-role chain. The edge exists on the
	// issuing STS call and nowhere else: the child's own events name only the
	// role it assumed, so once this record ages out of the lake the person
	// behind the second hop is unrecoverable. `link_source` records which
	// field established it, because a chain built from a caller-chosen
	// roleSessionName is weaker evidence than one built from sourceIdentity.
	issued := childMap(session, "issued")
	if issued == nil {
		return
	}
	childKey := strings.TrimSpace(asString(issued["key"]))
	if childKey == "" || childKey == key {
		return
	}
	childNatural := source + "|" + childKey

	childProps := map[string]interface{}{
		"session_key": childKey,
		// An issued credential is always the credential-that-is-the-session
		// kind; nothing else is handed out by an STS call.
		"key_kind": "vendor_credential",
		"source":   source,
	}
	if v := strings.TrimSpace(asString(issued["key_source"])); v != "" {
		childProps["key_source"] = v
	}
	if v := strings.TrimSpace(asString(issued["principal"])); v != "" {
		childProps["principal"] = v
	}
	if v := strings.TrimSpace(asString(issued["originating_human"])); v != "" {
		childProps["originating_human"] = v
	}
	ev.Nodes = append(ev.Nodes, Node{
		Label:      NodeSession,
		NaturalKey: childNatural,
		TenantID:   ev.TenantID,
		Properties: childProps,
	})
	ev.Edges = append(ev.Edges, Edge{
		Type:      RelIssuedSession,
		FromLabel: NodeSession, FromKey: natural,
		ToLabel: NodeSession, ToKey: childNatural,
		Properties: map[string]interface{}{
			"ts":              ev.TS.UTC().Format(time.RFC3339),
			"source_event_id": ev.EventID,
			"snapshot_id":     ev.SnapshotID,
			"link_source":     strings.TrimSpace(asString(issued["originating_human_source"])),
		},
	})
}

// sessionSource names the product the session belongs to, matching what the
// fusion store uses so the two agree on the namespace half of the key.
func sessionSource(ocsf map[string]interface{}) string {
	if v := getString(ocsf, "metadata.product.name"); v != "" {
		return v
	}
	if v := getString(ocsf, "connector_type"); v != "" {
		return v
	}
	return "unknown"
}

func asString(value interface{}) string {
	s, _ := value.(string)
	return s
}
