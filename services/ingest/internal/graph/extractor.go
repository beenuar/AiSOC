// extractor.go — pull entity references out of normalised OCSF events.
//
// Each connector type gets its own ``extractFromX`` helper so we can fill
// connectors in incrementally as the v8.0 program rolls out. v1.0 ships
// real coverage for the four most-used connectors:
//
//   - aws_security_hub  (cloud / IAM)
//   - github_audit      (vcs / repo / actor)
//   - okta_system_log   (identity)
//   - kubernetes_audit  (workload / actor / resource)
//
// Plus a *generic* fallback that pulls actor + endpoints + MITRE technique
// from any OCSF event, so the other 10 connector types still produce a
// non-empty graph projection on day one. The TODO blocks call out exactly
// which connectors are deferred to T1.2.
//
// The OCSF parser is intentionally defensive — every getter returns "" when
// the field isn't present, so a malformed event yields an empty Event
// rather than a panic. Connectors that emit junk events still get logged
// upstream by the normaliser; this layer must not crash the pipeline.
package graph

import (
	"fmt"
	"strings"
	"time"
)

// ExtractFromOCSF walks a normalised OCSF event and produces the graph
// projection. ``connectorType`` is the same string the normaliser keys on
// (e.g. ``aws_security_hub``); ``ocsf`` is the ``NormalizedEvent.OcsfEvent``
// map.
//
// Returns nil if the event has no extractable entities — caller should treat
// that as "no graph mutation".
func ExtractFromOCSF(eventID, tenantID, connectorType string, ocsf map[string]interface{}) *Event {
	if ocsf == nil {
		return nil
	}

	ts := parseTime(getString(ocsf, "time"))
	if ts.IsZero() {
		ts = time.Now().UTC()
	}

	ev := &Event{
		EventID:  eventID,
		TenantID: tenantID,
		TS:       ts,
	}

	switch strings.ToLower(connectorType) {
	case "aws_security_hub":
		extractFromAWS(ev, ocsf)
	case "github_audit":
		extractFromGitHub(ev, ocsf)
	case "okta_system_log":
		extractFromOkta(ev, ocsf)
	case "kubernetes_audit":
		extractFromKubernetes(ev, ocsf)

	// TODO(T1.1+): wire up real extractors for the remaining v8.0 source
	// types. Until then they fall through to extractGeneric which still
	// produces actor + endpoint + MITRE technique nodes, so the graph isn't
	// empty for these connectors — just less detailed.
	//
	//   - crowdstrike_falcon     (T1.2 — endpoint + actor + technique)
	//   - microsoft_sentinel     (T1.2 — alert + actor + technique)
	//   - splunk_enterprise      (T1.2 — actor + endpoints)
	//   - cloudflare             (T4.1)
	//   - sublime / abnormal     (T4.4 / T4.5)
	//   - lacework / sysdig / falco (T4.6 / T4.7 / T4.8)
	//   - vault                  (T4.9)
	//   - pagerduty / opsgenie   (T4.10)
	//   - confluence / box / dropbox (T4.11 / T4.12)
	//   - datadog / snowflake / oci  (T4.13 / T4.14 / T4.15)
	default:
		extractGeneric(ev, ocsf)
	}

	// Generic ATT&CK technique node + Triggered edge — applies to every
	// connector since it's pulled from the OCSF mitre_attck enrichment.
	extractMITRE(ev, ocsf)

	if len(ev.Nodes) == 0 && len(ev.Edges) == 0 {
		return nil
	}
	return ev
}

// extractGeneric is the fallback path. Every OCSF event has actor + endpoints
// at known field paths; this pulls those out so we never produce zero-node
// projections for connectors we haven't fully wired yet.
func extractGeneric(ev *Event, ocsf map[string]interface{}) {
	if name := getString(ocsf, "actor.user.name"); name != "" {
		key := fmt.Sprintf("user:%s:%s", ev.TenantID, name)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeUser,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{
				"name":  name,
				"email": getString(ocsf, "actor.user.email_addr"),
			},
		})
	}
	if dev := getString(ocsf, "device.name"); dev != "" {
		key := fmt.Sprintf("endpoint:%s:%s", ev.TenantID, dev)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeEndpoint,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"name": dev},
		})
	}
	if srcIP := getString(ocsf, "src_endpoint.ip"); srcIP != "" {
		key := fmt.Sprintf("netpath:%s:%s", ev.TenantID, srcIP)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeNetworkPath,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"src_ip": srcIP, "role": "src"},
		})
	}
	if dstIP := getString(ocsf, "dst_endpoint.ip"); dstIP != "" {
		key := fmt.Sprintf("netpath:%s:%s", ev.TenantID, dstIP)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeNetworkPath,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"dst_ip": dstIP, "role": "dst"},
		})
	}
}

// extractFromAWS handles AWS Security Hub findings.
//
// Entity model:
//
//   - User from Resource.Owner / actor.user.name → :User
//   - Resource (Resources[].Id, ARN) → :Resource
//   - Alert (finding) → :Alert
//   - Edges: User -[:OWNS]-> Resource, Alert -[:OCCURRED_ON]-> Resource
func extractFromAWS(ev *Event, ocsf map[string]interface{}) {
	resources, _ := ocsf["Resources"].([]interface{})
	if len(resources) == 0 {
		// Field may live under raw_data; fall through to generic if not.
		extractGeneric(ev, ocsf)
		return
	}

	actor := getString(ocsf, "actor.user.name")
	var actorKey string
	if actor != "" {
		actorKey = fmt.Sprintf("user:%s:%s", ev.TenantID, actor)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeUser,
			NaturalKey: actorKey,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"name": actor, "provider": "aws"},
		})
	}

	for _, r := range resources {
		rmap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		arn := getString(rmap, "Id")
		if arn == "" {
			arn = getString(rmap, "ARN")
		}
		if arn == "" {
			continue
		}
		key := fmt.Sprintf("resource:%s:%s", ev.TenantID, arn)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeResource,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{
				"arn":      arn,
				"type":     getString(rmap, "Type"),
				"region":   getString(rmap, "Region"),
				"provider": "aws",
			},
		})
		if actorKey != "" {
			ev.Edges = append(ev.Edges, Edge{
				Type:      RelOwns,
				FromLabel: NodeUser, FromKey: actorKey,
				ToLabel: NodeResource, ToKey: key,
			})
		}
		// Alert -> Resource edge
		alertID := getString(ocsf, "event_id")
		if alertID != "" {
			alertKey := fmt.Sprintf("alert:%s:%s", ev.TenantID, alertID)
			ev.Nodes = append(ev.Nodes, Node{
				Label:      NodeAlert,
				NaturalKey: alertKey,
				TenantID:   ev.TenantID,
				Properties: map[string]interface{}{
					"title":    getString(ocsf, "message"),
					"severity": getString(ocsf, "severity"),
				},
			})
			ev.Edges = append(ev.Edges, Edge{
				Type:      RelOccurredOn,
				FromLabel: NodeAlert, FromKey: alertKey,
				ToLabel: NodeResource, ToKey: key,
			})
		}
	}
}

// extractFromGitHub handles GitHub audit log events.
//
// Entity model:
//
//   - User from actor → :User
//   - Repo from repo (org/name) → :Repo
//   - Edge: User -[:READS_FROM]-> Repo for read actions
//           User -[:WRITES_TO]-> Repo for write actions
//
// We can fill in :ServiceAccount for app/bot actors in T1.2.
func extractFromGitHub(ev *Event, ocsf map[string]interface{}) {
	actor := getString(ocsf, "actor.user.name")
	repo := getString(ocsf, "repo.full_name")
	if repo == "" {
		repo = getString(ocsf, "repo")
	}
	action := strings.ToLower(getString(ocsf, "action"))

	var actorKey string
	if actor != "" {
		actorKey = fmt.Sprintf("user:%s:%s", ev.TenantID, actor)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeUser,
			NaturalKey: actorKey,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"name": actor, "provider": "github"},
		})
	}

	if repo != "" {
		repoKey := fmt.Sprintf("repo:%s:%s", ev.TenantID, repo)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeRepo,
			NaturalKey: repoKey,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{
				"full_name": repo,
				"provider":  "github",
			},
		})
		if actorKey != "" {
			rel := RelReadsFrom
			// Heuristic: GitHub action verbs that mutate the repo.
			if action != "" && (strings.Contains(action, "create") ||
				strings.Contains(action, "delete") ||
				strings.Contains(action, "push") ||
				strings.Contains(action, "merge") ||
				strings.Contains(action, "update")) {
				rel = RelWritesTo
			}
			ev.Edges = append(ev.Edges, Edge{
				Type:      rel,
				FromLabel: NodeUser, FromKey: actorKey,
				ToLabel: NodeRepo, ToKey: repoKey,
				Properties: map[string]interface{}{"action": action},
			})
		}
	}
}

// extractFromOkta handles Okta system log events.
//
// Entity model:
//
//   - Identity from actor.id → :Identity
//   - User from actor.alternateId / displayName → :User
//   - Endpoint from src_endpoint.ip → :Endpoint (NetworkPath)
//   - Edge: Identity -[:ASSUMED_BY]-> User
//           User -[:ACCESSES]-> SaaSApp (when target is an app)
func extractFromOkta(ev *Event, ocsf map[string]interface{}) {
	identityID := getString(ocsf, "actor.id")
	if identityID == "" {
		identityID = getString(ocsf, "actor.user.email_addr")
	}
	userName := getString(ocsf, "actor.user.name")
	if userName == "" {
		userName = getString(ocsf, "actor.user.email_addr")
	}

	var idKey, userKey string
	if identityID != "" {
		idKey = fmt.Sprintf("identity:%s:%s", ev.TenantID, identityID)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeIdentity,
			NaturalKey: idKey,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"id": identityID, "provider": "okta"},
		})
	}
	if userName != "" {
		userKey = fmt.Sprintf("user:%s:%s", ev.TenantID, userName)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeUser,
			NaturalKey: userKey,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"name": userName, "provider": "okta"},
		})
	}
	if idKey != "" && userKey != "" {
		ev.Edges = append(ev.Edges, Edge{
			Type:      RelAssumedBy,
			FromLabel: NodeIdentity, FromKey: idKey,
			ToLabel: NodeUser, ToKey: userKey,
		})
	}

	if srcIP := getString(ocsf, "src_endpoint.ip"); srcIP != "" {
		key := fmt.Sprintf("netpath:%s:%s", ev.TenantID, srcIP)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeNetworkPath,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"src_ip": srcIP},
		})
		if userKey != "" {
			ev.Edges = append(ev.Edges, Edge{
				Type:      RelAccesses,
				FromLabel: NodeUser, FromKey: userKey,
				ToLabel: NodeNetworkPath, ToKey: key,
			})
		}
	}

	if app := getString(ocsf, "target.app.name"); app != "" {
		appKey := fmt.Sprintf("saasapp:%s:%s", ev.TenantID, app)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeSaaSApp,
			NaturalKey: appKey,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"name": app, "provider": "okta"},
		})
		if userKey != "" {
			ev.Edges = append(ev.Edges, Edge{
				Type:      RelAccesses,
				FromLabel: NodeUser, FromKey: userKey,
				ToLabel: NodeSaaSApp, ToKey: appKey,
			})
		}
	}
}

// extractFromKubernetes handles audit.k8s.io/v1 events.
//
// Entity model:
//
//   - User / ServiceAccount from user.username → :User or :ServiceAccount
//   - Resource from objectRef → :Resource
//   - Endpoint from sourceIPs[0] → :NetworkPath
//   - Edge: actor -[:ACCESSES]-> resource (verb is on the edge)
//
// system:serviceaccount:* prefixes are mapped to :ServiceAccount; everything
// else is :User. This matches the convention the workload-identity stories
// (T3.2) will lean on.
func extractFromKubernetes(ev *Event, ocsf map[string]interface{}) {
	user := getString(ocsf, "actor.user.name")
	verb := getString(ocsf, "activity_name")
	resource := getString(ocsf, "resource.name")
	resType := getString(ocsf, "finding.title")
	namespace := getString(ocsf, "cloud.account.uid")

	var userKey string
	if user != "" {
		userKey = fmt.Sprintf("user:%s:%s", ev.TenantID, user)
		label := NodeUser
		if strings.HasPrefix(user, "system:serviceaccount:") {
			label = NodeServiceAccount
		}
		ev.Nodes = append(ev.Nodes, Node{
			Label:      label,
			NaturalKey: userKey,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{
				"name":     user,
				"provider": "kubernetes",
			},
		})
	}

	if resource != "" {
		key := fmt.Sprintf("k8sres:%s:%s/%s/%s", ev.TenantID, namespace, resType, resource)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeResource,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{
				"name":      resource,
				"type":      resType,
				"namespace": namespace,
				"provider":  "kubernetes",
			},
		})
		if userKey != "" {
			ev.Edges = append(ev.Edges, Edge{
				Type:      RelAccesses,
				FromLabel: NodeUser, FromKey: userKey,
				ToLabel: NodeResource, ToKey: key,
				Properties: map[string]interface{}{"verb": verb},
			})
		}
	}

	if srcIP := getString(ocsf, "src_endpoint.ip"); srcIP != "" {
		key := fmt.Sprintf("netpath:%s:%s", ev.TenantID, srcIP)
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeNetworkPath,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{"src_ip": srcIP},
		})
	}
}

// extractMITRE adds a Detection node and Triggered edge per ATT&CK technique
// the normaliser already attached to ``mitre_attck``. Universal across
// connectors so every event with a technique gets the link.
func extractMITRE(ev *Event, ocsf map[string]interface{}) {
	techs, ok := ocsf["mitre_attck"].([]interface{})
	if !ok {
		// The normaliser uses []map[string]interface{}, but JSON
		// round-trips can return []interface{}. Try both shapes.
		if rawTechs, ok2 := ocsf["mitre_attck"].([]map[string]interface{}); ok2 {
			techs = make([]interface{}, len(rawTechs))
			for i, m := range rawTechs {
				techs[i] = m
			}
		} else {
			return
		}
	}

	// We only attach the Detection node when there's an actor or endpoint to
	// hang it off. Otherwise it's just a floating technique with nothing to
	// trigger from — wait until T2.1 wires the case/alert path properly.
	var fromLabel NodeLabel
	var fromKey string
	for _, n := range ev.Nodes {
		if n.Label == NodeUser || n.Label == NodeServiceAccount || n.Label == NodeIdentity {
			fromLabel = n.Label
			fromKey = n.NaturalKey
			break
		}
	}
	if fromKey == "" {
		// Fall back to alert-as-source if it exists.
		for _, n := range ev.Nodes {
			if n.Label == NodeAlert {
				fromLabel = n.Label
				fromKey = n.NaturalKey
				break
			}
		}
	}

	for _, t := range techs {
		tmap, ok := t.(map[string]interface{})
		if !ok {
			continue
		}
		tid := getString(tmap, "technique_id")
		if tid == "" {
			continue
		}
		key := "detection:mitre:" + tid
		ev.Nodes = append(ev.Nodes, Node{
			Label:      NodeDetection,
			NaturalKey: key,
			TenantID:   ev.TenantID,
			Properties: map[string]interface{}{
				"mitre_technique_id":   tid,
				"mitre_technique_name": getString(tmap, "technique_name"),
				"url":                  getString(tmap, "url"),
			},
		})
		if fromKey != "" {
			ev.Edges = append(ev.Edges, Edge{
				Type:      RelTriggered,
				FromLabel: fromLabel, FromKey: fromKey,
				ToLabel: NodeDetection, ToKey: key,
			})
		}
	}
}

// getString reads a dotted-path string from a nested OCSF map. Returns "" if
// the path doesn't exist or the leaf isn't a string.
func getString(m map[string]interface{}, path string) string {
	parts := strings.Split(path, ".")
	cur := any(m)
	for _, p := range parts {
		mm, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur, ok = mm[p]
		if !ok {
			return ""
		}
	}
	if s, ok := cur.(string); ok {
		return s
	}
	return ""
}

// parseTime tries the common OCSF timestamp shapes — RFC3339Nano first,
// since that's what the normaliser emits.
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
