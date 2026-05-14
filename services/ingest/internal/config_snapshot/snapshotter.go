// snapshotter.go — capture per-event resource configurations.
//
// T1.2 (v8.0) extends the T1.1 ingest-side graph writer: every event that
// names a resource gets the resource's *configuration at event-time*
// attached as a versioned :Configuration node connected via
// ``:CONFIGURED_AS {ts}``. The whole point is "what did this S3 bucket /
// IAM policy / GitHub repo look like the moment the alert fired", which is
// the difference between "the bucket is public NOW" (boring) and "the bucket
// was made public 90 seconds before the data exfil" (incident-defining).
//
// Architecture:
//
//	┌──── ingest ────┐    ┌── snapshotter ──┐    ┌── connectors ──┐
//	│ event lands    │───▶│ ResourcesFromEvent │ │ aws_security_hub │
//	│ graph extracts │    │   for each         │ │ github / okta /  │
//	│  :Resource     │    │   Configuration =  │ │ azure / gcp ...  │
//	└────────────────┘    │   provider.Get(    │ │ get_resource_     │
//	                      │    id, ts)         │ │ config(id, ts)    │
//	                      │                    │◀┘                   │
//	                      │   cache.Set(...)   │
//	                      │   ev.Nodes += :Configuration              │
//	                      │   ev.Edges += :CONFIGURED_AS              │
//	                      └────────────────────┘
//
// Two pluggable seams:
//
//   - ``Provider``: how the snapshotter actually fetches the config.
//     Production wires an HTTP provider that calls the connectors service.
//     Tests wire ``StaticProvider`` with a fixture map.
//
//   - ``Cache``: how snapshots are remembered between events. See cache.go.
//
// Failure isolation: a Provider error is logged + the snapshot is skipped.
// The graph writer still upserts the underlying :Resource node, so the
// ingest pipeline NEVER stalls on a bad config lookup.
//
// AiSOC — open-source AI Security Operations Center (MIT License)
package config_snapshot

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync/atomic"
	"time"

	"github.com/beenuar/aisoc/services/ingest/internal/graph"
	"github.com/rs/zerolog/log"
)

// ErrNotImplemented is the sentinel returned by Provider implementations
// that don't (yet) support a given connector. Mirrors the Python
// ``BaseConnector.get_resource_config`` default. The snapshotter treats
// this as a soft skip — no error counter, no log spam.
var ErrNotImplemented = errors.New("snapshot: get_resource_config not implemented")

// Provider fetches a resource's configuration at event time.
//
// Implementations MUST honor ``ctx`` deadlines aggressively: the
// snapshotter sits on the graph flush path and a slow provider would push
// back on the writer queue.
type Provider interface {
	GetResourceConfig(
		ctx context.Context,
		connectorID string,
		resourceID string,
		ts time.Time,
	) (map[string]interface{}, error)
}

// StaticProvider is the test-friendly Provider. Configs are keyed by
// ``connectorID + resourceID``; entries can be time-ordered to model
// configuration history (the AWS Config-style fixture).
type StaticProvider struct {
	// Configs is the per-connector resource config history. The history
	// MUST be sorted by Recorded ascending; ``GetResourceConfig`` returns
	// the most recent entry whose Recorded <= ts.
	Configs map[string]map[string][]ConfigSnapshot
}

// ConfigSnapshot is one point-in-time configuration. ``Recorded`` is when
// the config took effect; ``Data`` is the connector-specific payload.
type ConfigSnapshot struct {
	Recorded time.Time
	Data     map[string]interface{}
}

// NewStaticProvider builds a fixture-driven provider. Useful in tests and
// in single-tenant deployments that want to seed a known-good config set.
func NewStaticProvider(seed map[string]map[string][]ConfigSnapshot) *StaticProvider {
	if seed == nil {
		seed = map[string]map[string][]ConfigSnapshot{}
	}
	for _, byResource := range seed {
		for id := range byResource {
			sort.Slice(byResource[id], func(i, j int) bool {
				return byResource[id][i].Recorded.Before(byResource[id][j].Recorded)
			})
		}
	}
	return &StaticProvider{Configs: seed}
}

// GetResourceConfig returns the configuration that was effective at ts.
// Falls through to ErrNotImplemented if the connector has no fixture data,
// matching the BaseConnector contract.
func (p *StaticProvider) GetResourceConfig(_ context.Context, connectorID, resourceID string, ts time.Time) (map[string]interface{}, error) {
	byResource, ok := p.Configs[connectorID]
	if !ok {
		return nil, ErrNotImplemented
	}
	history, ok := byResource[resourceID]
	if !ok || len(history) == 0 {
		return nil, ErrNotImplemented
	}
	// Walk newest → oldest, return first entry recorded at-or-before ts.
	for i := len(history) - 1; i >= 0; i-- {
		if !history[i].Recorded.After(ts) {
			return cloneMap(history[i].Data), nil
		}
	}
	// All recorded configs are *after* ts — return the earliest, which is
	// still our best estimate of "what this resource looked like".
	return cloneMap(history[0].Data), nil
}

// HTTPProvider calls the connectors service over HTTP.
//
// Endpoint contract:
//
//	GET {BaseURL}/v1/connectors/{connector_id}/resource-config?
//	      resource_id={resource_id}&ts={rfc3339}
//
// 200 JSON body                → return as map
// 404 / 501 / "not_implemented" → ErrNotImplemented (soft skip)
// other non-2xx                 → error (snapshotter logs + skips)
type HTTPProvider struct {
	BaseURL string
	Client  *http.Client
}

// NewHTTPProvider constructs the production provider. ``timeout`` caps each
// round-trip — defaults to 1.5s if non-positive (matches
// AISOC_SNAPSHOT_PROVIDER_TIMEOUT_MS).
func NewHTTPProvider(baseURL string, timeout time.Duration) *HTTPProvider {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	return &HTTPProvider{
		BaseURL: baseURL,
		Client:  &http.Client{Timeout: timeout},
	}
}

func (p *HTTPProvider) GetResourceConfig(ctx context.Context, connectorID, resourceID string, ts time.Time) (map[string]interface{}, error) {
	if p.BaseURL == "" {
		return nil, ErrNotImplemented
	}
	url := fmt.Sprintf(
		"%s/v1/connectors/%s/resource-config?resource_id=%s&ts=%s",
		p.BaseURL, connectorID, resourceID, ts.UTC().Format(time.RFC3339),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	switch {
	case resp.StatusCode == http.StatusOK:
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
		var out map[string]interface{}
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, err
		}
		return out, nil
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusNotImplemented:
		return nil, ErrNotImplemented
	default:
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snapshot provider: HTTP %d: %s", resp.StatusCode, string(body))
	}
}

// Snapshotter attaches Configuration nodes + CONFIGURED_AS edges to events
// before the graph writer flushes them. Construct one per ingest pod.
type Snapshotter struct {
	provider Provider
	cache    Cache
	ttl      time.Duration

	// metrics — atomic counters surfaced for tests and the Prometheus
	// collector.
	hits        atomic.Uint64
	misses      atomic.Uint64
	errors      atomic.Uint64
	skipped     atomic.Uint64
	attached    atomic.Uint64
}

// Config wires the snapshotter at construction time.
type Config struct {
	Provider Provider
	Cache    Cache
	TTL      time.Duration
}

// New constructs a Snapshotter. A nil provider is rejected — callers should
// pass a NoopProvider if they really want snapshots disabled. A nil cache
// is auto-replaced with an in-memory cache so the snapshotter still
// deduplicates within a single pod.
func New(cfg Config) (*Snapshotter, error) {
	if cfg.Provider == nil {
		return nil, errors.New("snapshot: Provider is required")
	}
	if cfg.Cache == nil {
		cfg.Cache = NewMemoryCache(cfg.TTL)
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	return &Snapshotter{
		provider: cfg.Provider,
		cache:    cfg.Cache,
		ttl:      cfg.TTL,
	}, nil
}

// Stats is a snapshot of internal counters.
type Stats struct {
	Hits     uint64
	Misses   uint64
	Errors   uint64
	Skipped  uint64
	Attached uint64
}

// Stats returns the current counters.
func (s *Snapshotter) Stats() Stats {
	return Stats{
		Hits:     s.hits.Load(),
		Misses:   s.misses.Load(),
		Errors:   s.errors.Load(),
		Skipped:  s.skipped.Load(),
		Attached: s.attached.Load(),
	}
}

// Close releases the cache. Safe to call multiple times.
func (s *Snapshotter) Close() error {
	return s.cache.Close()
}

// resourceRef is the minimal info the snapshotter needs about a resource
// in the graph projection: the natural key (so we can hang the
// :CONFIGURED_AS edge off it) and the connector-native id (which is what
// the connector's get_resource_config wants).
type resourceRef struct {
	NaturalKey  string
	ResourceID  string
	ConnectorID string
}

// Apply walks ev.Nodes for :Resource entries, fetches the live config, and
// appends a :Configuration node + :CONFIGURED_AS edge for every
// successful lookup. ev.SnapshotID is populated with a stable digest when
// at least one configuration was attached, so downstream consumers can
// dedupe on it.
//
// Failure isolation: any error from the provider is logged + counted +
// skipped. The graph writer's other nodes/edges still flush.
func (s *Snapshotter) Apply(ctx context.Context, ev *graph.Event) {
	if ev == nil || len(ev.Nodes) == 0 {
		return
	}
	connectorID := connectorIDForEvent(ev)
	if connectorID == "" {
		return
	}
	refs := resourceRefsFromEvent(ev, connectorID)
	if len(refs) == 0 {
		return
	}

	digestParts := make([]string, 0, len(refs))
	for _, ref := range refs {
		cfg, source := s.fetch(ctx, ref, ev.TS)
		if cfg == nil {
			continue
		}
		s.attached.Add(1)
		switch source {
		case "cache":
			s.hits.Add(1)
		case "provider":
			s.misses.Add(1)
		}

		configKey := configurationKey(ev.TenantID, ref.NaturalKey, ev.TS, s.ttl)
		props := map[string]interface{}{
			"resource_natural_key": ref.NaturalKey,
			"resource_id":          ref.ResourceID,
			"connector_id":         connectorID,
			"recorded_at":          ev.TS.UTC().Format(time.RFC3339Nano),
			"config":               cfg,
			"source":               source,
		}
		ev.Nodes = append(ev.Nodes, graph.Node{
			Label:      graph.NodeConfiguration,
			NaturalKey: configKey,
			TenantID:   ev.TenantID,
			Properties: props,
		})
		ev.Edges = append(ev.Edges, graph.Edge{
			Type:      graph.RelConfiguredAs,
			FromLabel: graph.NodeResource, FromKey: ref.NaturalKey,
			ToLabel: graph.NodeConfiguration, ToKey: configKey,
			Properties: map[string]interface{}{
				"ts":           ev.TS.UTC().Format(time.RFC3339Nano),
				"connector_id": connectorID,
			},
		})
		digestParts = append(digestParts, configKey)
	}

	if len(digestParts) > 0 && ev.SnapshotID == "" {
		sort.Strings(digestParts)
		h := sha256.Sum256([]byte(fmt.Sprintf("%v", digestParts)))
		ev.SnapshotID = hex.EncodeToString(h[:8])
	}
}

// fetch returns (config, source). source is one of "cache", "provider", or
// "" if no config was retrieved.
func (s *Snapshotter) fetch(ctx context.Context, ref resourceRef, ts time.Time) (map[string]interface{}, string) {
	key := CacheKey(ref.ConnectorID, ref.ResourceID, ts, s.ttl)
	if v, ok, err := s.cache.Get(ctx, key); err == nil && ok {
		return v, "cache"
	}
	cfg, err := s.provider.GetResourceConfig(ctx, ref.ConnectorID, ref.ResourceID, ts)
	if err != nil {
		if errors.Is(err, ErrNotImplemented) {
			s.skipped.Add(1)
			return nil, ""
		}
		s.errors.Add(1)
		log.Debug().Err(err).
			Str("connector_id", ref.ConnectorID).
			Str("resource_id", ref.ResourceID).
			Msg("snapshot: provider lookup failed")
		return nil, ""
	}
	if cfg == nil {
		s.skipped.Add(1)
		return nil, ""
	}
	if setErr := s.cache.Set(ctx, key, cfg); setErr != nil {
		log.Debug().Err(setErr).Str("key", key).Msg("snapshot: cache set failed")
	}
	return cfg, "provider"
}

// resourceRefsFromEvent returns the :Resource nodes already extracted by
// the T1.1 extractor, paired with the connector-native id we'll feed to
// get_resource_config. Detection / Alert / Identity / etc. nodes are
// ignored — only :Resource gets a snapshot.
func resourceRefsFromEvent(ev *graph.Event, connectorID string) []resourceRef {
	out := make([]resourceRef, 0, len(ev.Nodes))
	seen := make(map[string]struct{}, len(ev.Nodes))
	for _, n := range ev.Nodes {
		if n.Label != graph.NodeResource && n.Label != graph.NodeRepo &&
			n.Label != graph.NodeSaaSApp && n.Label != graph.NodeServiceAccount {
			continue
		}
		if _, dup := seen[n.NaturalKey]; dup {
			continue
		}
		seen[n.NaturalKey] = struct{}{}
		// resource_id is the connector-native identifier. Different node
		// shapes hold it in different property names — this picks the
		// first one that's present.
		id := getStringProp(n.Properties, "arn")
		if id == "" {
			id = getStringProp(n.Properties, "full_name")
		}
		if id == "" {
			id = getStringProp(n.Properties, "id")
		}
		if id == "" {
			id = getStringProp(n.Properties, "name")
		}
		if id == "" {
			continue
		}
		out = append(out, resourceRef{
			NaturalKey:  n.NaturalKey,
			ResourceID:  id,
			ConnectorID: connectorID,
		})
	}
	return out
}

// connectorIDForEvent looks at any :Resource / :Repo / :SaaSApp / :User
// node and returns the ``provider`` property the extractor stamps. That's
// the connector_id the snapshotter dispatches on.
//
// Falls back to the first :Resource's connector hint, or "" if no node
// exposes one.
func connectorIDForEvent(ev *graph.Event) string {
	for _, n := range ev.Nodes {
		if p := getStringProp(n.Properties, "provider"); p != "" {
			return p
		}
	}
	return ""
}

func getStringProp(m map[string]interface{}, k string) string {
	if v, ok := m[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// configurationKey builds the natural key used for the :Configuration
// node. The TTL bucket means rapid-fire events against the same resource
// MERGE onto a single Configuration node — exactly the dedup behavior we
// want for hot resources.
func configurationKey(tenantID, resourceKey string, ts time.Time, ttl time.Duration) string {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	bucket := ts.UTC().Truncate(ttl).Format(time.RFC3339)
	h := sha256.Sum256([]byte(resourceKey + ":" + bucket))
	return fmt.Sprintf("config:%s:%s", tenantID, hex.EncodeToString(h[:8]))
}

// NoopProvider returns ErrNotImplemented for everything. Use this when the
// snapshotter is wired but no real provider is configured (e.g. in
// integration tests that don't exercise T1.2).
type NoopProvider struct{}

// GetResourceConfig always returns ErrNotImplemented.
func (NoopProvider) GetResourceConfig(_ context.Context, _, _ string, _ time.Time) (map[string]interface{}, error) {
	return nil, ErrNotImplemented
}
