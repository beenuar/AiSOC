// Package aisocapi provides a lightweight HTTP client for the AiSOC API
// endpoints consumed by the osquery extension.
package aisocapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/beenuar/aisoc/osquery-extensions/internal/config"
)

// Client talks to the AiSOC API on behalf of the extension.
type Client struct {
	cfg    *config.Config
	http   *http.Client
}

// New returns a Client backed by cfg.
func New(cfg *config.Config) *Client {
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.HTTPTimeout},
	}
}

// ─── Response types ──────────────────────────────────────────────────────────

// PendingAction represents one HITL (human-in-the-loop) action awaiting
// approval for this host.
type PendingAction struct {
	ActionID    string `json:"action_id"`
	CaseID      string `json:"case_id"`
	ActionType  string `json:"action_type"`
	Target      string `json:"target"`
	RequestedBy string `json:"requested_by"`
	RequestedAt string `json:"requested_at"`
	ExpiresAt   string `json:"expires_at"`
	Description string `json:"description"`
}

// AlertCacheEntry is a recent alert for this host.
type AlertCacheEntry struct {
	AlertID  string `json:"alert_id"`
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	FiredAt  string `json:"fired_at"`
	Summary  string `json:"summary"`
	CaseID   string `json:"case_id"`
}

// PersistenceEntry is one item from the AiSOC persistence baseline for this
// host.  The extension joins this data against the live osquery tables.
type PersistenceEntry struct {
	EntryID   string `json:"entry_id"`
	Mechanism string `json:"mechanism"` // cron|systemd|launchd|registry_run|…
	Path      string `json:"path"`
	Arguments string `json:"arguments"`
	Approved  bool   `json:"approved"`
	MITRETech string `json:"mitre_technique"`
}

// ─── API methods ─────────────────────────────────────────────────────────────

// GetPendingActions returns HITL actions queued for the configured host.
func (c *Client) GetPendingActions(ctx context.Context) ([]PendingAction, error) {
	var result []PendingAction
	if err := c.get(ctx, "/v1/extensions/pending-actions", url.Values{
		"host_identifier": {c.cfg.HostIdentifier},
	}, &result); err != nil {
		return nil, fmt.Errorf("pending-actions: %w", err)
	}
	return result, nil
}

// GetAlertCache returns alerts fired for this host in the last 24 h.
func (c *Client) GetAlertCache(ctx context.Context) ([]AlertCacheEntry, error) {
	since := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	var result []AlertCacheEntry
	if err := c.get(ctx, "/v1/extensions/alert-cache", url.Values{
		"host_identifier": {c.cfg.HostIdentifier},
		"since":           {since},
	}, &result); err != nil {
		return nil, fmt.Errorf("alert-cache: %w", err)
	}
	return result, nil
}

// GetPersistenceBaseline returns the approved persistence baseline for this
// host.
func (c *Client) GetPersistenceBaseline(ctx context.Context) ([]PersistenceEntry, error) {
	var result []PersistenceEntry
	if err := c.get(ctx, "/v1/extensions/persistence-baseline", url.Values{
		"host_identifier": {c.cfg.HostIdentifier},
	}, &result); err != nil {
		return nil, fmt.Errorf("persistence-baseline: %w", err)
	}
	return result, nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func (c *Client) get(ctx context.Context, path string, params url.Values, dst any) error {
	u, err := url.Parse(c.cfg.APIURL + path)
	if err != nil {
		return err
	}
	u.RawQuery = params.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return err
	}
	if c.cfg.APIToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIToken)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d from %s", resp.StatusCode, u.String())
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}
