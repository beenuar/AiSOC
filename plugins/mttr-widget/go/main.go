// Package main is the MTTR dashboard widget reference plugin in Go.
//
// Computes Mean Time To Respond (MTTR) and Mean Time To Detect (MTTD)
// metrics from the AiSOC case database and returns a renderer-ready payload
// for the dashboard widget grid.
//
// Implements aisoc.Widget. The Python sibling at ../plugin.py is the
// canonical reference; this file mirrors its semantics so dashboards
// rendering either plugin produce the same shape of output.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
)

const defaultAPIBase = "http://api:8000"

// MTTRWidget computes MTTR/MTTD breakdowns for the dashboard.
type MTTRWidget struct {
	aisoc.BasePlugin

	httpClient *http.Client
}

// Manifest declares this plugin to the runtime.
func (m *MTTRWidget) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "mttr-widget",
		Name:        "MTTR Dashboard Widget",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeWidget,
		Description: "Computes MTTR/MTTD across closed AiSOC cases for the dashboard widget grid.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"metrics", "mttr", "mttd", "dashboard", "widget"},
	}
}

// OnLoad initialises the HTTP client used to query the AiSOC API.
func (m *MTTRWidget) OnLoad(ctx context.Context, pctx aisoc.PluginContext) error {
	m.httpClient = &http.Client{Timeout: 30 * time.Second}
	return nil
}

// caseRecord is a minimal projection of the AiSOC `Case` object covering only
// the fields this widget needs.
type caseRecord struct {
	CreatedAt  string `json:"created_at"`
	DetectedAt string `json:"detected_at"`
	ResolvedAt string `json:"resolved_at"`
	Severity   string `json:"severity"`
}

// Compute fetches recent closed cases, computes MTTR/MTTD breakdowns, and
// returns a renderer-ready payload keyed exactly like the Python sibling so
// front-end widgets can target either implementation interchangeably.
func (m *MTTRWidget) Compute(
	ctx context.Context,
	req aisoc.WidgetRequest,
	pctx aisoc.PluginContext,
) (aisoc.WidgetResult, error) {
	cfg := pctx.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	payload := req.Payload
	if payload == nil {
		payload = map[string]any{}
	}

	lookback := readInt(payload, "lookback_days", readInt(cfg, "lookback_days", 30))
	pcts := readPercentiles(cfg, "percentiles", []int{50, 75, 95})

	var severityFilter []string
	if raw, ok := payload["severity_filter"].([]any); ok {
		for _, s := range raw {
			if v, ok := s.(string); ok && v != "" {
				severityFilter = append(severityFilter, v)
			}
		}
	}
	playbookFilter, _ := payload["playbook_filter"].(string)

	apiURL := readString(cfg, "api_url", "")
	if apiURL == "" {
		apiURL = pctx.APIBaseURL
	}
	if apiURL == "" {
		apiURL = defaultAPIBase
	}
	apiURL = strings.TrimRight(apiURL, "/")

	apiKey := readString(cfg, "api_key", "")
	if apiKey == "" {
		apiKey = pctx.APIToken
	}

	since := time.Now().UTC().Add(-time.Duration(lookback) * 24 * time.Hour).Format(time.RFC3339)
	q := url.Values{}
	q.Set("status", "closed")
	q.Set("created_after", since)
	q.Set("limit", "1000")
	if len(severityFilter) > 0 {
		q.Set("severity", strings.Join(severityFilter, ","))
	}
	if playbookFilter != "" {
		q.Set("playbook_id", playbookFilter)
	}

	cases, err := m.fetchCases(ctx, apiURL, apiKey, q)
	if err != nil {
		return aisoc.WidgetResult{Error: err.Error()}, err
	}

	if len(cases) == 0 {
		return aisoc.WidgetResult{
			Data: map[string]any{
				"sample_size":  0,
				"mttr_seconds": map[string]any{},
				"mttd_seconds": map[string]any{},
				"by_severity":  map[string]any{},
				"trend":        []any{},
			},
		}, nil
	}

	var mttrVals []float64
	var mttdVals []float64
	bySev := map[string][]float64{}
	daily := map[string][]float64{}

	for _, c := range cases {
		if c.ResolvedAt == "" {
			continue
		}
		tCreated, errCreated := parseTime(c.CreatedAt)
		detected := c.DetectedAt
		if detected == "" {
			detected = c.CreatedAt
		}
		tDetected, errDetected := parseTime(detected)
		tResolved, errResolved := parseTime(c.ResolvedAt)
		if errCreated != nil || errDetected != nil || errResolved != nil {
			continue
		}
		mttr := tResolved.Sub(tCreated).Seconds()
		mttd := tCreated.Sub(tDetected).Seconds()
		if mttr < 0 || mttd < 0 {
			continue
		}
		mttrVals = append(mttrVals, mttr)
		if mttd < 0 {
			mttd = 0
		}
		mttdVals = append(mttdVals, mttd)
		sev := strings.ToLower(c.Severity)
		if sev == "" {
			sev = "unknown"
		}
		bySev[sev] = append(bySev[sev], mttr)
		dayKey := tResolved.UTC().Format("2006-01-02")
		daily[dayKey] = append(daily[dayKey], mttr)
	}

	summary := func(vals []float64) map[string]any {
		out := map[string]any{}
		if len(vals) == 0 {
			return out
		}
		out["mean"] = round1(mean(vals))
		for _, p := range pcts {
			out[fmt.Sprintf("p%d", p)] = round1(percentile(vals, p))
		}
		return out
	}

	bySevOut := map[string]any{}
	for sev, vs := range bySev {
		bySevOut[sev] = map[string]any{
			"mean_mttr": round1(mean(vs)),
			"count":     len(vs),
		}
	}

	dayKeys := make([]string, 0, len(daily))
	for k := range daily {
		dayKeys = append(dayKeys, k)
	}
	sort.Strings(dayKeys)
	trend := make([]map[string]any, 0, len(dayKeys))
	for _, k := range dayKeys {
		trend = append(trend, map[string]any{
			"date":      k,
			"mean_mttr": round1(mean(daily[k])),
		})
	}

	return aisoc.WidgetResult{
		SampleSize: len(mttrVals),
		Data: map[string]any{
			"sample_size":  len(mttrVals),
			"mttr_seconds": summary(mttrVals),
			"mttd_seconds": summary(mttdVals),
			"by_severity":  bySevOut,
			"trend":        trend,
		},
	}, nil
}

func (m *MTTRWidget) fetchCases(
	ctx context.Context,
	apiURL, apiKey string,
	q url.Values,
) ([]caseRecord, error) {
	full := apiURL + "/api/v1/cases?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("aisoc cases api: %s: %s", resp.Status, string(body))
	}
	var envelope struct {
		Items []caseRecord `json:"items"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, errors.New("decode cases response: " + err.Error())
	}
	return envelope.Items, nil
}

// parseTime accepts both RFC3339 and the `2006-01-02T15:04:05` shape that the
// Python `datetime.fromisoformat` defaults to.
func parseTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, errors.New("empty timestamp")
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02T15:04:05", s)
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	var sum float64
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// percentile uses linear interpolation between closest ranks (matches
// Python's `_percentile` helper in the sibling plugin.py).
func percentile(vals []float64, pct int) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	k := float64(len(sorted)-1) * float64(pct) / 100
	f := int(math.Floor(k))
	c := int(math.Min(float64(f+1), float64(len(sorted)-1)))
	return sorted[f] + (sorted[c]-sorted[f])*(k-float64(f))
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func readInt(m map[string]any, key string, fallback int) int {
	if v, ok := m[key]; ok {
		switch x := v.(type) {
		case int:
			return x
		case int64:
			return int(x)
		case float64:
			return int(x)
		}
	}
	return fallback
}

func readString(m map[string]any, key, fallback string) string {
	if v, ok := m[key].(string); ok && v != "" {
		return v
	}
	return fallback
}

func readPercentiles(m map[string]any, key string, fallback []int) []int {
	v, ok := m[key]
	if !ok {
		return fallback
	}
	raw, ok := v.([]any)
	if !ok {
		return fallback
	}
	var out []int
	for _, x := range raw {
		switch n := x.(type) {
		case int:
			out = append(out, n)
		case int64:
			out = append(out, int(n))
		case float64:
			out = append(out, int(n))
		}
	}
	if len(out) == 0 {
		return fallback
	}
	return out
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&MTTRWidget{}); err != nil {
		panic(err)
	}
	fmt.Println("mttr-widget reference plugin loaded")
}
