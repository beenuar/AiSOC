// AiSOC Demo Event Producer
//
// Generates synthetic but realistic security events and posts them to the
// ingest service so dashboards, alerts, copilots, and the attack graph all
// have data to chew on while developing locally.
//
// Usage:
//
//	go run ./services/demo-producer \
//	    --ingest-url http://localhost:8001/v1/ingest \
//	    --tenant 00000000-0000-0000-0000-000000000001 \
//	    --rate 5 \
//	    --duration 0
//
// `--rate` is events per second per connector. `--duration 0` runs forever.
//
// # Load mode
//
// `--load` switches from "keep a dashboard populated" to "measure what the
// spine sustains". It replaces the six randomised connector profiles with one
// deterministic event shape whose title carries a run id, a sequence number
// and the send time in Unix nanoseconds, so every alert that reaches Postgres
// can be attributed to the exact event that produced it. Each event also
// carries its own host, because the fusion correlation key is
// {tenant}:{entity}:{tactic}: shared entities would collapse thousands of
// events into a handful of alerts and there would be nothing per-event left
// to time. That makes load mode the worst case for fusion and the alert
// store, which is the case worth publishing.
//
//	go run ./services/demo-producer --load \
//	    --ingest-url http://localhost:8081/v1/ingest/batch \
//	    --token "$AISOC_INGEST_TOKEN" \
//	    --total 20000 --workers 8 --batch 50 \
//	    --summary /tmp/producer.json
//
// `scripts/perf/load_harness.py` drives this and correlates the summary with
// the alert rows. Nothing here measures latency: this end knows only when it
// sent, and the other end of the clock lives in the database.
//
// Part of the AiSOC platform (MIT License).
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type ingestRequest struct {
	ConnectorID   string                   `json:"connector_id"`
	ConnectorType string                   `json:"connector_type"`
	SourceFormat  string                   `json:"source_format"`
	Events        []map[string]interface{} `json:"events"`
}

type connectorProfile struct {
	id     string
	typ    string
	format string
	build  func(*rand.Rand) map[string]interface{}
}

var (
	hosts = []string{
		"WIN-FIN-DB01", "WIN-PROD-WEB02", "MAC-SARAH-LT", "LIN-K8S-NODE-03",
		"WIN-HR-DESKTOP", "DC01.corp.example.com", "WIN-DEVOPS-LT", "WIN-CFO-LT",
	}
	users = []string{
		"alice@example.com", "bob@example.com", "carol@example.com", "dave@example.com",
		"svc-backup@example.com", "eve@example.com", "ceo@example.com",
	}
	processes = []string{
		"powershell.exe", "cmd.exe", "explorer.exe", "wmic.exe", "rundll32.exe",
		"net.exe", "bash", "python3", "curl", "ssh",
	}
	severities = []string{"low", "medium", "high", "critical"}
	tactics    = []struct {
		ID   string
		Name string
	}{
		{"TA0001", "Initial Access"}, {"TA0002", "Execution"},
		{"TA0003", "Persistence"}, {"TA0004", "Privilege Escalation"},
		{"TA0005", "Defense Evasion"}, {"TA0006", "Credential Access"},
		{"TA0008", "Lateral Movement"}, {"TA0010", "Exfiltration"},
		{"TA0011", "Command and Control"}, {"TA0040", "Impact"},
	}
)

func randIP(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d", r.Intn(255), r.Intn(255), r.Intn(255), r.Intn(255))
}

func pickTactic(r *rand.Rand) (string, string) {
	t := tactics[r.Intn(len(tactics))]
	return t.ID, t.Name
}

func crowdstrikeEvent(r *rand.Rand) map[string]interface{} {
	tacticID, tactic := pickTactic(r)
	host := hosts[r.Intn(len(hosts))]
	return map[string]interface{}{
		"event_simpleName": "ProcessRollup2",
		"timestamp":        time.Now().UTC().Format(time.RFC3339Nano),
		"ComputerName":     host,
		"UserName":         users[r.Intn(len(users))],
		"FileName":         processes[r.Intn(len(processes))],
		"CommandLine":      "powershell -enc " + randString(r, 24),
		"Severity":         severities[r.Intn(len(severities))],
		"MitreTactic":      tactic,
		"MitreTacticID":    tacticID,
		"SrcIP":            randIP(r),
		"DstIP":            randIP(r),
	}
}

func defenderEvent(r *rand.Rand) map[string]interface{} {
	host := hosts[r.Intn(len(hosts))]
	return map[string]interface{}{
		"AlertId":         fmt.Sprintf("da%d", r.Int63()),
		"AlertTitle":      "Suspicious LSASS access",
		"Severity":        severities[r.Intn(len(severities))],
		"Category":        "CredentialAccess",
		"ComputerDnsName": host,
		"InitiatedByUser": users[r.Intn(len(users))],
		"FileName":        "lsass.exe",
		"DetectionSource": "WindowsDefenderAv",
		"SrcIP":           randIP(r),
		"Timestamp":       time.Now().UTC().Format(time.RFC3339),
	}
}

func suricataEvent(r *rand.Rand) map[string]interface{} {
	return map[string]interface{}{
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
		"event_type": "alert",
		"src_ip":     randIP(r),
		"dest_ip":    randIP(r),
		"src_port":   r.Intn(60000) + 1024,
		"dest_port":  443,
		"proto":      "TCP",
		"alert": map[string]interface{}{
			"signature":    "ET TROJAN Possible Cobalt Strike Beacon",
			"category":     "A Network Trojan was Detected",
			"severity":     1,
			"signature_id": 2024555,
		},
	}
}

func guarddutyEvent(r *rand.Rand) map[string]interface{} {
	return map[string]interface{}{
		"id":       fmt.Sprintf("gd-%d", r.Int63()),
		"type":     "UnauthorizedAccess:IAMUser/MaliciousIPCaller",
		"severity": []float64{2.0, 5.0, 7.0, 8.5}[r.Intn(4)],
		"region":   "us-east-1",
		"resource": map[string]interface{}{
			"resourceType": "AccessKey",
			"accessKeyDetails": map[string]string{
				"userName": users[r.Intn(len(users))],
			},
		},
		"service": map[string]interface{}{
			"action": map[string]string{
				"actionType": "AWS_API_CALL",
			},
		},
		"createdAt": time.Now().UTC().Format(time.RFC3339),
	}
}

func oktaEvent(r *rand.Rand) map[string]interface{} {
	return map[string]interface{}{
		"eventType":      "user.session.start",
		"published":      time.Now().UTC().Format(time.RFC3339),
		"actor":          map[string]string{"alternateId": users[r.Intn(len(users))]},
		"client":         map[string]interface{}{"ipAddress": randIP(r), "userAgent": map[string]string{"os": "Mac OS X"}},
		"outcome":        map[string]string{"result": []string{"SUCCESS", "FAILURE"}[r.Intn(2)]},
		"severity":       severities[r.Intn(len(severities))],
		"displayMessage": "User login attempt",
	}
}

func splunkEvent(r *rand.Rand) map[string]interface{} {
	return map[string]interface{}{
		"_time":      time.Now().UTC().Unix(),
		"sourcetype": "wineventlog:security",
		"source":     "WinEventLog:Security",
		"host":       hosts[r.Intn(len(hosts))],
		"EventCode":  4625,
		"message":    "An account failed to log on",
		"user":       users[r.Intn(len(users))],
		"src_ip":     randIP(r),
		"severity":   severities[r.Intn(len(severities))],
	}
}

func randString(r *rand.Rand, n int) string {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[r.Intn(len(letters))]
	}
	return string(b)
}

var profiles = []connectorProfile{
	{id: "demo-crowdstrike", typ: "crowdstrike", format: "crowdstrike-edr-event", build: crowdstrikeEvent},
	{id: "demo-defender", typ: "microsoft_defender", format: "defender-alert", build: defenderEvent},
	{id: "demo-suricata", typ: "suricata", format: "suricata-eve", build: suricataEvent},
	{id: "demo-guardduty", typ: "aws_guardduty", format: "guardduty-finding", build: guarddutyEvent},
	{id: "demo-okta", typ: "okta", format: "okta-system-log", build: oktaEvent},
	{id: "demo-splunk", typ: "splunk", format: "splunk-event", build: splunkEvent},
}

// stats counts what happened to each event, not how many were handed to the
// HTTP client. The producer used to add len(batch) to one counter immediately
// after Do() returned, without reading the status: a stack answering 401 or
// 500 to every batch still reported full throughput. A load harness built on
// that number would publish the throughput of an ingest endpoint that
// accepted nothing.
type stats struct {
	attempted atomic.Int64 // events handed to ingest
	accepted  atomic.Int64 // events ingest said it took
	rejected  atomic.Int64 // events ingest parsed and refused
	refused   atomic.Int64 // events in batches answered with a non-2xx
	transport atomic.Int64 // events in batches that never got an answer

	mu       sync.Mutex
	statuses map[int]int64
}

func newStats() *stats { return &stats{statuses: map[int]int64{}} }

func (s *stats) recordStatus(code int) {
	s.mu.Lock()
	s.statuses[code]++
	s.mu.Unlock()
}

func (s *stats) statusCounts() map[string]int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int64, len(s.statuses))
	for code, n := range s.statuses {
		out[strconv.Itoa(code)] = n
	}
	return out
}

// ingestResponse is the shape /v1/ingest/batch answers with. Both counters are
// read rather than inferred: a 200 whose body says `rejected: 50` is not a
// batch that landed.
type ingestResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}

// errFatalRequest marks the one failure in the send loop that retrying cannot
// clear: a URL that will not parse never becomes one that will.
var errFatalRequest = fmt.Errorf("request cannot be built")

func postBatch(ctx context.Context, client *http.Client, opts options, payload ingestRequest, st *stats) error {
	n := int64(len(payload.Events))
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", opts.ingestURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w for %q: %v", errFatalRequest, opts.ingestURL, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", opts.tenant)
	// /v1/ingest derives the tenant from the credential and only intersects
	// the header above with it, so without a token every batch is refused
	// with 401.
	if opts.token != "" {
		req.Header.Set("Authorization", "Bearer "+opts.token)
	}

	st.attempted.Add(n)
	resp, err := client.Do(req)
	if err != nil {
		st.transport.Add(n)
		return err
	}
	defer resp.Body.Close()
	st.recordStatus(resp.StatusCode)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		st.refused.Add(n)
		return fmt.Errorf("ingest answered HTTP %d", resp.StatusCode)
	}
	var decoded ingestResponse
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		// A 2xx whose body we cannot read is not evidence the events landed,
		// so it is counted as refused rather than credited.
		st.refused.Add(n)
		return fmt.Errorf("ingest answered HTTP %d with an unreadable body: %w", resp.StatusCode, err)
	}
	st.accepted.Add(int64(decoded.Accepted))
	st.rejected.Add(int64(decoded.Rejected))
	return nil
}

func runProducer(ctx context.Context, wg *sync.WaitGroup, profile connectorProfile, opts options, st *stats) {
	defer wg.Done()
	r := rand.New(rand.NewSource(time.Now().UnixNano() + int64(len(profile.id))))
	interval := time.Second / time.Duration(opts.rate)
	if interval <= 0 {
		interval = 100 * time.Millisecond
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	client := &http.Client{Timeout: 10 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			batch := make([]map[string]interface{}, 0, opts.batch)
			for i := 0; i < opts.batch; i++ {
				batch = append(batch, profile.build(r))
			}
			err := postBatch(ctx, client, opts, ingestRequest{
				ConnectorID:   profile.id,
				ConnectorType: profile.typ,
				SourceFormat:  profile.format,
				Events:        batch,
			}, st)
			if err == nil {
				continue
			}
			if errors := ctx.Err(); errors != nil {
				return
			}
			fmt.Fprintf(os.Stderr, "[%s] %v\n", profile.id, err)
			if isFatalRequest(err) {
				fmt.Fprintf(os.Stderr, "[%s] this will not resolve; fix --ingest-url\n", profile.id)
				return
			}
		}
	}
}

func isFatalRequest(err error) bool {
	for err != nil {
		if err == errFatalRequest {
			return true
		}
		type unwrapper interface{ Unwrap() error }
		u, ok := err.(unwrapper)
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// ── Load mode ───────────────────────────────────────────────────────────────

// MarkerPrefix opens the title of every load event. `scripts/perf/load_harness.py`
// matches alert rows on it, so the two must agree; it is a constant here and a
// constant there, and the harness fails loudly when it finds none rather than
// publishing a throughput figure over zero correlated alerts.
const MarkerPrefix = "aisoc-load"

// loadEvent is one deterministic endpoint detection, shaped like the event the
// golden pipeline pushes so it takes the same promotion path a real detection
// takes. Three things are per-event and load-bearing:
//
//	seq   attributes the alert back to the event that made it, which is what
//	      makes "no loss and no duplicates" a countable statement.
//	sentNanos is the send time in the producer's clock. The harness subtracts
//	      it from the alert's created_at, correcting for the measured offset
//	      between the two clocks rather than assuming they agree.
//	host  is unique per event so the fusion correlation key
//	      {tenant}:{entity}:{tactic} does not collapse the run into a handful
//	      of alerts.
func loadEvent(runID string, seq int64, sentNanos int64) map[string]interface{} {
	host := fmt.Sprintf("LOAD-%s-%06d", runID, seq)
	return map[string]interface{}{
		"severity":       "high",
		"title":          fmt.Sprintf("%s %s seq=%d t=%d", MarkerPrefix, runID, seq, sentNanos),
		"description":    fmt.Sprintf("winword.exe spawned powershell.exe with an encoded command line on %s", host),
		"host":           host,
		"user":           fmt.Sprintf("loaduser%03d", seq%200),
		"process_name":   "powershell.exe",
		"parent_process": "winword.exe",
		"command_line":   "powershell.exe -nop -w hidden -enc JABzAD0A",
		"event_type":     "process_create",
		"technique":      "T1059.001",
		"timestamp":      time.Unix(0, sentNanos).UTC().Format(time.RFC3339Nano),
	}
}

type loadSummary struct {
	RunID           string           `json:"run_id"`
	Mode            string           `json:"mode"`
	MarkerPrefix    string           `json:"marker_prefix"`
	IngestURL       string           `json:"ingest_url"`
	Tenant          string           `json:"tenant"`
	StartedAt       string           `json:"started_at"`
	EndedAt         string           `json:"ended_at"`
	WallSeconds     float64          `json:"wall_seconds"`
	Workers         int              `json:"workers"`
	BatchSize       int              `json:"batch_size"`
	TargetEPS       int              `json:"target_eps"`
	Requested       int64            `json:"requested_events"`
	Attempted       int64            `json:"attempted_events"`
	Accepted        int64            `json:"accepted_events"`
	Rejected        int64            `json:"rejected_events"`
	Refused         int64            `json:"refused_events"`
	TransportErrors int64            `json:"transport_error_events"`
	AcceptedEPS     float64          `json:"accepted_eps"`
	StatusCounts    map[string]int64 `json:"http_status_counts"`
	SeqLow          int64            `json:"seq_low"`
	SeqHigh         int64            `json:"seq_high"`
}

// runLoad saturates or paces ingest with `total` attributable events and
// returns what happened. It never returns a throughput figure for events that
// were not accepted: `accepted_eps` divides the accepted count, so an ingest
// that refuses everything reports zero rather than the rate at which it
// refused.
func runLoad(ctx context.Context, opts options) loadSummary {
	st := newStats()
	var seq atomic.Int64
	var issued atomic.Int64

	// A shared bucket rather than a per-worker ticker: pacing per worker makes
	// the aggregate rate depend on how many workers happen to be blocked.
	var pace <-chan time.Time
	if opts.targetEPS > 0 {
		batchesPerSecond := float64(opts.targetEPS) / float64(opts.batch)
		if batchesPerSecond < 1 {
			batchesPerSecond = 1
		}
		ticker := time.NewTicker(time.Duration(float64(time.Second) / batchesPerSecond))
		defer ticker.Stop()
		pace = ticker.C
	}

	started := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < opts.workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{Timeout: 30 * time.Second}
			for {
				if ctx.Err() != nil {
					return
				}
				if opts.total > 0 && issued.Load() >= opts.total {
					return
				}
				if pace != nil {
					select {
					case <-ctx.Done():
						return
					case <-pace:
					}
				}
				size := opts.batch
				if opts.total > 0 {
					remaining := opts.total - issued.Add(int64(size))
					if remaining < 0 {
						size += int(remaining) // the last batch is short, never over
						if size <= 0 {
							return
						}
					}
				}
				batch := make([]map[string]interface{}, 0, size)
				now := time.Now().UnixNano()
				for i := 0; i < size; i++ {
					batch = append(batch, loadEvent(opts.runID, seq.Add(1)-1, now))
				}
				err := postBatch(ctx, client, opts, ingestRequest{
					ConnectorID:   "load-" + opts.runID,
					ConnectorType: "crowdstrike",
					SourceFormat:  "json",
					Events:        batch,
				}, st)
				if err != nil && ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "[load] %v\n", err)
					if isFatalRequest(err) {
						return
					}
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(started)

	accepted := st.accepted.Load()
	eps := 0.0
	if elapsed.Seconds() > 0 {
		eps = float64(accepted) / elapsed.Seconds()
	}
	high := seq.Load() - 1
	if high < 0 {
		high = 0
	}
	return loadSummary{
		RunID:           opts.runID,
		Mode:            "load",
		MarkerPrefix:    MarkerPrefix,
		IngestURL:       opts.ingestURL,
		Tenant:          opts.tenant,
		StartedAt:       started.UTC().Format(time.RFC3339Nano),
		EndedAt:         started.Add(elapsed).UTC().Format(time.RFC3339Nano),
		WallSeconds:     elapsed.Seconds(),
		Workers:         opts.workers,
		BatchSize:       opts.batch,
		TargetEPS:       opts.targetEPS,
		Requested:       opts.total,
		Attempted:       st.attempted.Load(),
		Accepted:        accepted,
		Rejected:        st.rejected.Load(),
		Refused:         st.refused.Load(),
		TransportErrors: st.transport.Load(),
		AcceptedEPS:     eps,
		StatusCounts:    st.statusCounts(),
		SeqLow:          0,
		SeqHigh:         high,
	}
}

func writeSummary(path string, summary loadSummary) error {
	blob, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(blob, '\n'), 0o600)
}

type options struct {
	ingestURL string
	tenant    string
	token     string
	rate      int
	batch     int
	duration  time.Duration

	load      bool
	runID     string
	total     int64
	workers   int
	targetEPS int
	summary   string
}

func main() {
	var opts options
	flag.StringVar(&opts.ingestURL, "ingest-url", envDefault("INGEST_URL", "http://localhost:8001/v1/ingest"), "Ingest service ingest endpoint")
	flag.StringVar(&opts.tenant, "tenant", envDefault("TENANT_ID", "00000000-0000-0000-0000-000000000001"), "Tenant ID header")
	flag.StringVar(&opts.token, "token", envDefault("AISOC_INGEST_TOKEN", ""), "Ingest credential (mint with `make ingest-token`); /v1/ingest refuses requests without one")
	flag.IntVar(&opts.rate, "rate", 4, "Batches per second per connector")
	flag.IntVar(&opts.batch, "batch", 5, "Events per batch")
	flag.DurationVar(&opts.duration, "duration", 0, "How long to run (0 = forever)")
	flag.BoolVar(&opts.load, "load", false, "Load-harness mode: one attributable event shape, a run id in every title, and a JSON summary")
	flag.StringVar(&opts.runID, "run-id", "", "Load mode: run identifier stamped into every title (default: generated)")
	flag.Int64Var(&opts.total, "total", 0, "Load mode: stop after this many events (0 = until --duration elapses)")
	flag.IntVar(&opts.workers, "workers", 8, "Load mode: concurrent senders")
	flag.IntVar(&opts.targetEPS, "target-eps", 0, "Load mode: pace to this many events per second (0 = saturate)")
	flag.StringVar(&opts.summary, "summary", "", "Load mode: write the run summary as JSON to this path")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	if opts.duration > 0 {
		ctx, cancel = context.WithTimeout(ctx, opts.duration)
	}
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[demo-producer] shutting down…")
		cancel()
	}()

	if opts.load {
		os.Exit(mainLoad(ctx, opts))
	}

	fmt.Printf("[demo-producer] ingest=%s tenant=%s rate=%d batch=%d connectors=%d\n",
		opts.ingestURL, opts.tenant, opts.rate, opts.batch, len(profiles))

	st := newStats()
	var wg sync.WaitGroup
	for _, p := range profiles {
		wg.Add(1)
		go runProducer(ctx, &wg, p, opts, st)
	}

	// Periodic stats line. Accepted, not attempted: a stack refusing every
	// batch must not read as one taking them.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fmt.Printf("[demo-producer] events accepted so far: %d (attempted %d)\n",
					st.accepted.Load(), st.attempted.Load())
			}
		}
	}()

	wg.Wait()
	fmt.Printf("[demo-producer] done. accepted %d of %d attempted\n", st.accepted.Load(), st.attempted.Load())
}

func mainLoad(ctx context.Context, opts options) int {
	if opts.runID == "" {
		opts.runID = fmt.Sprintf("%x", time.Now().UnixNano())[:10]
	}
	if opts.workers < 1 {
		opts.workers = 1
	}
	if opts.batch < 1 {
		opts.batch = 1
	}
	if opts.total <= 0 && opts.duration <= 0 {
		fmt.Fprintln(os.Stderr, "[load] refusing to run unbounded: pass --total or --duration")
		return 2
	}
	fmt.Fprintf(os.Stderr, "[load] run=%s ingest=%s total=%d workers=%d batch=%d target-eps=%d\n",
		opts.runID, opts.ingestURL, opts.total, opts.workers, opts.batch, opts.targetEPS)

	summary := runLoad(ctx, opts)

	if opts.summary != "" {
		if err := writeSummary(opts.summary, summary); err != nil {
			fmt.Fprintf(os.Stderr, "[load] could not write %s: %v\n", opts.summary, err)
			return 1
		}
	}
	blob, _ := json.MarshalIndent(summary, "", "  ")
	fmt.Println(string(blob))

	codes := make([]string, 0, len(summary.StatusCounts))
	for code := range summary.StatusCounts {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	fmt.Fprintf(os.Stderr, "[load] accepted %d of %d attempted in %.1fs (%.0f eps); statuses %v\n",
		summary.Accepted, summary.Attempted, summary.WallSeconds, summary.AcceptedEPS, codes)

	// A run that accepted nothing is a failed run, not a run that measured
	// zero throughput. Saying so here stops a harness publishing an honest
	// zero for what was actually a misconfiguration.
	if summary.Accepted == 0 {
		fmt.Fprintln(os.Stderr, "[load] ingest accepted no events; check --token and --ingest-url")
		return 1
	}
	return 0
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
