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
		"WIN-HR-DESKTOP", "DC01.corp.aisoc.dev", "WIN-DEVOPS-LT", "WIN-CFO-LT",
	}
	users = []string{
		"alice@aisoc.dev", "bob@aisoc.dev", "carol@aisoc.dev", "dave@aisoc.dev",
		"svc-backup@aisoc.dev", "eve@aisoc.dev", "ceo@aisoc.dev",
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
		"AlertId":     fmt.Sprintf("da%d", r.Int63()),
		"AlertTitle":  "Suspicious LSASS access",
		"Severity":    severities[r.Intn(len(severities))],
		"Category":    "CredentialAccess",
		"ComputerDnsName": host,
		"InitiatedByUser": users[r.Intn(len(users))],
		"FileName":    "lsass.exe",
		"DetectionSource": "WindowsDefenderAv",
		"SrcIP":       randIP(r),
		"Timestamp":   time.Now().UTC().Format(time.RFC3339),
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
			"signature":   "ET TROJAN Possible Cobalt Strike Beacon",
			"category":    "A Network Trojan was Detected",
			"severity":    1,
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
		"eventType":  "user.session.start",
		"published":  time.Now().UTC().Format(time.RFC3339),
		"actor":      map[string]string{"alternateId": users[r.Intn(len(users))]},
		"client":     map[string]interface{}{"ipAddress": randIP(r), "userAgent": map[string]string{"os": "Mac OS X"}},
		"outcome":    map[string]string{"result": []string{"SUCCESS", "FAILURE"}[r.Intn(2)]},
		"severity":   severities[r.Intn(len(severities))],
		"displayMessage": "User login attempt",
	}
}

func splunkEvent(r *rand.Rand) map[string]interface{} {
	return map[string]interface{}{
		"_time":     time.Now().UTC().Unix(),
		"sourcetype": "wineventlog:security",
		"source":    "WinEventLog:Security",
		"host":      hosts[r.Intn(len(hosts))],
		"EventCode": 4625,
		"message":   "An account failed to log on",
		"user":      users[r.Intn(len(users))],
		"src_ip":    randIP(r),
		"severity":  severities[r.Intn(len(severities))],
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

func runProducer(ctx context.Context, wg *sync.WaitGroup, profile connectorProfile, opts options, sent *atomic.Int64) {
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
			payload := ingestRequest{
				ConnectorID:   profile.id,
				ConnectorType: profile.typ,
				SourceFormat:  profile.format,
				Events:        batch,
			}
			body, err := json.Marshal(payload)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[%s] marshal: %v\n", profile.id, err)
				continue
			}
			req, err := http.NewRequestWithContext(ctx, "POST", opts.ingestURL, bytes.NewReader(body))
			if err != nil {
				continue
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-Tenant-ID", opts.tenant)
			resp, err := client.Do(req)
			if err != nil {
				if ctx.Err() == nil {
					fmt.Fprintf(os.Stderr, "[%s] post: %v\n", profile.id, err)
				}
				continue
			}
			resp.Body.Close()
			sent.Add(int64(len(batch)))
		}
	}
}

type options struct {
	ingestURL string
	tenant    string
	rate      int
	batch     int
	duration  time.Duration
}

func main() {
	var opts options
	flag.StringVar(&opts.ingestURL, "ingest-url", envDefault("INGEST_URL", "http://localhost:8001/v1/ingest"), "Ingest service ingest endpoint")
	flag.StringVar(&opts.tenant, "tenant", envDefault("TENANT_ID", "00000000-0000-0000-0000-000000000001"), "Tenant ID header")
	flag.IntVar(&opts.rate, "rate", 4, "Batches per second per connector")
	flag.IntVar(&opts.batch, "batch", 5, "Events per batch")
	flag.DurationVar(&opts.duration, "duration", 0, "How long to run (0 = forever)")
	flag.Parse()

	fmt.Printf("[demo-producer] ingest=%s tenant=%s rate=%d batch=%d connectors=%d\n",
		opts.ingestURL, opts.tenant, opts.rate, opts.batch, len(profiles))

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

	var sent atomic.Int64
	var wg sync.WaitGroup
	for _, p := range profiles {
		wg.Add(1)
		go runProducer(ctx, &wg, p, opts, &sent)
	}

	// Periodic stats line.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fmt.Printf("[demo-producer] events sent so far: %d\n", sent.Load())
			}
		}
	}()

	wg.Wait()
	fmt.Printf("[demo-producer] done. total events sent: %d\n", sent.Load())
}

func envDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
