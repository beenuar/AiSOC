// Command aisoc-extension is an osquery extension that exposes five virtual
// tables backed by the AiSOC API and local OS introspection.
//
//	aisoc_pending_actions       – HITL response actions queued for this host
//	aisoc_alert_cache           – alerts fired against this host (last 24h)
//	aisoc_attck_persistence     – approved persistence baseline (MITRE T1547)
//	aisoc_kernel_modules_verified – live kernel modules with signing status
//	aisoc_browser_extensions    – installed browser extensions per profile
package main

import (
	"flag"
	"log"
	"time"

	"github.com/beenuar/aisoc/osquery-extensions/internal/aisocapi"
	"github.com/beenuar/aisoc/osquery-extensions/internal/config"
	"github.com/beenuar/aisoc/osquery-extensions/tables"
	osquery "github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

func main() {
	socket := flag.String("socket", "", "Path to the osquery socket")
	timeout := flag.Int("timeout", 30, "Seconds to wait for osquery socket")
	flag.Parse()

	if *socket == "" {
		log.Fatal("--socket is required")
	}

	cfg := config.Load()
	client := aisocapi.New(cfg)

	server, err := osquery.NewExtensionManagerServer(
		"aisoc",
		*socket,
		osquery.ServerTimeout(time.Duration(*timeout)*time.Second),
	)
	if err != nil {
		log.Fatalf("failed to create extension manager: %v", err)
	}

	server.RegisterPlugin(table.NewPlugin(
		"aisoc_pending_actions",
		tables.PendingActionsColumns(),
		tables.PendingActionsGenerate(client),
	))

	server.RegisterPlugin(table.NewPlugin(
		"aisoc_alert_cache",
		tables.AlertCacheColumns(),
		tables.AlertCacheGenerate(client),
	))

	server.RegisterPlugin(table.NewPlugin(
		"aisoc_attck_persistence",
		tables.ATTCKPersistenceColumns(),
		tables.ATTCKPersistenceGenerate(client),
	))

	server.RegisterPlugin(table.NewPlugin(
		"aisoc_kernel_modules_verified",
		tables.KernelModulesVerifiedColumns(),
		tables.KernelModulesVerifiedGenerate(nil),
	))

	server.RegisterPlugin(table.NewPlugin(
		"aisoc_browser_extensions",
		tables.BrowserExtensionsColumns(),
		tables.BrowserExtensionsGenerate(nil),
	))

	log.Println("aisoc-extension: starting, waiting for osquery…")
	if err := server.Run(); err != nil {
		log.Fatalf("extension exited with error: %v", err)
	}
}
