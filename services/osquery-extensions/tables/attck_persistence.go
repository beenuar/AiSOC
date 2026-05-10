package tables

import (
	"context"
	"fmt"
	"log"

	"github.com/beenuar/aisoc/osquery-extensions/internal/aisocapi"
	"github.com/osquery/osquery-go/plugin/table"
)

// ATTCKPersistenceColumns returns the column schema for aisoc_attck_persistence.
func ATTCKPersistenceColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("entry_id"),
		table.TextColumn("mechanism"),
		table.TextColumn("path"),
		table.TextColumn("arguments"),
		table.IntegerColumn("approved"),
		table.TextColumn("mitre_technique"),
	}
}

// ATTCKPersistenceGenerate returns a GenerateFunc that fetches the approved
// persistence baseline from the AiSOC API, so analysts can diff it against
// what osquery actually finds on the host.
func ATTCKPersistenceGenerate(client *aisocapi.Client) table.GenerateFunc {
	return func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
		entries, err := client.GetPersistenceBaseline(ctx)
		if err != nil {
			log.Printf("aisoc_attck_persistence: API error: %v", err)
			return nil, nil
		}

		rows := make([]map[string]string, 0, len(entries))
		for _, e := range entries {
			approved := "0"
			if e.Approved {
				approved = "1"
			}
			rows = append(rows, map[string]string{
				"entry_id":        e.EntryID,
				"mechanism":       e.Mechanism,
				"path":            e.Path,
				"arguments":       e.Arguments,
				"approved":        approved,
				"mitre_technique": e.MITRETech,
			})
		}
		return rows, nil
	}
}

// ATTCKPersistenceDescription returns a human-readable table description for
// the osquery extension registry.
func ATTCKPersistenceDescription() string {
	return fmt.Sprintf(
		"AiSOC-managed persistence baseline (T1547). " +
			"JOIN against startup_items / launchd / crontab to surface unapproved entries.",
	)
}
