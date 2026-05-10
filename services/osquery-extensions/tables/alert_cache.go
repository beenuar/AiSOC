package tables

import (
	"context"
	"log"

	"github.com/beenuar/aisoc/osquery-extensions/internal/aisocapi"
	"github.com/osquery/osquery-go/plugin/table"
)

// AlertCacheColumns returns the column schema for aisoc_alert_cache.
func AlertCacheColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("alert_id"),
		table.TextColumn("rule_id"),
		table.TextColumn("severity"),
		table.TextColumn("fired_at"),
		table.TextColumn("summary"),
		table.TextColumn("case_id"),
	}
}

// AlertCacheGenerate returns a GenerateFunc that fetches the last-24h alert
// cache for this host from the AiSOC API.
func AlertCacheGenerate(client *aisocapi.Client) table.GenerateFunc {
	return func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
		alerts, err := client.GetAlertCache(ctx)
		if err != nil {
			log.Printf("aisoc_alert_cache: API error: %v", err)
			return nil, nil
		}

		rows := make([]map[string]string, 0, len(alerts))
		for _, a := range alerts {
			rows = append(rows, map[string]string{
				"alert_id": a.AlertID,
				"rule_id":  a.RuleID,
				"severity": a.Severity,
				"fired_at": a.FiredAt,
				"summary":  a.Summary,
				"case_id":  a.CaseID,
			})
		}
		return rows, nil
	}
}
