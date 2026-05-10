// Package tables implements the five AiSOC virtual osquery tables.
package tables

import (
	"context"
	"log"

	"github.com/beenuar/aisoc/osquery-extensions/internal/aisocapi"
	"github.com/osquery/osquery-go/plugin/table"
)

// PendingActionsColumns returns the column schema for aisoc_pending_actions.
func PendingActionsColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("action_id"),
		table.TextColumn("case_id"),
		table.TextColumn("action_type"),
		table.TextColumn("target"),
		table.TextColumn("requested_by"),
		table.TextColumn("requested_at"),
		table.TextColumn("expires_at"),
		table.TextColumn("description"),
	}
}

// PendingActionsGenerate satisfies osquery-go's Generate signature and fetches
// pending HITL actions from the AiSOC API.
func PendingActionsGenerate(client *aisocapi.Client) table.GenerateFunc {
	return func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
		actions, err := client.GetPendingActions(ctx)
		if err != nil {
			log.Printf("aisoc_pending_actions: API error: %v", err)
			return nil, nil // return empty rather than failing the query
		}

		rows := make([]map[string]string, 0, len(actions))
		for _, a := range actions {
			rows = append(rows, map[string]string{
				"action_id":    a.ActionID,
				"case_id":     a.CaseID,
				"action_type": a.ActionType,
				"target":      a.Target,
				"requested_by": a.RequestedBy,
				"requested_at": a.RequestedAt,
				"expires_at":  a.ExpiresAt,
				"description": a.Description,
			})
		}
		return rows, nil
	}
}
