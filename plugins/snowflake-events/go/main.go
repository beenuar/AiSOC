// Package main is the Snowflake events connector reference implementation in Go.
//
// This skeleton uses gosnowflake (github.com/snowflakedb/gosnowflake) to pull
// recent login/query history from SNOWFLAKE.ACCOUNT_USAGE. It is provided as a
// reference for cross-language SDK parity; production deployments should pin
// dependencies via go.mod.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/beenuar/aisoc/plugin-sdk-go/aisoc"
	// _ "github.com/snowflakedb/gosnowflake"
)

// SnowflakeConnector implements aisoc.Connector for Snowflake account usage.
type SnowflakeConnector struct {
	aisoc.BasePlugin
}

func (s *SnowflakeConnector) Manifest() aisoc.PluginManifest {
	return aisoc.PluginManifest{
		ID:          "snowflake-events",
		Name:        "Snowflake Events Connector",
		Version:     "1.0.0",
		PluginType:  aisoc.PluginTypeConnector,
		Description: "Polls login/query history from SNOWFLAKE.ACCOUNT_USAGE.",
		Author:      "AiSOC Core Team",
		Tags:        []string{"data", "snowflake", "warehouse", "events", "connector"},
	}
}

func (s *SnowflakeConnector) connect(pctx aisoc.PluginContext) (*sql.DB, error) {
	account, _ := pctx.Config["account"].(string)
	user, _ := pctx.Config["user"].(string)
	password, _ := pctx.Config["password"].(string)
	warehouse, _ := pctx.Config["warehouse"].(string)
	role, _ := pctx.Config["role"].(string)
	if account == "" || user == "" || password == "" || warehouse == "" {
		return nil, errors.New("account, user, password, warehouse are required")
	}
	if role == "" {
		role = "ACCOUNTADMIN"
	}
	dsn := fmt.Sprintf(
		"%s:%s@%s/?warehouse=%s&role=%s",
		user, password, account, warehouse, role,
	)
	return sql.Open("snowflake", dsn)
}

func (s *SnowflakeConnector) TestConnection(
	ctx context.Context,
	pctx aisoc.PluginContext,
) (bool, error) {
	db, err := s.connect(pctx)
	if err != nil {
		return false, err
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return false, err
	}
	return true, nil
}

func (s *SnowflakeConnector) FetchEvents(
	ctx context.Context,
	pctx aisoc.PluginContext,
	since string,
) (<-chan map[string]any, error) {
	out := make(chan map[string]any)

	if since == "" {
		since = time.Now().Add(-15 * time.Minute).UTC().Format(time.RFC3339)
	}

	db, err := s.connect(pctx)
	if err != nil {
		close(out)
		return out, err
	}

	go func() {
		defer close(out)
		defer db.Close()

		query := `SELECT EVENT_TIMESTAMP, USER_NAME, CLIENT_IP,
		                 REPORTED_CLIENT_TYPE, IS_SUCCESS, ERROR_MESSAGE
		            FROM SNOWFLAKE.ACCOUNT_USAGE.LOGIN_HISTORY
		           WHERE EVENT_TIMESTAMP >= TO_TIMESTAMP_TZ(?)
		           ORDER BY EVENT_TIMESTAMP DESC LIMIT 500`
		rows, err := db.QueryContext(ctx, query, since)
		if err != nil {
			out <- map[string]any{"error": err.Error()}
			return
		}
		defer rows.Close()

		cols, _ := rows.Columns()
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				out <- map[string]any{"error": err.Error()}
				continue
			}
			event := map[string]any{"_aisoc_feed": "login_history"}
			for i, col := range cols {
				event[col] = values[i]
			}
			out <- event
		}
	}()

	return out, nil
}

func main() {
	registry := aisoc.NewRegistry()
	if err := registry.Register(&SnowflakeConnector{}); err != nil {
		panic(err)
	}
	fmt.Println("snowflake-events reference plugin loaded")
}
