package tables

import (
	"bufio"
	"context"
	"log"
	"os"
	"strings"

	"github.com/osquery/osquery-go/plugin/table"
)

// KernelModulesVerifiedColumns returns the column schema for
// aisoc_kernel_modules_verified.  This table is Linux-only; on macOS/Windows
// it returns zero rows.
func KernelModulesVerifiedColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("name"),
		table.IntegerColumn("loaded"),
		table.IntegerColumn("signed"),
		table.TextColumn("signer"),
		table.TextColumn("path"),
	}
}

// KernelModulesVerifiedGenerate reads the live kernel modules from
// /proc/modules and emits a row per module with a basic signature-status
// field populated from /sys/module/<name>/parameters (best-effort).
func KernelModulesVerifiedGenerate(_ *struct{}) table.GenerateFunc {
	return func(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
		f, err := os.Open("/proc/modules")
		if err != nil {
			// Not Linux or permission denied — return empty gracefully.
			log.Printf("aisoc_kernel_modules_verified: /proc/modules not available: %v", err)
			return nil, nil
		}
		defer f.Close()

		var rows []map[string]string
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 1 {
				continue
			}
			name := fields[0]
			// Attempt to detect in-kernel module signing via
			// /sys/module/<name>/taint; this is a best-effort heuristic.
			signed := "0"
			signer := ""
			taintPath := "/sys/module/" + name + "/taint"
			if data, err := os.ReadFile(taintPath); err == nil {
				taint := strings.TrimSpace(string(data))
				if !strings.Contains(taint, "E") { // "E" = unsigned (out-of-tree)
					signed = "1"
					signer = "kernel"
				}
			}
			rows = append(rows, map[string]string{
				"name":   name,
				"loaded": "1",
				"signed": signed,
				"signer": signer,
				"path":   "/sys/module/" + name,
			})
		}
		return rows, nil
	}
}
