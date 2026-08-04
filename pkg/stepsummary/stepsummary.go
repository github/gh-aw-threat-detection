// Package stepsummary writes threat-detection observability data to the
// GitHub Actions step summary.
package stepsummary

import (
	"fmt"
	"os"
	"strings"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

// WriteArtifactInventory appends an artifact inventory table to path. An empty
// path disables summary output.
func WriteArtifactInventory(path string, inventory []artifacts.InventoryEntry) error {
	if path == "" {
		return nil
	}
	// GITHUB_STEP_SUMMARY intentionally names a caller-controlled output file.
	// #nosec G304 -- opening that configured path is this package's contract.
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("opening GITHUB_STEP_SUMMARY: %w", err)
	}

	var summary strings.Builder
	summary.WriteString("## Threat detection artifact inventory\n\n")
	summary.WriteString("| Path | Size (bytes) | Kind | Consumed |\n")
	summary.WriteString("|---|---:|---|:---:|\n")
	if len(inventory) == 0 {
		summary.WriteString("| _No files found_ | 0 | - | No |\n")
	}
	for _, entry := range inventory {
		consumed := "No"
		if entry.Consumed {
			consumed = "Yes"
		}
		fmt.Fprintf(&summary, "| `%s` | %d | %s | %s |\n",
			escapeCell(entry.Path), entry.Size, escapeCell(entry.Kind), consumed)
	}
	summary.WriteByte('\n')

	_, writeErr := file.WriteString(summary.String())
	closeErr := file.Close()
	if writeErr != nil {
		return fmt.Errorf("writing GITHUB_STEP_SUMMARY: %w", writeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("closing GITHUB_STEP_SUMMARY: %w", closeErr)
	}
	return nil
}

func escapeCell(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"|", "\\|",
		"\r", "\\r",
		"\n", "\\n",
	)
	return replacer.Replace(value)
}
