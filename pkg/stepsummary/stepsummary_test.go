package stepsummary

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

func TestWriteArtifactInventory_EmptyPathIsNoOp(t *testing.T) {
	if err := WriteArtifactInventory("", []artifacts.InventoryEntry{{Path: "a"}}); err != nil {
		t.Fatalf("WriteArtifactInventory(\"\") error = %v", err)
	}
}

func TestWriteArtifactInventory_NeutralizesMarkdownInFilenames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.md")
	// A hostile filename that tries to break out of the code span/table cell.
	hostile := "a`b</code>|<script>x</script>&\r\n.txt"
	if err := WriteArtifactInventory(path, []artifacts.InventoryEntry{
		{Path: hostile, Size: 3, Kind: "file", Consumed: true},
	}); err != nil {
		t.Fatalf("WriteArtifactInventory() error = %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}
	content := string(data)

	// The raw markup must never appear unescaped in the rendered cell. Check
	// payload-adjacent sequences so the wrapper's own </code> is not matched.
	for _, raw := range []string{"b</code>", "<script>", "\n.txt"} {
		if strings.Contains(content, raw) {
			t.Errorf("summary contains unescaped %q:\n%s", raw, content)
		}
	}
	// The escaped forms must be present, keeping the row on a single line.
	for _, escaped := range []string{"&lt;/code&gt;", "&#124;", "&lt;script&gt;", "&amp;"} {
		if !strings.Contains(content, escaped) {
			t.Errorf("summary missing escaped %q:\n%s", escaped, content)
		}
	}
	// Exactly one data row (header + separator + one entry, no injected rows).
	rows := 0
	for _, line := range strings.Split(content, "\n") {
		if strings.HasPrefix(line, "| <code>") {
			rows++
		}
	}
	if rows != 1 {
		t.Errorf("expected exactly one data row, got %d:\n%s", rows, content)
	}
}

func TestWriteArtifactInventory_EmptyInventoryRendersPlaceholder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.md")
	if err := WriteArtifactInventory(path, nil); err != nil {
		t.Fatalf("WriteArtifactInventory() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading summary: %v", err)
	}
	if !strings.Contains(string(data), "_No files found_") {
		t.Errorf("summary missing empty placeholder:\n%s", data)
	}
}
