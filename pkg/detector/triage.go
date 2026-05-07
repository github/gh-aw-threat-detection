package detector

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/github/gh-aw-threat-detection/pkg/artifacts"
)

const defaultTriageMaxBytes = 32 * 1024

// DefaultTriageMaxBytes returns the default per-artifact read budget for triage.
func DefaultTriageMaxBytes() int {
	return defaultTriageMaxBytes
}

// DefaultTriagePromptTemplate returns the embedded fast triage prompt template.
func DefaultTriagePromptTemplate() (string, error) {
	data, err := defaultPromptFS.ReadFile("prompts/threat_detection_triage.md")
	if err != nil {
		return "", fmt.Errorf("reading embedded triage prompt template: %w", err)
	}
	return string(data), nil
}

// BuildTriagePrompt constructs the Phase 1 prompt with bounded inline artifact content.
func BuildTriagePrompt(arts *artifacts.Artifacts, maxBytes int) (string, error) {
	if arts == nil {
		return "", fmt.Errorf("artifacts are required")
	}
	if maxBytes <= 0 {
		maxBytes = defaultTriageMaxBytes
	}
	template, err := DefaultTriagePromptTemplate()
	if err != nil {
		return "", err
	}

	analysis := BuildPromptAnalysis(arts)
	analysisContent := analysis.FormatForPrompt()
	if analysisContent == "" {
		analysisContent = "No prompt template or import tree available. Prompt analysis was not performed."
	}

	prompt := template
	prompt = strings.ReplaceAll(prompt, "{WORKFLOW_NAME}", arts.WorkflowName)
	prompt = strings.ReplaceAll(prompt, "{WORKFLOW_DESCRIPTION}", arts.WorkflowDescription)
	prompt = strings.ReplaceAll(prompt, "{PROMPT_ANALYSIS}", analysisContent)
	prompt = strings.ReplaceAll(prompt, "{WORKFLOW_PROMPT_CONTENT}", triageFileBlock(arts.PromptFilePath, maxBytes))
	prompt = strings.ReplaceAll(prompt, "{AGENT_OUTPUT_CONTENT}", triageFileBlock(arts.AgentOutputFilePath, maxBytes))
	prompt = strings.ReplaceAll(prompt, "{PATCH_CONTENT}", triagePatchBlocks(arts.PatchFiles, maxBytes))
	if arts.CustomPrompt != "" {
		prompt += "\n\n## Additional Instructions\n\n" + arts.CustomPrompt
	}
	return prompt, nil
}

func triagePatchBlocks(paths []string, maxBytes int) string {
	if len(paths) == 0 {
		return "No patch or bundle file found."
	}
	blocks := make([]string, 0, len(paths))
	for _, path := range paths {
		blocks = append(blocks, triageFileBlock(path, maxBytes))
	}
	return strings.Join(blocks, "\n\n")
}

func triageFileBlock(path string, maxBytes int) string {
	if path == "" || strings.HasPrefix(path, "No ") {
		return path
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Sprintf("%s: unavailable: %v", path, err)
	}
	if strings.HasSuffix(path, ".bundle") {
		return fmt.Sprintf("%s (%d bytes, git-bundle binary; content omitted from Phase 1 triage)", path, info.Size())
	}
	data, truncated, err := readBoundedText(path, maxBytes)
	if err != nil {
		return fmt.Sprintf("%s: unavailable: %v", path, err)
	}
	header := fmt.Sprintf("%s (%d bytes", path, info.Size())
	if truncated {
		header += fmt.Sprintf(", truncated to %d bytes", maxBytes)
	}
	header += ")"
	return fmt.Sprintf("%s\n```%s\n%s\n```", header, fenceLanguage(path), data)
}

func readBoundedText(path string, maxBytes int) (string, bool, error) {
	if maxBytes <= 0 {
		maxBytes = defaultTriageMaxBytes
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, err
	}

	// Read one extra byte so truncation can be detected without reading the
	// entire artifact into memory.
	buf, err := io.ReadAll(io.LimitReader(f, int64(maxBytes+1)))
	closeErr := f.Close()
	if err != nil {
		return "", false, errors.Join(err, closeErr)
	}
	if closeErr != nil {
		return "", false, closeErr
	}
	n := len(buf)
	truncated := n > maxBytes
	if truncated {
		n = maxBytes
	}
	textBytes := buf[:n]
	if !utf8.Valid(textBytes) {
		for len(textBytes) > 0 {
			r, size := utf8.DecodeLastRune(textBytes)
			if r != utf8.RuneError || size != 1 {
				break
			}
			textBytes = textBytes[:len(textBytes)-size]
		}
		if !utf8.Valid(textBytes) {
			return "[binary or invalid UTF-8 content omitted]", truncated, nil
		}
	}
	text := string(textBytes)
	if strings.IndexByte(text, 0) >= 0 {
		return "[binary or NUL-containing content omitted]", truncated, nil
	}
	return text, truncated, nil
}

func fenceLanguage(path string) string {
	switch filepath.Ext(path) {
	case ".json":
		return "json"
	case ".patch":
		return "diff"
	default:
		return ""
	}
}
