// Package artifacts handles reading and validating threat detection input artifacts.
// Artifacts are the files produced by the agent job that the detection tool analyzes.
package artifacts

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Artifacts holds the loaded artifact information for threat detection.
type Artifacts struct {
	// Dir is the base artifacts directory path.
	Dir string

	// PromptFilePath is the path to the workflow prompt file.
	PromptFilePath string

	// PromptTemplatePath is the path to the prompt template file (before variable expansion).
	// This is used to distinguish trusted template content from untrusted user inputs.
	PromptTemplatePath string

	// AgentOutputFilePath is the path to the agent output JSON file.
	AgentOutputFilePath string

	// PatchFiles contains paths to any .patch or .bundle files.
	PatchFiles []string

	// PatchFileInfo is a human-readable description of patch files for template replacement.
	PatchFileInfo string

	// WorkflowName is the name of the workflow being analyzed.
	WorkflowName string

	// WorkflowDescription is the description of the workflow being analyzed.
	WorkflowDescription string

	// CustomPrompt contains additional detection instructions if provided.
	CustomPrompt string
}

// Load reads and validates artifacts from the given directory.
func Load(dir string) (*Artifacts, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("artifacts directory not accessible: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("artifacts path is not a directory: %s", dir)
	}

	arts := &Artifacts{
		Dir:                 dir,
		WorkflowName:        envOrDefault("WORKFLOW_NAME", "Unnamed Workflow"),
		WorkflowDescription: envOrDefault("WORKFLOW_DESCRIPTION", "No description provided"),
		CustomPrompt:        os.Getenv("CUSTOM_PROMPT"),
	}

	// Check for prompt file
	promptPath := filepath.Join(dir, "aw-prompts", "prompt.txt")
	if fileExists(promptPath) {
		arts.PromptFilePath = promptPath
	} else {
		arts.PromptFilePath = "No prompt file found"
	}

	// Check for prompt template file (pre-expansion template)
	promptTemplatePath := filepath.Join(dir, "aw-prompts", "prompt-template.txt")
	if fileExists(promptTemplatePath) {
		arts.PromptTemplatePath = promptTemplatePath
	}

	// Check for agent output file
	agentOutputPath := filepath.Join(dir, "agent_output.json")
	if fileExists(agentOutputPath) {
		arts.AgentOutputFilePath = agentOutputPath
	} else {
		arts.AgentOutputFilePath = "No agent output file found"
	}

	// Find patch/bundle files
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading artifacts directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, "aw-") && (strings.HasSuffix(name, ".patch") || strings.HasSuffix(name, ".bundle")) {
			arts.PatchFiles = append(arts.PatchFiles, filepath.Join(dir, name))
		}
	}

	// Build patch file info string
	if len(arts.PatchFiles) > 0 {
		var infos []string
		for _, p := range arts.PatchFiles {
			info, err := os.Stat(p)
			if err != nil {
				continue
			}
			pType := "git-patch"
			if strings.HasSuffix(p, ".bundle") {
				pType = "git-bundle"
			}
			infos = append(infos, fmt.Sprintf("%s (%d bytes, %s)", p, info.Size(), pType))
		}
		arts.PatchFileInfo = strings.Join(infos, "\n")
	} else {
		arts.PatchFileInfo = "No patch or bundle file found"
	}

	return arts, nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
