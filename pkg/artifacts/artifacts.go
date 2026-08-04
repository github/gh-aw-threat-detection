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

	// PromptImportTreePath is the path to the prompt import tree JSON file.
	// This maps each runtime-import macro to its source file and content.
	PromptImportTreePath string

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

	// CommentMemoryFiles contains paths to any comment-memory markdown files.
	CommentMemoryFiles []string

	// CommentMemoryFileInfo is a human-readable description of comment-memory
	// files for template replacement.
	CommentMemoryFileInfo string

	// Warnings holds non-fatal validation warnings collected while loading
	// artifacts (for example, an unreadable comment-memory directory). Each
	// entry is prefixed with an error code such as ERR_VALIDATION.
	Warnings []string
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

	// Check for prompt import tree file (runtime-import provenance)
	promptImportTreePath := filepath.Join(dir, "aw-prompts", "prompt-import-tree.json")
	if fileExists(promptImportTreePath) {
		arts.PromptImportTreePath = promptImportTreePath
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

	// Discover comment-memory markdown files (an attacker-influenced, persisted
	// channel written by the agent). The directory is optional; when present but
	// unreadable we record a non-fatal ERR_VALIDATION warning and continue.
	arts.loadCommentMemory(dir)

	return arts, nil
}

func (arts *Artifacts) loadCommentMemory(dir string) {
	commentMemoryDir := filepath.Join(dir, "comment-memory")
	// Use Lstat so a symlink named comment-memory is not followed: a symlinked
	// directory would let the engine read markdown outside the artifacts tree.
	info, err := os.Lstat(commentMemoryDir)
	if err != nil {
		if !os.IsNotExist(err) {
			arts.Warnings = append(arts.Warnings, fmt.Sprintf(
				"ERR_VALIDATION: Unable to inspect comment-memory directory at %s: %v", commentMemoryDir, err))
		}
		arts.CommentMemoryFileInfo = "No comment-memory files found"
		return
	}
	// Reject anything that is not a real directory (regular files, symlinks,
	// FIFOs, etc.).
	if info.Mode().Type() != os.ModeDir {
		arts.CommentMemoryFileInfo = "No comment-memory files found"
		return
	}

	entries, err := os.ReadDir(commentMemoryDir)
	if err != nil {
		arts.Warnings = append(arts.Warnings, fmt.Sprintf(
			"ERR_VALIDATION: Unable to read comment-memory directory at %s: %v", commentMemoryDir, err))
		arts.CommentMemoryFileInfo = "No comment-memory files found"
		return
	}

	var infos []string
	for _, entry := range entries {
		// Only accept confirmed regular files: symlinks could point outside the
		// artifacts tree and FIFOs/other special files could hang a read.
		if !entry.Type().IsRegular() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		p := filepath.Join(commentMemoryDir, name)
		arts.CommentMemoryFiles = append(arts.CommentMemoryFiles, p)
		if fi, statErr := os.Stat(p); statErr == nil {
			infos = append(infos, fmt.Sprintf("%s (%d bytes)", p, fi.Size()))
		} else {
			infos = append(infos, p)
		}
	}

	if len(infos) > 0 {
		arts.CommentMemoryFileInfo = strings.Join(infos, "\n")
	} else {
		arts.CommentMemoryFileInfo = "No comment-memory files found"
	}
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
