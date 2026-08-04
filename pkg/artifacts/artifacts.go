// Package artifacts handles reading and validating threat detection input artifacts.
// Artifacts are the files produced by the agent job that the detection tool analyzes.
package artifacts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	maxAWInfoBytes      = 64 * 1024
	maxActivationValue  = 512
	activationInfoName  = "aw_info.json"
	artifactPromptDir   = "aw-prompts"
	artifactAgentOutput = "agent_output.json"
	artifactPrompt      = "aw-prompts/prompt.txt"
	artifactTemplate    = "aw-prompts/prompt-template.txt"
	artifactImportTree  = "aw-prompts/prompt-import-tree.json"
)

// Default workflow-context values used when neither the corresponding flag nor
// environment variable supplies one. They are exported so callers (e.g. the CLI)
// can detect when a value was defaulted rather than provided, which is useful
// for diagnosing dropped workflow-context plumbing.
const (
	DefaultWorkflowName        = "Unnamed Workflow"
	DefaultWorkflowDescription = "No description provided"
)

// InventoryEntry describes a file discovered below the artifacts directory.
type InventoryEntry struct {
	Path     string `json:"path"`
	Size     int64  `json:"size"`
	Kind     string `json:"kind"`
	Consumed bool   `json:"consumed"`
}

// ActivationContext is the bounded, allowlisted subset of aw_info.json exposed
// to the detection model. Every value is treated as untrusted runtime data.
type ActivationContext struct {
	EventName    string         `json:"event_name,omitempty"`
	Actor        string         `json:"actor,omitempty"`
	EngineID     string         `json:"engine_id,omitempty"`
	Model        string         `json:"model,omitempty"`
	WorkflowName string         `json:"workflow_name,omitempty"`
	Repository   string         `json:"repository,omitempty"`
	TargetRepo   string         `json:"target_repo,omitempty"`
	Ref          string         `json:"ref,omitempty"`
	SHA          string         `json:"sha,omitempty"`
	RunID        string         `json:"run_id,omitempty"`
	RunNumber    string         `json:"run_number,omitempty"`
	RunAttempt   string         `json:"run_attempt,omitempty"`
	Context      *CallerContext `json:"context,omitempty"`
}

// CallerContext identifies an upstream workflow that dispatched this run.
type CallerContext struct {
	Repo           string `json:"repo,omitempty"`
	RunID          string `json:"run_id,omitempty"`
	WorkflowID     string `json:"workflow_id,omitempty"`
	WorkflowCallID string `json:"workflow_call_id,omitempty"`
	Actor          string `json:"actor,omitempty"`
	EventType      string `json:"event_type,omitempty"`
	ItemType       string `json:"item_type,omitempty"`
	ItemNumber     string `json:"item_number,omitempty"`
	CommentID      string `json:"comment_id,omitempty"`
}

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

	// ActivationContext is the allowlisted activation metadata from aw_info.json.
	ActivationContext *ActivationContext

	// Inventory lists every non-directory entry found below Dir.
	Inventory []InventoryEntry

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

	// MissingRequired lists the expected-but-absent artifacts that a strict
	// host treats as a setup failure: the agent output file, the expanded
	// prompt file, and — when the host declares HAS_PATCH=true — at least one
	// patch or bundle file. Each entry is prefixed with an error code. Loading
	// never fails on these; the caller decides whether they are fatal (see the
	// GH_AW_DETECTION_CONTINUE_ON_ERROR handling in the CLI).
	MissingRequired []string
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("opening artifacts directory: %w", err)
	}
	defer root.Close()

	arts := &Artifacts{
		Dir:                 dir,
		WorkflowName:        envOrDefault("WORKFLOW_NAME", DefaultWorkflowName),
		WorkflowDescription: envOrDefault("WORKFLOW_DESCRIPTION", DefaultWorkflowDescription),
		CustomPrompt:        os.Getenv("CUSTOM_PROMPT"),
	}

	inventory, err := buildInventory(dir)
	if err != nil {
		return nil, err
	}
	arts.Inventory = inventory

	// Check for prompt file
	promptPath := filepath.Join(dir, artifactPromptDir, "prompt.txt")
	if fileExists(promptPath) {
		arts.PromptFilePath = promptPath
	} else {
		arts.PromptFilePath = "No prompt file found"
	}

	// Check for prompt template file (pre-expansion template)
	promptTemplatePath := filepath.Join(dir, artifactPromptDir, "prompt-template.txt")
	if fileExists(promptTemplatePath) {
		arts.PromptTemplatePath = promptTemplatePath
	}

	// Check for prompt import tree file (runtime-import provenance)
	promptImportTreePath := filepath.Join(dir, artifactPromptDir, "prompt-import-tree.json")
	if fileExists(promptImportTreePath) {
		arts.PromptImportTreePath = promptImportTreePath
	}

	// Check for agent output file
	agentOutputPath := filepath.Join(dir, artifactAgentOutput)
	if fileExists(agentOutputPath) {
		arts.AgentOutputFilePath = agentOutputPath
	} else {
		arts.AgentOutputFilePath = "No agent output file found"
	}

	awInfoPath := filepath.Join(dir, activationInfoName)
	if fileExists(awInfoPath) {
		context, err := loadActivationContext(root)
		if err != nil {
			return nil, err
		}
		arts.ActivationContext = context
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

	// Record (but never fail on) artifacts the host was expected to stage. The
	// CLI decides whether these are warnings or a configuration error.
	arts.checkRequired(dir, promptPath, agentOutputPath)

	return arts, nil
}

// checkRequired records the expected-but-absent artifacts described by
// MissingRequired. Error-code prefixes mirror gh-aw's detection setup so job
// logs categorize the same failure identically on both paths.
func (a *Artifacts) checkRequired(dir, promptPath, agentOutputPath string) {
	if !fileExists(agentOutputPath) {
		a.MissingRequired = append(a.MissingRequired,
			fmt.Sprintf("ERR_SYSTEM: Agent output file not found at: %s", agentOutputPath))
	}
	if !fileExists(promptPath) {
		a.MissingRequired = append(a.MissingRequired,
			fmt.Sprintf("ERR_VALIDATION: Prompt file not found at: %s", promptPath))
	}
	if os.Getenv("HAS_PATCH") == "true" && len(a.PatchFiles) == 0 {
		a.MissingRequired = append(a.MissingRequired,
			fmt.Sprintf("ERR_VALIDATION: Patch/bundle file(s) expected but not found in: %s", dir))
	}
}

// FormatActivationContext returns indented JSON for prompt rendering.
func (a *Artifacts) FormatActivationContext() string {
	if a == nil || a.ActivationContext == nil {
		return "No activation metadata found"
	}
	data, err := json.MarshalIndent(a.ActivationContext, "", "  ")
	if err != nil {
		return "No activation metadata found"
	}
	return string(data)
}

func buildInventory(dir string) ([]InventoryEntry, error) {
	var inventory []InventoryEntry
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return fmt.Errorf("reading artifact metadata for %s: %w", path, err)
		}
		relativePath, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("resolving artifact path %s: %w", path, err)
		}
		relativePath = filepath.ToSlash(relativePath)
		inventory = append(inventory, InventoryEntry{
			Path:     relativePath,
			Size:     info.Size(),
			Kind:     artifactKind(info),
			Consumed: isConsumedArtifact(relativePath),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("inventorying artifacts directory: %w", err)
	}
	return inventory, nil
}

func artifactKind(info os.FileInfo) string {
	switch {
	case info.Mode().IsRegular():
		return "file"
	case info.Mode()&os.ModeSymlink != 0:
		return "symlink"
	default:
		return "other"
	}
}

func isConsumedArtifact(path string) bool {
	switch path {
	case artifactPrompt, artifactTemplate, artifactImportTree, artifactAgentOutput, activationInfoName:
		return true
	}
	name := filepath.Base(path)
	return !strings.Contains(path, "/") &&
		strings.HasPrefix(name, "aw-") &&
		(strings.HasSuffix(name, ".patch") || strings.HasSuffix(name, ".bundle"))
}

func loadActivationContext(root *os.Root) (*ActivationContext, error) {
	file, err := root.Open(activationInfoName)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", activationInfoName, err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("reading %s metadata: %w", activationInfoName, err)
	}
	if info.Size() > maxAWInfoBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte limit", activationInfoName, maxAWInfoBytes)
	}

	decoder := json.NewDecoder(io.LimitReader(file, maxAWInfoBytes))
	decoder.UseNumber()
	var raw map[string]json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", activationInfoName, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("parsing %s: multiple JSON values", activationInfoName)
	}

	context := &ActivationContext{}
	fields := map[string]*string{
		"event_name":    &context.EventName,
		"actor":         &context.Actor,
		"engine_id":     &context.EngineID,
		"model":         &context.Model,
		"workflow_name": &context.WorkflowName,
		"repository":    &context.Repository,
		"target_repo":   &context.TargetRepo,
		"ref":           &context.Ref,
		"sha":           &context.SHA,
		"run_id":        &context.RunID,
		"run_number":    &context.RunNumber,
		"run_attempt":   &context.RunAttempt,
	}
	for name, destination := range fields {
		value, err := decodeScalar(raw[name], name)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", activationInfoName, err)
		}
		*destination = value
	}

	if contextRaw := raw["context"]; len(contextRaw) > 0 && !bytes.Equal(bytes.TrimSpace(contextRaw), []byte("null")) {
		var callerRaw map[string]json.RawMessage
		if err := json.Unmarshal(contextRaw, &callerRaw); err != nil {
			return nil, fmt.Errorf("parsing %s context: %w", activationInfoName, err)
		}
		caller := &CallerContext{}
		callerFields := map[string]*string{
			"repo":             &caller.Repo,
			"run_id":           &caller.RunID,
			"workflow_id":      &caller.WorkflowID,
			"workflow_call_id": &caller.WorkflowCallID,
			"actor":            &caller.Actor,
			"event_type":       &caller.EventType,
			"item_type":        &caller.ItemType,
			"item_number":      &caller.ItemNumber,
			"comment_id":       &caller.CommentID,
		}
		for name, destination := range callerFields {
			value, err := decodeScalar(callerRaw[name], "context."+name)
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", activationInfoName, err)
			}
			*destination = value
		}
		context.Context = caller
	}
	return context, nil
}

func decodeScalar(raw json.RawMessage, field string) (string, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", nil
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return "", fmt.Errorf("field %q: %w", field, err)
	}
	var text string
	switch typed := value.(type) {
	case string:
		text = typed
	case json.Number:
		text = typed.String()
	case bool:
		text = strconv.FormatBool(typed)
	default:
		return "", fmt.Errorf("field %q must be a scalar value", field)
	}
	if len(text) > maxActivationValue {
		return "", fmt.Errorf("field %q exceeds %d-byte limit", field, maxActivationValue)
	}
	return text, nil
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
