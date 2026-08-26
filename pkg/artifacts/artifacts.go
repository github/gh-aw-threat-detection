// Package artifacts handles reading and validating threat detection input artifacts.
// Artifacts are the files produced by the agent job that the detection tool analyzes.
package artifacts

import (
	"bytes"
	"encoding/json"
	"errors"
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

// ErrCodeValidation mirrors the ERR_VALIDATION prefix used by gh-aw's
// error_codes.cjs so degraded-artifact warnings look identical whether they
// originate from gh-aw's inline detection path or this standalone detector.
const ErrCodeValidation = "ERR_VALIDATION"

// errCodeValidation is retained as an unexported alias for the historical
// spelling used inside this package.
const errCodeValidation = ErrCodeValidation

// ArtifactWarning records a single degraded-input finding: a human-readable
// message (already prefixed with the ERR_VALIDATION error code) plus the
// structured fields worth reporting individually.
type ArtifactWarning struct {
	// Message is the full warning text, ready to emit as
	// "::warning::" + Message in a GitHub Actions annotation.
	Message string
	// Field identifies which artifact the warning concerns (e.g. "prompt",
	// "agent_output", "patch"), for structured logging.
	Field string
	// Code is the stable error-code identifier (e.g. ErrCodeValidation) that
	// categorizes the warning. It matches the prefix embedded in Message and
	// is exposed as a separate field so downstream consumers (the result
	// contract, structured logs) can render code and message independently
	// without having to parse the prefix.
	Code string
	// RequiredInput is true when the warning concerns an artifact the host was
	// expected to stage (the prompt, the agent output, or a patch declared by
	// HAS_PATCH). A host running in strict mode
	// (GH_AW_DETECTION_CONTINUE_ON_ERROR="false") treats these as a setup
	// failure rather than a warning; other findings stay advisory in both modes.
	RequiredInput bool
}

// MessageBody returns Message with the leading "<Code>: " prefix stripped, if
// present. It is the form to surface in structured outputs that carry Code
// separately (for example, the result-contract warnings block), so the code
// is not repeated twice.
func (w ArtifactWarning) MessageBody() string {
	if w.Code == "" {
		return w.Message
	}
	prefix := w.Code + ": "
	return strings.TrimPrefix(w.Message, prefix)
}

// requiredInputFields are the ArtifactWarning fields that describe an artifact
// the host was expected to stage. They mirror the inputs gh-aw's detection
// setup validates before invoking the detector.
var requiredInputFields = map[string]bool{
	"prompt":       true,
	"agent_output": true,
	"patch":        true,
}

// UninspectableNotice renders the text handed to the detection model when a
// channel exists but could not be read. It exists because the alternative --
// telling the model the channel is empty -- is a fail-open bug: the model
// reports clean about content nobody looked at, and the run exits 0.
//
// The closing sentence is load-bearing in the other direction. A notice that
// only said "this could not be read" invites the model to treat the failure
// itself as suspicious, which would manufacture exactly the false positives
// this detector is being tightened to avoid. Staging failures are almost always
// misconfiguration; the correct response is to abstain on this channel, not to
// accuse.
func UninspectableNotice(what, reason string) string {
	return fmt.Sprintf(
		"%s was NOT analyzed: %s. Treat this channel as unexamined rather than empty, "+
			"and do not draw any conclusion about its contents. "+
			"This is a staging or configuration failure, not evidence of a threat: "+
			"do NOT report a threat on the basis of this notice alone.",
		what, reason)
}

// HasWarningForField reports whether a warning was recorded for the named
// artifact field. A warning means the artifact could not be inspected, which is
// distinct from the artifact being absent: an uninspectable channel must not be
// mistaken for one that does not exist.
func (a *Artifacts) HasWarningForField(field string) bool {
	if a == nil {
		return false
	}
	for _, w := range a.Warnings {
		if w.Field == field {
			return true
		}
	}
	return false
}

// HasRequiredInputWarnings reports whether any recorded warning concerns an
// artifact the host was expected to stage.
func (a *Artifacts) HasRequiredInputWarnings() bool {
	for _, w := range a.Warnings {
		if w.RequiredInput {
			return true
		}
	}
	return false
}

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

	// PromptFileSize is the size in bytes of the prompt file, or 0 if absent.
	PromptFileSize int64

	// AgentOutputFileSize is the size in bytes of the agent output file, or 0 if absent.
	AgentOutputFileSize int64

	// Warnings holds non-fatal validation warnings collected while loading
	// artifacts (for example, missing/empty prompt or agent output, an
	// unreadable comment-memory directory, or an expected-but-absent patch).
	// Each entry's Message is prefixed with an error code such as
	// ERR_VALIDATION. Callers are expected to surface each one as a GitHub
	// Actions ::warning:: annotation.
	Warnings []ArtifactWarning

	// AllPrimaryInputsMissing is true when the prompt, agent output, and any
	// patch/bundle files are all missing or empty simultaneously. This is a
	// fail-open red flag: the detector would otherwise analyze nothing and
	// return a clean verdict. Callers should treat this as a hard
	// configuration error rather than proceeding.
	AllPrimaryInputsMissing bool
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

	// Check for prompt file. Missing or zero-length is a degraded input:
	// detection continues with fallback workflow context (WORKFLOW_NAME/
	// WORKFLOW_DESCRIPTION), but the operator must be warned.
	promptPath := filepath.Join(dir, artifactPromptDir, "prompt.txt")
	promptSize, promptErr := fileSize(promptPath)
	promptMissing := promptErr != nil
	promptEmpty := promptErr == nil && promptSize == 0
	// A staged, non-empty prompt the detector cannot open yields no content:
	// the reader in BuildPromptAnalysis discards its error and analyzes an
	// empty string. Detect that here so it is reported as unexamined rather
	// than silently analyzed as empty.
	promptUnreadable := false
	if !promptMissing && !promptEmpty {
		if readErr := readableFile(promptPath); readErr != nil {
			promptUnreadable = true
			arts.addWarning("prompt", fmt.Sprintf(
				"%s: Detection context prompt at %s could not be read (%v). Its contents were not examined; detection will continue with fallback workflow context. This failure is not itself evidence of a threat.",
				errCodeValidation, promptPath, readErr))
		}
	}
	if !promptMissing {
		arts.PromptFilePath = promptPath
		arts.PromptFileSize = promptSize
	} else {
		arts.PromptFilePath = "No prompt file found"
	}
	if promptMissing {
		arts.addWarning("prompt", fmt.Sprintf(
			"%s: Missing detection context prompt at %s. Ensure the agent artifact includes aw-prompts/prompt.txt. Detection will continue with fallback workflow context.",
			errCodeValidation, promptPath))
	} else if promptEmpty {
		arts.addWarning("prompt", fmt.Sprintf(
			"%s: Detection context prompt at %s is empty. Detection will continue with fallback workflow context.",
			errCodeValidation, promptPath))
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

	// Check for agent output file. Missing, zero-length, or invalid JSON is a
	// degraded input: the detector cannot see the agent's structured output.
	agentOutputPath := filepath.Join(dir, artifactAgentOutput)
	agentOutputData, agentOutputErr := os.ReadFile(agentOutputPath)
	agentOutputMissing := agentOutputErr != nil
	agentOutputEmpty := agentOutputErr == nil && len(agentOutputData) == 0
	agentOutputInvalid := agentOutputErr == nil && len(agentOutputData) > 0 && !json.Valid(agentOutputData)
	if !agentOutputMissing {
		arts.AgentOutputFilePath = agentOutputPath
		arts.AgentOutputFileSize = int64(len(agentOutputData))
	} else {
		arts.AgentOutputFilePath = "No agent output file found"
	}
	switch {
	case agentOutputMissing:
		arts.addWarning("agent_output", fmt.Sprintf(
			"%s: Missing agent output file at %s. Detection will run without the agent's structured output.",
			errCodeValidation, agentOutputPath))
	case agentOutputEmpty:
		arts.addWarning("agent_output", fmt.Sprintf(
			"%s: Agent output file at %s is empty. Detection will run without the agent's structured output.",
			errCodeValidation, agentOutputPath))
	case agentOutputInvalid:
		arts.addWarning("agent_output", fmt.Sprintf(
			"%s: Agent output file at %s is not valid JSON. Detection will run without the agent's structured output.",
			errCodeValidation, agentOutputPath))
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

	// Build patch file info string. A patch/bundle only counts as "present"
	// for the checks below if it is a readable, non-empty regular file: a
	// zero-length or unreadable entry provides no actual patch context.
	var infos []string
	var unreadable []string
	hasReadablePatch := false
	for _, p := range arts.PatchFiles {
		info, statErr := os.Stat(p)
		if statErr != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s (%v)", p, statErr))
			continue
		}
		// Stat succeeding does not mean the contents can be read. Route an
		// unopenable patch through the same path as a failed stat so it is
		// described to the model as unexamined, counts as uninspectable for
		// eligibility, and never sets hasReadablePatch.
		if readErr := readableFile(p); readErr != nil {
			unreadable = append(unreadable, fmt.Sprintf("%s (%v)", p, readErr))
			continue
		}
		if info.Size() > 0 {
			hasReadablePatch = true
		}
		pType := "git-patch"
		if strings.HasSuffix(p, ".bundle") {
			pType = "git-bundle"
		}
		infos = append(infos, fmt.Sprintf("%s (%d bytes, %s)", p, info.Size(), pType))
	}
	if len(unreadable) > 0 {
		arts.addWarning("patch", fmt.Sprintf(
			"%s: Unable to inspect %d patch/bundle file(s) in %s: %s. Detection will run without their contents.",
			errCodeValidation, len(unreadable), dir, strings.Join(unreadable, ", ")))
	}
	switch {
	case len(infos) > 0 && len(unreadable) > 0:
		arts.PatchFileInfo = strings.Join(infos, "\n") + "\n" + UninspectableNotice(
			fmt.Sprintf("%d further patch/bundle file(s)", len(unreadable)),
			fmt.Sprintf("they could not be read (%s)", strings.Join(unreadable, ", ")))
	case len(infos) > 0:
		arts.PatchFileInfo = strings.Join(infos, "\n")
	case len(unreadable) > 0:
		arts.PatchFileInfo = UninspectableNotice(
			"Every patch/bundle file staged for this run",
			fmt.Sprintf("none could be read (%s)", strings.Join(unreadable, ", ")))
	default:
		arts.PatchFileInfo = "No patch or bundle file found"
	}

	// Cross-check against HAS_PATCH: gh-aw sets this env var when the agent
	// job reported a patch, so its absence here means the patch/bundle never
	// made it into the artifacts directory (or it is present but empty/unreadable).
	if os.Getenv("HAS_PATCH") == "true" && !hasReadablePatch {
		arts.addWarning("patch", fmt.Sprintf(
			"%s: HAS_PATCH=true was set but no readable, non-empty aw-*.patch or aw-*.bundle file was found in %s. Detection will run without patch context.",
			errCodeValidation, dir))
		if len(infos) == 0 && len(unreadable) == 0 {
			// The agent job produced a patch that never reached the artifacts
			// directory. Saying "no patch found" here would tell the model the
			// run made no changes, which is the opposite of what HAS_PATCH says.
			arts.PatchFileInfo = UninspectableNotice(
				"The patch produced by this run",
				fmt.Sprintf("the agent job reported a patch (HAS_PATCH=true) but no patch or bundle file reached %s", dir))
		}
	}

	// All three primary inputs missing simultaneously means the detector would
	// otherwise analyze nothing and return a clean verdict: a fail-open failure
	// mode in a security control. Flag it so the caller can hard-fail instead.
	arts.AllPrimaryInputsMissing = (promptMissing || promptEmpty || promptUnreadable) &&
		(agentOutputMissing || agentOutputEmpty || agentOutputInvalid) &&
		!hasReadablePatch

	// Discover comment-memory markdown files (an attacker-influenced, persisted
	// channel written by the agent). The directory is optional; when present but
	// unreadable we record a non-fatal ERR_VALIDATION warning and continue.
	arts.loadCommentMemory(dir)

	return arts, nil
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
			arts.addWarning("comment_memory", fmt.Sprintf(
				"%s: Unable to inspect comment-memory directory at %s: %v", errCodeValidation, commentMemoryDir, err))
			arts.CommentMemoryFileInfo = UninspectableNotice(
				"The comment-memory directory",
				fmt.Sprintf("%s could not be inspected (%v)", commentMemoryDir, err))
			return
		}
		arts.CommentMemoryFileInfo = "No comment-memory files found"
		return
	}
	// Reject anything that is not a real directory (regular files, symlinks,
	// FIFOs, etc.). This guard is deliberate -- following a symlink here would
	// let the run under analysis point the detector at markdown outside the
	// artifacts tree -- which makes the rejected path agent-reachable. Warn on
	// it rather than returning silently, so a bundle shaped this way is not
	// indistinguishable from one with no comment memory at all.
	if info.Mode().Type() != os.ModeDir {
		arts.addWarning("comment_memory", fmt.Sprintf(
			"%s: Expected %s to be a directory, found %s. Comment-memory files were not read. "+
				"Stage comment memory as a real directory: symlinks are refused because they can resolve outside the artifacts directory.",
			errCodeValidation, commentMemoryDir, describeFileType(info.Mode())))
		arts.CommentMemoryFileInfo = UninspectableNotice(
			"The comment-memory directory",
			fmt.Sprintf("%s exists but is %s rather than a directory, so it was refused", commentMemoryDir, describeFileType(info.Mode())))
		return
	}

	entries, err := os.ReadDir(commentMemoryDir)
	if err != nil {
		arts.addWarning("comment_memory", fmt.Sprintf(
			"%s: Unable to read comment-memory directory at %s: %v", errCodeValidation, commentMemoryDir, err))
		arts.CommentMemoryFileInfo = UninspectableNotice(
			"The comment-memory directory",
			fmt.Sprintf("%s could not be read (%v)", commentMemoryDir, err))
		return
	}

	var infos []string
	var refused []string
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		// Only accept confirmed regular files: symlinks could point outside the
		// artifacts tree and FIFOs/other special files could hang a read. Same
		// agent-reachable shape as the directory guard above, so it is recorded
		// rather than skipped silently.
		if !entry.Type().IsRegular() {
			refused = append(refused, fmt.Sprintf("%s (%s)", name, describeFileType(entry.Type())))
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

	if len(refused) > 0 {
		arts.addWarning("comment_memory", fmt.Sprintf(
			"%s: Skipped %d comment-memory entr%s in %s that %s not regular files: %s. "+
				"Stage comment memory as real files: symlinks and special files are refused because they can resolve outside the artifacts directory.",
			errCodeValidation, len(refused), pluralY(len(refused)), commentMemoryDir, pluralWere(len(refused)), strings.Join(refused, ", ")))
	}

	switch {
	case len(infos) > 0 && len(refused) > 0:
		arts.CommentMemoryFileInfo = strings.Join(infos, "\n") + "\n" + UninspectableNotice(
			fmt.Sprintf("%d further comment-memory file(s) in %s", len(refused), commentMemoryDir),
			"they are symlinks or special files rather than regular files, so they were refused")
	case len(infos) > 0:
		arts.CommentMemoryFileInfo = strings.Join(infos, "\n")
	case len(refused) > 0:
		arts.CommentMemoryFileInfo = UninspectableNotice(
			fmt.Sprintf("Every comment-memory file in %s", commentMemoryDir),
			"they are symlinks or special files rather than regular files, so they were refused")
	default:
		arts.CommentMemoryFileInfo = "No comment-memory files found"
	}
}

// describeFileType names a filesystem entry type for an operator-facing
// message, so a refusal says what was actually staged instead of only what was
// expected.
func describeFileType(mode os.FileMode) string {
	switch {
	case mode&os.ModeSymlink != 0:
		return "a symlink"
	case mode&os.ModeDir != 0:
		return "a directory"
	case mode&os.ModeNamedPipe != 0:
		return "a named pipe"
	case mode&os.ModeSocket != 0:
		return "a socket"
	case mode&os.ModeDevice != 0:
		return "a device file"
	case mode&os.ModeIrregular != 0:
		return "an irregular file"
	default:
		return "a regular file"
	}
}

func pluralY(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

func pluralWere(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// fileSize returns the size of the regular file at path, or an error if it
// does not exist or is not accessible.
func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// readableFile reports whether the detector can actually read path's contents.
//
// Stat is not sufficient. It succeeds on a file the process has no permission
// to open, and on one whose contents are unreadable for I/O reasons, so a
// stat-only check reports a non-empty size for a channel nothing can read. The
// callers then describe that channel to the model as present and inspected,
// which is the fail-open shape UninspectableNotice exists to prevent: the model
// reports clean about content nobody looked at.
//
// The probe opens the file and reads a byte, because permission is enforced at
// open and media errors only surface on read. io.EOF means an empty but
// perfectly readable file, so it is not a failure.
func readableFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	buf := make([]byte, 1)
	if _, err := f.Read(buf); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

// NewWarning builds an ERR_VALIDATION finding for the named artifact field,
// classifying it as concerning a required input from the same table Load uses.
// It exists so findings raised outside Load — the prompt analysis reads its
// inputs after loading — carry an identical classification and code rather than
// caller-chosen ones.
func NewWarning(field, message string) ArtifactWarning {
	return ArtifactWarning{
		Field:         field,
		Code:          errCodeValidation,
		Message:       message,
		RequiredInput: requiredInputFields[field],
	}
}

// addWarning records an ERR_VALIDATION finding on the Artifacts value.
func (a *Artifacts) addWarning(field, message string) {
	a.Warnings = append(a.Warnings, NewWarning(field, message))
}

func envOrDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
