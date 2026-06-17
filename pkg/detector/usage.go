package detector

import (
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// Usage captures best-effort AI credit consumption for a single detection run.
// The detection job is a separate agentic engine pass, so this usage is billed
// to the configured engine independently of the main agentic run it guards.
type Usage struct {
	// Engine is the engine that produced the detection verdict (copilot, claude, codex).
	Engine string `json:"engine"`
	// Model is the model override forwarded to the engine, when one was set.
	Model string `json:"model,omitempty"`
	// Tokens is the total tokens (input + output, including cache tokens when
	// reported) attributed to the detection pass.
	Tokens int `json:"tokens"`
	// EstimatedCost is the engine-reported cost in USD, when the engine surfaces it.
	EstimatedCost float64 `json:"estimated_cost"`
	// Available reports whether any token or cost figure could be parsed from the
	// engine transcript. It is false when the engine does not surface usage on
	// stdout (for example copilot, which writes usage to its own debug log) or
	// when early termination truncated the transcript before usage was reported.
	Available bool `json:"available"`
}

// codexTokensUsedPattern matches Codex textual usage lines like "tokens used: 13934".
var codexTokensUsedPattern = regexp.MustCompile(`tokens used:\s*(\d+)`)

// codexTotalTokensPattern matches Codex structured usage like "total_tokens: 13281".
var codexTotalTokensPattern = regexp.MustCompile(`total_tokens:\s*(\d+)`)

// ParseUsage extracts best-effort token usage and estimated cost from an engine
// transcript (the engine's captured stdout). It scans line by line for JSON
// usage objects (Claude/Codex stream JSON: top-level input/output tokens, nested
// usage objects, and total_cost_usd) and for Codex textual token counters.
//
// The largest token figure and the largest cost figure observed are returned,
// because engines emit cumulative usage incrementally; the final line carries the
// running total. The result is best-effort: it may undercount when early
// termination kills the engine before its final usage line is emitted, and it is
// zero for engines that do not report usage on stdout.
func ParseUsage(transcript string) (tokens int, cost float64) {
	for _, line := range strings.Split(transcript, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if jsonTokens, jsonCost := parseUsageJSONLine(trimmed); jsonTokens > 0 || jsonCost > 0 {
			if jsonTokens > tokens {
				tokens = jsonTokens
			}
			if jsonCost > cost {
				cost = jsonCost
			}
		}

		if textTokens := parseCodexTextTokens(trimmed); textTokens > tokens {
			tokens = textTokens
		}
	}
	return tokens, cost
}

// parseCodexTextTokens extracts a token count from a single Codex textual log
// line. It returns the first pattern that matches on the line; ParseUsage
// aggregates the largest count across all lines.
func parseCodexTextTokens(line string) int {
	if m := codexTokensUsedPattern.FindStringSubmatch(line); len(m) > 1 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	if m := codexTotalTokensPattern.FindStringSubmatch(line); len(m) > 1 {
		if n, err := strconv.Atoi(m[1]); err == nil {
			return n
		}
	}
	return 0
}

// parseUsageJSONLine extracts token usage and cost from a single JSON log line.
// Lines that are not, or do not embed, a JSON object yield (0, 0).
func parseUsageJSONLine(line string) (tokens int, cost float64) {
	jsonStr := line
	if !strings.HasPrefix(line, "{") || !strings.HasSuffix(line, "}") {
		openIdx := strings.Index(line, "{")
		closeIdx := strings.LastIndex(line, "}")
		if openIdx == -1 || closeIdx <= openIdx {
			return 0, 0
		}
		jsonStr = line[openIdx : closeIdx+1]
	}

	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil {
		return 0, 0
	}
	// Ensure the decoder consumed the entire input, mirroring json.Unmarshal
	// semantics. If extra non-whitespace content follows the first JSON value
	// (e.g. log noise that was sliced in by the openIdx/closeIdx heuristic),
	// reject the parse to avoid misattributing tokens/cost.
	if err := dec.Decode(new(json.RawMessage)); err != io.EOF {
		return 0, 0
	}
	return extractJSONTokens(data), extractJSONCost(data)
}

// extractJSONTokens mirrors the token extraction gh-aw applies to engine logs:
// top-level input/output tokens, single total fields, and nested usage objects
// in Claude (input_tokens/output_tokens/cache_*) and OpenAI (prompt_tokens/
// completion_tokens) shapes.
func extractJSONTokens(data map[string]any) int {
	if total := toInt(data["input_tokens"]) + toInt(data["output_tokens"]); total > 0 {
		return total
	}
	for _, field := range []string{"tokens", "token_count", "total_tokens"} {
		if n := toInt(data[field]); n > 0 {
			return n
		}
	}
	if usage, ok := data["usage"].(map[string]any); ok {
		input := toInt(usage["input_tokens"])
		output := toInt(usage["output_tokens"])
		if input == 0 {
			input = toInt(usage["prompt_tokens"])
		}
		if output == 0 {
			output = toInt(usage["completion_tokens"])
		}
		total := input + output +
			toInt(usage["cache_creation_input_tokens"]) +
			toInt(usage["cache_read_input_tokens"])
		if total > 0 {
			return total
		}
		for _, field := range []string{"tokens", "token_count", "total_tokens"} {
			if n := toInt(usage[field]); n > 0 {
				return n
			}
		}
	}
	return 0
}

// extractJSONCost mirrors the cost extraction gh-aw applies to engine logs,
// preferring total_cost_usd and falling back to other common cost fields.
func extractJSONCost(data map[string]any) float64 {
	costFields := []string{"total_cost_usd", "cost", "total_cost", "estimated_cost"}
	for _, field := range costFields {
		if c := toFloat(data[field]); c > 0 {
			return c
		}
	}
	if billing, ok := data["billing"].(map[string]any); ok {
		for _, field := range costFields {
			if c := toFloat(billing[field]); c > 0 {
				return c
			}
		}
	}
	return 0
}

// toInt converts a JSON-decoded value to an int, tolerating float64 and string
// encodings. Non-numeric values yield 0.
func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return int(i)
		}
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(n)); err == nil {
			return i
		}
	}
	return 0
}

// toFloat converts a JSON-decoded value to a float64, tolerating string
// encodings. Non-numeric values yield 0.
func toFloat(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case json.Number:
		if f, err := n.Float64(); err == nil {
			return f
		}
	case string:
		if f, err := strconv.ParseFloat(strings.TrimSpace(n), 64); err == nil {
			return f
		}
	}
	return 0
}
