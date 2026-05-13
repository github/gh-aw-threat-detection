package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/github/gh-aw-threat-detection/pkg/detector"
)

// ReflectClient calls the local api-proxy /reflect endpoint for structured detection.
type ReflectClient struct {
	BaseURL    string
	HTTPClient *http.Client
	Model      string
	Retries    int
	Timeout    time.Duration
}

const (
	maxModelListBytes       = 4 << 20
	maxReflectResponseBytes = 8 << 20
	maxErrorPreviewBytes    = 512

	reflectCorrectionSummary     = "Your previous response was invalid"
	reflectCorrectionInstruction = "Return only the strict JSON object matching the requested schema."
)

// AnalyzeStructured sends a prompt through /reflect and parses a strict Result.
func (c *ReflectClient) AnalyzeStructured(ctx context.Context, prompt string) (*detector.Result, error) {
	model, err := c.selectModel(ctx)
	if err != nil {
		return nil, err
	}
	attempts := c.Retries + 1
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	currentPrompt := prompt
	for i := 0; i < attempts; i++ {
		body, err := c.postReflect(ctx, buildReflectRequest(model, currentPrompt))
		if err != nil {
			return nil, err
		}
		result, err := parseReflectResult(body)
		if err == nil {
			return result, nil
		}
		lastErr = err
		currentPrompt = detector.BuildCorrectionPrompt(prompt, reflectCorrectionSummary, err.Error(), reflectCorrectionInstruction)
	}
	return nil, lastErr
}

func (c *ReflectClient) selectModel(ctx context.Context) (ReflectModel, error) {
	models, err := c.ListModels(ctx)
	if err != nil {
		return ReflectModel{}, err
	}
	if len(models) == 0 {
		return ReflectModel{}, fmt.Errorf("reflect did not advertise any models")
	}
	if c.Model != "" {
		for _, model := range models {
			if model.ID == c.Model {
				if !model.supportsStructured() {
					return ReflectModel{}, fmt.Errorf("reflect model %q does not advertise structured output support", c.Model)
				}
				return model, nil
			}
		}
		return ReflectModel{}, fmt.Errorf("reflect model %q not found", c.Model)
	}
	sort.SliceStable(models, func(i, j int) bool {
		if models[i].priority() == models[j].priority() {
			return models[i].ID < models[j].ID
		}
		return models[i].priority() > models[j].priority()
	})
	if !models[0].supportsStructured() {
		return ReflectModel{}, fmt.Errorf("no reflect model advertises structured output support")
	}
	return models[0], nil
}

// ListModels retrieves and normalizes available /reflect models.
func (c *ReflectClient) ListModels(ctx context.Context) ([]ReflectModel, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(), nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("listing reflect models: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxModelListBytes))
	if err != nil {
		return nil, fmt.Errorf("reading reflect model list: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("listing reflect models returned %s: %s", resp.Status, responseBodyPreview(body))
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("parsing reflect model list: %w", err)
	}
	return normalizeModels(decoded), nil
}

func (c *ReflectClient) postReflect(ctx context.Context, payload map[string]any) ([]byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling reflect: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxReflectResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("reading reflect response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("reflect returned %s: %s", resp.Status, responseBodyPreview(body))
	}
	return body, nil
}

func (c *ReflectClient) endpoint() string {
	base := strings.TrimSpace(c.BaseURL)
	if base == "" {
		base = DefaultReflectURL
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if !strings.HasSuffix(u.Path, "/reflect") {
		u.Path += "/reflect"
	}
	return u.String()
}

func responseBodyPreview(body []byte) string {
	if len(body) <= maxErrorPreviewBytes {
		return string(body)
	}
	return string(body[:maxErrorPreviewBytes]) + "...(truncated)"
}

func (c *ReflectClient) httpClient() *http.Client {
	if c.HTTPClient != nil {
		return c.HTTPClient
	}
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &http.Client{Timeout: timeout}
}

func normalizeModels(decoded any) []ReflectModel {
	var items []any
	switch typed := decoded.(type) {
	case []any:
		items = typed
	case map[string]any:
		for _, key := range []string{"models", "data"} {
			if arr, ok := typed[key].([]any); ok {
				items = arr
				break
			}
		}
	}
	models := make([]ReflectModel, 0, len(items))
	for _, item := range items {
		raw, ok := item.(map[string]any)
		if !ok {
			continue
		}
		id := firstString(raw, "id", "name", "model")
		if id == "" {
			continue
		}
		caps, _ := raw["capabilities"].(map[string]any)
		models = append(models, ReflectModel{
			ID:           id,
			Provider:     firstString(raw, "provider", "vendor"),
			Endpoint:     firstString(raw, "endpoint", "endpoint_style", "api"),
			Capabilities: caps,
			raw:          raw,
		})
	}
	return models
}

func buildReflectRequest(model ReflectModel, prompt string) map[string]any {
	schemaName := "threat_detection_result"
	req := map[string]any{
		"model": model.ID,
	}
	switch model.structuredMode() {
	case modeGeminiSchema:
		req["contents"] = []map[string]any{{"role": "user", "parts": []map[string]string{{"text": prompt}}}}
		req["generation_config"] = map[string]any{
			"response_mime_type": "application/json",
			"response_schema":    detector.ResultJSONSchema,
		}
	case modeAnthropicTool:
		req["messages"] = []map[string]string{{"role": "user", "content": prompt}}
		req["tools"] = []map[string]any{{
			"name":         schemaName,
			"description":  "Return the threat detection result.",
			"input_schema": detector.ResultJSONSchema,
		}}
		req["tool_choice"] = map[string]string{"type": "tool", "name": schemaName}
	case modeJSON:
		req["messages"] = []map[string]string{{"role": "user", "content": prompt}}
		req["response_format"] = map[string]string{"type": "json_object"}
	default:
		if strings.EqualFold(model.Endpoint, "responses") {
			req["input"] = prompt
		} else {
			req["messages"] = []map[string]string{{"role": "user", "content": prompt}}
		}
		req["response_format"] = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   schemaName,
				"strict": true,
				"schema": detector.ResultJSONSchema,
			},
		}
	}
	return req
}

func parseReflectResult(body []byte) (*detector.Result, error) {
	if result, err := detector.ParseStructuredResult(bytes.TrimSpace(body)); err == nil {
		return result, nil
	}
	var decoded any
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("reflect response is not JSON: %w", err)
	}
	for _, candidate := range collectResultCandidates(decoded) {
		if result, err := detector.ParseStructuredResult([]byte(candidate)); err == nil {
			return result, nil
		}
	}
	return nil, fmt.Errorf("reflect response did not contain a valid structured threat result")
}

func collectResultCandidates(v any) []string {
	var out []string
	switch typed := v.(type) {
	case string:
		out = append(out, typed)
	case map[string]any:
		if looksLikeResultMap(typed) {
			if data, err := json.Marshal(typed); err == nil {
				out = append(out, string(data))
			}
		}
		// Intentionally search only response/output fields. Do not recurse into
		// request echo fields such as "input", or prompt examples could be parsed.
		// See TestReflectClient_DoesNotParseEchoedInput.
		for _, key := range []string{"output_text", "output", "content", "text", "result"} {
			if val, ok := typed[key]; ok {
				out = append(out, collectResultCandidates(val)...)
			}
		}
		for _, key := range []string{"choices", "candidates", "parts"} {
			if val, ok := typed[key]; ok {
				out = append(out, collectResultCandidates(val)...)
			}
		}
		if msg, ok := typed["message"]; ok {
			out = append(out, collectResultCandidates(msg)...)
		}
	case []any:
		for _, item := range typed {
			out = append(out, collectResultCandidates(item)...)
		}
	}
	return out
}

func looksLikeResultMap(m map[string]any) bool {
	_, a := m["prompt_injection"]
	_, b := m["secret_leak"]
	_, c := m["malicious_patch"]
	_, d := m["reasons"]
	return a && b && c && d
}

func firstString(raw map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := raw[key].(string); ok {
			return v
		}
	}
	return ""
}
