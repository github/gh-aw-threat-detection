package engine

import (
	"strings"
)

// ReflectModel describes one model advertised by api-proxy /reflect.
type ReflectModel struct {
	ID           string
	Provider     string
	Endpoint     string
	Capabilities map[string]any
	raw          map[string]any
}

type structuredMode int

const (
	modeUnsupported structuredMode = iota
	modeJSON
	modeJSONSchema
	modeGeminiSchema
	modeAnthropicTool
)

func (m ReflectModel) structuredMode() structuredMode {
	provider := strings.ToLower(m.Provider)
	if provider == "" {
		provider = strings.ToLower(stringValue(m.raw, "provider"))
	}
	if provider == "anthropic" && hasAnyCapability(m, "tool_schema", "tools.input_schema", "forced_tool_choice", "input_schema") {
		return modeAnthropicTool
	}
	if (provider == "gemini" || provider == "google" || strings.Contains(strings.ToLower(m.ID), "gemini")) &&
		hasAnyCapability(m, "response_schema", "generation_config.response_schema") {
		return modeGeminiSchema
	}
	if hasAnyCapability(m, "json_schema", "response_format.json_schema", "structured_output", "structured_outputs") {
		return modeJSONSchema
	}
	if hasAnyCapability(m, "json_mode", "response_format.json_object", "response_format.json") {
		return modeJSON
	}
	return modeUnsupported
}

func (m ReflectModel) supportsStructured() bool {
	return m.structuredMode() != modeUnsupported
}

func (m ReflectModel) priority() int {
	switch m.structuredMode() {
	case modeJSONSchema, modeGeminiSchema:
		return 3
	case modeAnthropicTool:
		return 2
	case modeJSON:
		return 1
	default:
		return 0
	}
}

func hasAnyCapability(m ReflectModel, keys ...string) bool {
	for _, key := range keys {
		if boolValue(m.Capabilities, key) || boolValue(m.raw, key) {
			return true
		}
	}
	return false
}

func boolValue(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	if v, ok := values[key]; ok {
		return truthy(v)
	}
	parts := strings.Split(key, ".")
	var cur any = values
	for _, part := range parts {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		cur, ok = m[part]
		if !ok {
			return false
		}
	}
	return truthy(cur)
}

func truthy(v any) bool {
	switch typed := v.(type) {
	case bool:
		return typed
	case string:
		// /reflect capability metadata is provider-normalized but may use strings
		// for supported features; these values all indicate advertised support.
		switch strings.ToLower(typed) {
		case "true", "supported", "strict", "json_schema", "schema", "required":
			return true
		}
	case map[string]any:
		return len(typed) > 0
	case []any:
		return len(typed) > 0
	}
	return false
}

func stringValue(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	if v, ok := values[key].(string); ok {
		return v
	}
	return ""
}
