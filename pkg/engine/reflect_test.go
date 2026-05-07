package engine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReflectClient_SelectsSchemaCapableModel(t *testing.T) {
	var requestedModel string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_, _ = w.Write([]byte(`{"models":[
				{"id":"json-only","provider":"openai","capabilities":{"json_mode":true}},
				{"id":"schema","provider":"openai","endpoint":"responses","capabilities":{"response_format":{"json_schema":true}}}
			]}`))
		case http.MethodPost:
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decoding request: %v", err)
			}
			requestedModel, _ = req["model"].(string)
			if _, ok := req["response_format"].(map[string]any); !ok {
				t.Fatalf("expected response_format in request: %#v", req)
			}
			_, _ = w.Write([]byte(`{"output_text":"{\"prompt_injection\":false,\"secret_leak\":false,\"malicious_patch\":false,\"reasons\":[]}"}`))
		default:
			t.Fatalf("unexpected method %s", r.Method)
		}
	}))
	defer server.Close()

	result, err := (&ReflectClient{BaseURL: server.URL}).AnalyzeStructured(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsSafe() {
		t.Fatal("expected safe result")
	}
	if requestedModel != "schema" {
		t.Fatalf("requested model = %q, want schema", requestedModel)
	}
}

func TestReflectClient_RejectsUnsupportedPreferredModel(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"models":[{"id":"plain","provider":"openai","capabilities":{}}]}`))
	}))
	defer server.Close()

	_, err := (&ReflectClient{BaseURL: server.URL, Model: "plain"}).AnalyzeStructured(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected unsupported model error")
	}
}

func TestReflectClient_RetriesMalformedResponse(t *testing.T) {
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"models":[{"id":"schema","provider":"openai","capabilities":{"json_schema":true}}]}`))
			return
		}
		posts++
		if posts == 1 {
			_, _ = w.Write([]byte(`{"output_text":"not json"}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"prompt_injection\":true,\"secret_leak\":false,\"malicious_patch\":false,\"reasons\":[\"uncertain\"]}"}}]}`))
	}))
	defer server.Close()

	result, err := (&ReflectClient{BaseURL: server.URL, Retries: 1}).AnalyzeStructured(context.Background(), "prompt")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.PromptInjection || posts != 2 {
		t.Fatalf("expected retry with prompt_injection=true, posts=%d result=%#v", posts, result)
	}
}

func TestReflectClient_GeminiAndAnthropicRequests(t *testing.T) {
	tests := []struct {
		name         string
		models       string
		wantTopLevel string
	}{
		{
			name:         "gemini",
			models:       `{"models":[{"id":"gemini-2.5","provider":"gemini","capabilities":{"response_schema":true}}]}`,
			wantTopLevel: "generation_config",
		},
		{
			name:         "anthropic",
			models:       `{"models":[{"id":"claude","provider":"anthropic","capabilities":{"tools.input_schema":true,"forced_tool_choice":true}}]}`,
			wantTopLevel: "tools",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(tt.models))
					return
				}
				var req map[string]any
				if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
					t.Fatal(err)
				}
				if _, ok := req[tt.wantTopLevel]; !ok {
					t.Fatalf("expected %s in request: %#v", tt.wantTopLevel, req)
				}
				_, _ = w.Write([]byte(`{"prompt_injection":false,"secret_leak":false,"malicious_patch":false,"reasons":[]}`))
			}))
			defer server.Close()
			if _, err := (&ReflectClient{BaseURL: server.URL}).AnalyzeStructured(context.Background(), "prompt"); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
