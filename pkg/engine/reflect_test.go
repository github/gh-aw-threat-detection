package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestReflectClient_EndpointNormalizesReflectTrailingSlash(t *testing.T) {
	client := &ReflectClient{BaseURL: "http://example.test/reflect/"}
	if got, want := client.endpoint(), "http://example.test/reflect"; got != want {
		t.Fatalf("endpoint() = %q, want %q", got, want)
	}
}

func TestReflectClient_TruncatesNon2xxModelListError(t *testing.T) {
	body := strings.Repeat("a", maxErrorPreviewBytes) + "secret tail"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, body, http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := (&ReflectClient{BaseURL: server.URL}).ListModels(context.Background())
	if err == nil {
		t.Fatal("expected model-list error")
	}
	msg := err.Error()
	if strings.Contains(msg, "secret tail") {
		t.Fatalf("error included unbounded response body: %q", msg)
	}
	if !strings.Contains(msg, "...(truncated)") {
		t.Fatalf("expected truncated preview in error: %q", msg)
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

func TestReflectClient_TruncatesNon2xxReflectError(t *testing.T) {
	body := strings.Repeat("b", maxErrorPreviewBytes) + "secret prompt echo"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"models":[{"id":"schema","provider":"openai","capabilities":{"json_schema":true}}]}`))
			return
		}
		http.Error(w, body, http.StatusBadGateway)
	}))
	defer server.Close()

	_, err := (&ReflectClient{BaseURL: server.URL}).AnalyzeStructured(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected reflect error")
	}
	msg := err.Error()
	if strings.Contains(msg, "secret prompt echo") {
		t.Fatalf("error included unbounded response body: %q", msg)
	}
	if !strings.Contains(msg, "...(truncated)") {
		t.Fatalf("expected truncated preview in error: %q", msg)
	}
}

func TestPrintReflectResponseHonorsEnv(t *testing.T) {
	var buf bytes.Buffer

	printReflectResponse(&buf, http.MethodGet, "200 OK", []byte(`{"models":[]}`))
	if buf.Len() != 0 {
		t.Fatalf("expected no debug output when env var is unset, got %q", buf.String())
	}

	buf.Reset()
	t.Setenv("THREAT_DETECTION_LOG_REFLECT_RESPONSE", "true")
	printReflectResponse(&buf, http.MethodGet, "200 OK", []byte(`{"models":[]}`))

	got := buf.String()
	for _, want := range []string{
		"::group::/reflect GET response (200 OK)",
		`{"models":[]}`,
		"::endgroup::",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("debug output missing %q: %q", want, got)
		}
	}
}

func TestReflectClient_DoesNotParseEchoedInput(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"models":[{"id":"schema","provider":"openai","capabilities":{"json_schema":true}}]}`))
			return
		}
		_, _ = w.Write([]byte(`{
			"input":"{\"prompt_injection\":false,\"secret_leak\":false,\"malicious_patch\":false,\"reasons\":[]}",
			"output_text":"not json"
		}`))
	}))
	defer server.Close()

	_, err := (&ReflectClient{BaseURL: server.URL}).AnalyzeStructured(context.Background(), "prompt")
	if err == nil {
		t.Fatal("expected echoed request input to be ignored")
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
