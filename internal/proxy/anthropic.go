package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const anthropicVersion = "2023-06-01"

// defaultAnthropicMaxTokens is used when neither the request nor the policy specifies max_tokens.
// Anthropic's API requires the field; there is no server-side default.
const defaultAnthropicMaxTokens = 4096

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
	System    string             `json:"system,omitempty"`
	Stream    bool               `json:"stream,omitempty"`
}

type AnthropicAdapter struct {
	baseURL    string
	model      string
	httpClient *http.Client
	keyPool    interface{ Pick() string }
}

func NewAnthropicAdapter(baseURL string) *AnthropicAdapter {
	return &AnthropicAdapter{
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      resolveModel("PROMPTSHIELD_ANTHROPIC_MODEL"),
		httpClient: newHTTPClient(),
		keyPool:    buildKeyPool("ANTHROPIC_API_KEY"),
	}
}

func (a *AnthropicAdapter) Name() string      { return ProviderAnthropic }
func (a *AnthropicAdapter) Model() string     { return a.model }
func (a *AnthropicAdapter) RequiresKey() bool { return true }

func (a *AnthropicAdapter) ResolveAPIKey(r *http.Request) string {
	if key := strings.TrimSpace(r.Header.Get("x-llm-api-key")); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("x-anthropic-api-key")); key != "" {
		return key
	}
	if key := a.keyPool.Pick(); key != "" {
		return key
	}
	return apiKeyFromBearer(r)
}

func (a *AnthropicAdapter) Forward(ctx context.Context, requestID string, req *ChatRequest, apiKey string) (int, []byte, http.Header, io.ReadCloser, error) {
	model := a.model
	if req.Model != "" {
		model = req.Model
	}

	// Anthropic puts system messages in a top-level "system" field.
	var systemParts []string
	messages := make([]anthropicMessage, 0, len(req.Messages))
	for _, msg := range req.Messages {
		switch strings.ToLower(strings.TrimSpace(msg.Role)) {
		case "system":
			systemParts = append(systemParts, msg.Content)
		case "assistant":
			messages = append(messages, anthropicMessage{Role: "assistant", Content: msg.Content})
		default:
			messages = append(messages, anthropicMessage{Role: "user", Content: msg.Content})
		}
	}

	maxTokens := defaultAnthropicMaxTokens
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTokens = *req.MaxTokens
	}

	payload := anthropicRequest{
		Model:     model,
		MaxTokens: maxTokens,
		Messages:  messages,
		Stream:    req.Stream,
	}
	if len(systemParts) > 0 {
		payload.System = strings.Join(systemParts, "\n")
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	url := fmt.Sprintf("%s/messages", a.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)) //nolint:gosec // upstream URL is operator-configured
	if err != nil {
		return 0, nil, nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Request-ID", requestID)
	httpReq.Header.Set("anthropic-version", anthropicVersion)
	if apiKey != "" {
		httpReq.Header.Set("x-api-key", apiKey)
	}

	resp, err := doWithRetry(a.httpClient, httpReq, body, req.Stream)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	if req.Stream {
		return resp.StatusCode, nil, resp.Header.Clone(), resp.Body, nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return 0, nil, nil, nil, err
	}
	return resp.StatusCode, respBody, resp.Header.Clone(), nil, nil
}

// ExtractStreamTokenUsage accumulates token usage across Anthropic streaming events.
// input_tokens arrive in "message_start"; output_tokens arrive in "message_delta".
func (a *AnthropicAdapter) ExtractStreamTokenUsage(payload []byte, prior TokenUsage) TokenUsage {
	if !bytes.Contains(payload, []byte(`"usage"`)) {
		return prior
	}
	var event struct {
		Type    string `json:"type"`
		Message struct {
			Usage struct {
				InputTokens int `json:"input_tokens"`
			} `json:"usage"`
		} `json:"message"`
		Usage struct {
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		return prior
	}
	switch event.Type {
	case "message_start":
		prior.PromptTokens = event.Message.Usage.InputTokens
	case "message_delta":
		prior.CompletionTokens = event.Usage.OutputTokens
	}
	prior.TotalTokens = prior.PromptTokens + prior.CompletionTokens
	return prior
}

// ExtractTokenUsage reads from Anthropic's native response format.
func (a *AnthropicAdapter) ExtractTokenUsage(body []byte) TokenUsage {
	var root struct {
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return TokenUsage{}
	}
	in := root.Usage.InputTokens
	out := root.Usage.OutputTokens
	return TokenUsage{
		PromptTokens:     in,
		CompletionTokens: out,
		TotalTokens:      in + out,
	}
}

// ScanResponse walks Anthropic's content blocks and applies maskFn to text blocks.
func (a *AnthropicAdapter) ScanResponse(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return body
	}
	content, ok := root["content"].([]any)
	if !ok {
		return body
	}
	changed := false
	for i, block := range content {
		bm, ok := block.(map[string]any)
		if !ok || bm["type"] != "text" {
			continue
		}
		text, ok := bm["text"].(string)
		if !ok || text == "" {
			continue
		}
		if masked, didMask := maskFn(ctx, text); didMask {
			bm["text"] = masked
			content[i] = bm
			changed = true
		}
	}
	if !changed {
		return body
	}
	root["content"] = content
	out, err := json.Marshal(root)
	if err != nil {
		return body
	}
	return out
}
