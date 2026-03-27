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

type openAIStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type openAICompatibleRequest struct {
	Model         string               `json:"model"`
	Messages      []ChatMessage        `json:"messages"`
	Stream        bool                 `json:"stream"`
	MaxTokens     *int                 `json:"max_tokens,omitempty"`
	StreamOptions *openAIStreamOptions `json:"stream_options,omitempty"`
}

// OpenAIAdapter covers openai, openai-compatible, and selfhosted — all use /v1/chat/completions.
type OpenAIAdapter struct {
	name       string // ProviderOpenAI | ProviderOpenAICompatible | ProviderSelfHosted
	baseURL    string
	model      string
	httpClient *http.Client
	keyPool    interface{ Pick() string }
}

func NewOpenAIAdapter(name, baseURL string) *OpenAIAdapter {
	keyEnv, modelEnv := "", ""
	switch name {
	case ProviderOpenAI:
		keyEnv, modelEnv = "OPENAI_API_KEY", "PROMPTSHIELD_OPENAI_MODEL"
	case ProviderSelfHosted:
		keyEnv, modelEnv = "SELFHOSTED_API_KEY", "PROMPTSHIELD_SELFHOSTED_MODEL"
	case ProviderOpenAICompatible:
		modelEnv = "PROMPTSHIELD_OPENAI_COMPATIBLE_MODEL"
	}
	return &OpenAIAdapter{
		name:       name,
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      resolveModel(modelEnv),
		httpClient: newHTTPClient(),
		keyPool:    buildKeyPool(keyEnv),
	}
}

func (a *OpenAIAdapter) Name() string      { return a.name }
func (a *OpenAIAdapter) Model() string     { return a.model }
func (a *OpenAIAdapter) RequiresKey() bool { return a.name == ProviderOpenAI }

func (a *OpenAIAdapter) ResolveAPIKey(r *http.Request) string {
	if key := strings.TrimSpace(r.Header.Get("x-llm-api-key")); key != "" {
		return key
	}
	if a.name == ProviderOpenAI {
		if key := strings.TrimSpace(r.Header.Get("x-openai-api-key")); key != "" {
			return key
		}
	}
	// Prefer configured key pool so the proxy acts as a key vault.
	if key := a.keyPool.Pick(); key != "" {
		return key
	}
	return apiKeyFromBearer(r)
}

func (a *OpenAIAdapter) Forward(ctx context.Context, requestID string, req *ChatRequest, apiKey string) (int, []byte, http.Header, io.ReadCloser, error) {
	model := a.model
	if req.Model != "" {
		model = req.Model
	}
	payload := openAICompatibleRequest{
		Model:     model,
		Messages:  req.Messages,
		Stream:    req.Stream,
		MaxTokens: req.MaxTokens,
	}
	// include_usage in streaming only for official OpenAI; compatible servers may not support it.
	if req.Stream && a.name == ProviderOpenAI {
		payload.StreamOptions = &openAIStreamOptions{IncludeUsage: true}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	url := fmt.Sprintf("%s/chat/completions", a.baseURL)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body)) //nolint:gosec // upstream URL is operator-configured
	if err != nil {
		return 0, nil, nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Request-ID", requestID)
	if apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
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

func (a *OpenAIAdapter) ExtractTokenUsage(body []byte) TokenUsage {
	return extractOpenAITokenUsage(body)
}

// ExtractStreamTokenUsage reads usage from the final streaming chunk.
// Skips chunks without "total_tokens" to avoid unmarshalling null usage objects.
func (a *OpenAIAdapter) ExtractStreamTokenUsage(payload []byte, prior TokenUsage) TokenUsage {
	if !bytes.Contains(payload, []byte(`"total_tokens"`)) {
		return prior
	}
	u := extractOpenAITokenUsage(payload)
	if u.TotalTokens > 0 {
		return u
	}
	return prior
}

func (a *OpenAIAdapter) ScanResponse(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte {
	return scanOpenAIChoices(ctx, body, maskFn)
}
