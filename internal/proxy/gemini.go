package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type geminiPart struct {
	Text string `json:"text"`
}

type geminiContent struct {
	Role  string       `json:"role"`
	Parts []geminiPart `json:"parts"`
}

type geminiSystemInstruction struct {
	Parts []geminiPart `json:"parts"`
}

type geminiGenerationConfig struct {
	MaxOutputTokens int `json:"maxOutputTokens,omitempty"`
}

type geminiRequest struct {
	SystemInstruction *geminiSystemInstruction `json:"systemInstruction,omitempty"`
	Contents          []geminiContent          `json:"contents"`
	GenerationConfig  *geminiGenerationConfig  `json:"generationConfig,omitempty"`
}

type GeminiAdapter struct {
	baseURL    string
	model      string
	httpClient *http.Client
	keyPool    interface{ Pick() string }
}

func NewGeminiAdapter(baseURL string) *GeminiAdapter {
	return &GeminiAdapter{
		baseURL:    strings.TrimRight(baseURL, "/"),
		model:      resolveModel("PROMPTSHIELD_GEMINI_MODEL"),
		httpClient: newHTTPClient(),
		keyPool:    buildKeyPool("GEMINI_API_KEY"),
	}
}

func (a *GeminiAdapter) Name() string      { return ProviderGemini }
func (a *GeminiAdapter) Model() string     { return a.model }
func (a *GeminiAdapter) RequiresKey() bool { return true }

func (a *GeminiAdapter) ResolveAPIKey(r *http.Request) string {
	if key := strings.TrimSpace(r.Header.Get("x-llm-api-key")); key != "" {
		return key
	}
	if key := strings.TrimSpace(r.Header.Get("x-gemini-api-key")); key != "" {
		return key
	}
	// Prefer the configured key pool over the incoming Bearer token so the proxy
	// acts as a key vault (e.g. OpenClaw sends a placeholder Bearer value).
	// Bearer passthrough is only used when no pool key is configured.
	if key := a.keyPool.Pick(); key != "" {
		return key
	}
	return apiKeyFromBearer(r)
}

func (a *GeminiAdapter) Forward(ctx context.Context, requestID string, req *ChatRequest, apiKey string) (int, []byte, http.Header, io.ReadCloser, error) {
	contents, sysInst := toGeminiContents(req.Messages)
	var genConfig *geminiGenerationConfig
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		genConfig = &geminiGenerationConfig{MaxOutputTokens: *req.MaxTokens}
	}
	gemReq := geminiRequest{SystemInstruction: sysInst, Contents: contents, GenerationConfig: genConfig}
	body, err := json.Marshal(gemReq)
	if err != nil {
		return 0, nil, nil, nil, err
	}

	model := a.model
	if req.Model != "" {
		model = req.Model
	}
	endpoint := "generateContent"
	if req.Stream {
		endpoint = "streamGenerateContent?alt=sse"
	}
	reqURL := fmt.Sprintf("%s/models/%s:%s", a.baseURL, url.PathEscape(model), endpoint)

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body)) //nolint:gosec // upstream URL is operator-configured
	if err != nil {
		return 0, nil, nil, nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Request-ID", requestID)
	if req.Stream {
		httpReq.Header.Set("Accept", "text/event-stream")
	}
	if apiKey != "" {
		httpReq.Header.Set("x-goog-api-key", apiKey)
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

// ExtractStreamTokenUsage reads usageMetadata from each Gemini streaming chunk.
// Gemini includes cumulative counts in every event; the last non-zero value is authoritative.
func (a *GeminiAdapter) ExtractStreamTokenUsage(payload []byte, prior TokenUsage) TokenUsage {
	if !bytes.Contains(payload, []byte(`"usageMetadata"`)) {
		return prior
	}
	u := a.ExtractTokenUsage(payload)
	if u.TotalTokens > 0 {
		return u
	}
	return prior
}

// ExtractTokenUsage reads from Gemini's native usageMetadata field.
func (a *GeminiAdapter) ExtractTokenUsage(body []byte) TokenUsage {
	var root struct {
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}
	if err := json.Unmarshal(body, &root); err != nil {
		return TokenUsage{}
	}
	return TokenUsage{
		PromptTokens:     root.UsageMetadata.PromptTokenCount,
		CompletionTokens: root.UsageMetadata.CandidatesTokenCount,
		TotalTokens:      root.UsageMetadata.TotalTokenCount,
	}
}

// ScanResponse walks Gemini's native candidates and applies maskFn to text parts.
// Gemini: {"candidates":[{"content":{"parts":[{"text":"..."}]}}]}
func (a *GeminiAdapter) ScanResponse(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return body
	}
	candidates, ok := root["candidates"].([]any)
	if !ok {
		return body
	}
	changed := false
	for i, cand := range candidates {
		cm, ok := cand.(map[string]any)
		if !ok {
			continue
		}
		content, ok := cm["content"].(map[string]any)
		if !ok {
			continue
		}
		parts, ok := content["parts"].([]any)
		if !ok {
			continue
		}
		for j, part := range parts {
			pm, ok := part.(map[string]any)
			if !ok {
				continue
			}
			text, ok := pm["text"].(string)
			if !ok || text == "" {
				continue
			}
			if masked, didMask := maskFn(ctx, text); didMask {
				pm["text"] = masked
				parts[j] = pm
				changed = true
			}
		}
		content["parts"] = parts
		cm["content"] = content
		candidates[i] = cm
	}
	if !changed {
		return body
	}
	root["candidates"] = candidates
	out, err := json.Marshal(root)
	if err != nil {
		return body
	}
	return out
}

// toGeminiContents converts OpenAI-style messages to Gemini's systemInstruction + contents.
func toGeminiContents(messages []ChatMessage) ([]geminiContent, *geminiSystemInstruction) {
	var systemParts []geminiPart
	contents := make([]geminiContent, 0, len(messages))

	for _, msg := range messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		switch role {
		case "system":
			systemParts = append(systemParts, geminiPart{Text: msg.Content})
		case "assistant":
			contents = append(contents, geminiContent{
				Role:  "model", // Gemini uses "model", not "assistant"
				Parts: []geminiPart{{Text: msg.Content}},
			})
		default: // "user" and anything unrecognised
			contents = append(contents, geminiContent{
				Role:  "user",
				Parts: []geminiPart{{Text: msg.Content}},
			})
		}
	}

	var sysInst *geminiSystemInstruction
	if len(systemParts) > 0 {
		sysInst = &geminiSystemInstruction{Parts: systemParts}
	}
	return contents, sysInst
}
