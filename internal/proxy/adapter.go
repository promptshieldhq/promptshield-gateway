package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/promptshieldhq/promptshield-proxy/internal/config"
)

const (
	ProviderGemini           = "gemini"
	ProviderOpenAI           = "openai"
	ProviderAnthropic        = "anthropic"
	ProviderOpenAICompatible = "openai-compatible"
	ProviderSelfHosted       = "selfhosted"
)

const maxResponseBytes = 10 << 20 // 10 MiB — upstream LLM response

// AdapterRouter is an optional interface for adapters that route by model name (MultiAdapter).
type AdapterRouter interface {
	Route(model string) Adapter
}

// Adapter is the interface upstream LLM providers must implement.
type Adapter interface {
	Name() string
	Model() string
	RequiresKey() bool
	ResolveAPIKey(r *http.Request) string
	// Forward sends the request upstream. For streaming, body is nil and stream is non-nil; for
	// non-streaming the inverse holds. The caller owns closing stream.
	Forward(ctx context.Context, requestID string, req *ChatRequest, apiKey string) (status int, body []byte, headers http.Header, stream io.ReadCloser, err error)
	ExtractTokenUsage(body []byte) TokenUsage
	// ExtractStreamTokenUsage extracts token counts from a single SSE data-line payload,
	// accumulating into prior. Returns prior unchanged if the line carries no usage data.
	ExtractStreamTokenUsage(payload []byte, prior TokenUsage) TokenUsage
	// ScanResponse applies maskFn to text fields in the response body; returns original on error.
	ScanResponse(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte
}

type TokenUsage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// ── Shared provider helpers ────────────────────────────────────────────────────

// resolveModel returns the configured model. PROMPTSHIELD_MODEL is a global override;
// providerEnvKey is the provider-specific fallback.
func resolveModel(providerEnvKey string) string {
	if m := strings.TrimSpace(os.Getenv("PROMPTSHIELD_MODEL")); m != "" {
		return m
	}
	if providerEnvKey == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(providerEnvKey))
}

// buildKeyPool returns a KeyPool from providerEnvKey, falling back to PROMPTSHIELD_UPSTREAM_API_KEY.
func buildKeyPool(providerEnvKey string) *config.KeyPool {
	if providerEnvKey != "" {
		if raw := strings.TrimSpace(os.Getenv(providerEnvKey)); raw != "" {
			return config.NewKeyPool(raw)
		}
	}
	return config.NewKeyPool(strings.TrimSpace(os.Getenv("PROMPTSHIELD_UPSTREAM_API_KEY")))
}

// extractOpenAITokenUsage parses token counts from an OpenAI-format response body.
func extractOpenAITokenUsage(body []byte) TokenUsage {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return TokenUsage{}
	}
	usage, ok := root["usage"].(map[string]any)
	if !ok {
		return TokenUsage{}
	}
	return TokenUsage{
		PromptTokens:     intFromJSON(usage["prompt_tokens"]),
		CompletionTokens: intFromJSON(usage["completion_tokens"]),
		TotalTokens:      intFromJSON(usage["total_tokens"]),
	}
}

// scanOpenAIChoices walks choices[].message.content and applies maskFn to each string.
func scanOpenAIChoices(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte {
	var root map[string]any
	if err := json.Unmarshal(body, &root); err != nil {
		return body
	}
	choices, ok := root["choices"].([]any)
	if !ok {
		return body
	}
	changed := false
	for i, c := range choices {
		cm, ok := c.(map[string]any)
		if !ok {
			continue
		}
		msg, ok := cm["message"].(map[string]any)
		if !ok {
			continue
		}
		content, ok := msg["content"].(string)
		if !ok || content == "" {
			continue
		}
		if masked, didMask := maskFn(ctx, content); didMask {
			msg["content"] = masked
			cm["message"] = msg
			choices[i] = cm
			changed = true
		}
	}
	if !changed {
		return body
	}
	root["choices"] = choices
	out, err := json.Marshal(root)
	if err != nil {
		return body
	}
	return out
}

// ── Low-level utilities ────────────────────────────────────────────────────────

func intFromJSON(v any) int {
	f, ok := v.(float64)
	if !ok {
		return 0
	}
	return int(f)
}

func newHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 90 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

// doWithRetry sends req, retrying once on 5xx or timeout. Streaming is never retried.
// Note: a retryable 5xx can result in up to 2× the rate-limit RPM reaching the upstream.
func doWithRetry(client *http.Client, req *http.Request, bodyBytes []byte, isStream bool) (*http.Response, error) {
	if isStream {
		return client.Do(req) //nolint:gosec // upstream URL is operator-configured
	}

	resp, err := client.Do(req) //nolint:gosec // upstream URL is operator-configured
	if err != nil {
		if isRetryableNetworkError(err) {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			req.ContentLength = int64(len(bodyBytes))
			return client.Do(req) //nolint:gosec // retry of same operator-configured URL
		}
		return nil, err
	}
	if !isRetryableStatus(resp.StatusCode) {
		return resp, nil
	}

	_ = resp.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
	return client.Do(req) //nolint:gosec // retry of same operator-configured URL
}

func isRetryableNetworkError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	var netErr interface{ Timeout() bool }
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	return false
}

func apiKeyFromBearer(r *http.Request) string {
	auth := strings.TrimSpace(r.Header.Get("authorization"))
	if !strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return ""
	}
	return strings.TrimSpace(auth[7:])
}

// clientIP returns the best-effort client IP for audit logging only.
// X-Forwarded-For is accepted because spoofing it only affects log accuracy, not security decisions.
func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx != -1 {
			return strings.TrimSpace(xff[:idx])
		}
		return xff
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isRetryableStatus(status int) bool {
	return status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}
