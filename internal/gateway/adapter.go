package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
)

const (
	ProviderGemini           = "gemini"
	ProviderOpenAI           = "openai"
	ProviderAnthropic        = "anthropic"
	ProviderOpenAICompatible = "openai-compatible"
	ProviderSelfHosted       = "selfhosted"
)

const (
	roleAssistant = "assistant"
	fieldText     = "text"
)

const maxResponseBytes = 10 << 20 // 10 MiB; upstream LLM response

const upstreamAllowedHostsEnv = "PROMPTSHIELD_UPSTREAM_ALLOWED_HOSTS"

var (
	upstreamAllowedHostsOnce sync.Once
	upstreamAllowedHosts     map[string]struct{}
)

// AdapterRouter routes requests by model name.
type AdapterRouter interface {
	Route(model string) Adapter
}

// Adapter is the provider interface used by the gateway.
type Adapter interface {
	Name() string
	Model() string
	RequiresKey() bool
	ResolveAPIKey(r *http.Request) string
	// Forward sends the request upstream.
	// For streaming: body is nil and stream is non-nil. Caller closes stream.
	Forward(ctx context.Context, requestID string, req *ChatRequest, apiKey string) (status int, body []byte, headers http.Header, stream io.ReadCloser, err error)
	ExtractTokenUsage(body []byte) TokenUsage
	// ExtractStreamTokenUsage updates token totals from one SSE payload.
	ExtractStreamTokenUsage(payload []byte, prior TokenUsage) TokenUsage
	// ScanResponse masks text fields and returns original on parse error.
	ScanResponse(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte
	// BuildStreamChunk builds a provider-native SSE chunk from masked text.
	BuildStreamChunk(text string) []byte
}

type TokenUsage struct {
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
}

// resolveModel returns model from global override or provider fallback.
func resolveModel(providerEnvKey string) string {
	if m := strings.TrimSpace(os.Getenv("PROMPTSHIELD_MODEL")); m != "" {
		return m
	}
	if providerEnvKey == "" {
		return ""
	}
	return strings.TrimSpace(os.Getenv(providerEnvKey))
}

// buildKeyPool loads provider keys, then falls back to upstream keys.
func buildKeyPool(providerEnvKey string) *config.KeyPool {
	if providerEnvKey != "" {
		if raw := strings.TrimSpace(os.Getenv(providerEnvKey)); raw != "" {
			return config.NewKeyPool(raw)
		}
	}
	return config.NewKeyPool(strings.TrimSpace(os.Getenv("PROMPTSHIELD_UPSTREAM_API_KEY")))
}

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
		// Never follow redirects: redirect targets bypass validateUpstreamRequestURL
		// and could be used to reach link-local / IMDS endpoints (SSRF). LLM APIs
		// do not redirect chat completion endpoints.
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 100,
			IdleConnTimeout:     90 * time.Second,
		},
	}
}

func validateUpstreamRequestURL(raw string) error {
	if err := config.ValidateURL(raw); err != nil {
		return err
	}
	if err := config.ValidateNotLinkLocalURL(raw); err != nil {
		return err
	}

	u, err := url.ParseRequestURI(raw)
	if err != nil {
		return err
	}

	if err := validateAllowedUpstreamHost(u.Hostname()); err != nil {
		return err
	}

	return nil
}

func validateAllowedUpstreamHost(host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return errors.New("upstream host is empty")
	}

	allowed := configuredUpstreamAllowedHosts()
	if len(allowed) == 0 {
		return nil
	}

	if _, ok := allowed[host]; ok {
		return nil
	}

	return errors.New("upstream host is not in allowed hosts list")
}

func configuredUpstreamAllowedHosts() map[string]struct{} {
	upstreamAllowedHostsOnce.Do(func() {
		upstreamAllowedHosts = make(map[string]struct{})
		raw := strings.TrimSpace(os.Getenv(upstreamAllowedHostsEnv))
		if raw == "" {
			return
		}

		for _, part := range strings.Split(raw, ",") {
			host := strings.ToLower(strings.TrimSpace(part))
			if host == "" {
				continue
			}
			upstreamAllowedHosts[host] = struct{}{}
		}
	})

	return upstreamAllowedHosts
}

// doWithRetry sends req and retries once only on retryable network timeouts.
// Streaming is never retried.
func doWithRetry(client *http.Client, req *http.Request, bodyBytes []byte, isStream bool) (*http.Response, error) {
	if err := ensureValidatedOutboundRequest(req); err != nil {
		return nil, err
	}

	if isStream {
		return roundTripWithClientTimeout(client, req)
	}

	return doNonStreamWithRetry(client, req, bodyBytes)
}

func doNonStreamWithRetry(client *http.Client, req *http.Request, bodyBytes []byte) (*http.Response, error) {
	if err := ensureValidatedOutboundRequest(req); err != nil {
		return nil, err
	}

	resp, err := roundTripWithClientTimeout(client, req)
	if err != nil {
		if !isRetryableNetworkError(err) {
			return nil, err
		}
		resetRequestBody(req, bodyBytes)
		return roundTripWithClientTimeout(client, req)
	}

	return resp, nil
}

func ensureValidatedOutboundRequest(req *http.Request) error {
	if req == nil || req.URL == nil {
		return errors.New("upstream request is nil")
	}

	return validateUpstreamRequestURL(req.URL.String())
}

func newValidatedRequestWithContext(ctx context.Context, method, rawURL string, body []byte) (*http.Request, error) {
	if err := validateUpstreamRequestURL(rawURL); err != nil {
		return nil, err
	}

	parsedURL, err := url.ParseRequestURI(rawURL)
	if err != nil {
		return nil, err
	}

	// Use a constant URL first, then set the validated parsed URL.
	req, err := http.NewRequestWithContext(ctx, method, "https://example.invalid", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.URL = parsedURL
	req.Host = parsedURL.Host
	req.RequestURI = ""

	return req, nil
}

func roundTripWithClientTimeout(client *http.Client, req *http.Request) (*http.Response, error) {
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	reqToSend := req.Clone(req.Context())

	if client.Timeout > 0 {
		ctx, cancel := context.WithTimeout(req.Context(), client.Timeout)
		defer cancel()
		reqToSend = req.Clone(ctx)
	}

	if client.Jar != nil && reqToSend.URL != nil {
		for _, cookie := range client.Jar.Cookies(reqToSend.URL) {
			reqToSend.AddCookie(cookie)
		}
	}

	resp, err := transport.RoundTrip(reqToSend)
	if err != nil {
		return nil, err
	}

	if client.Jar != nil && reqToSend.URL != nil {
		if cookies := resp.Cookies(); len(cookies) > 0 {
			client.Jar.SetCookies(reqToSend.URL, cookies)
		}
	}

	return resp, nil
}

func resetRequestBody(req *http.Request, bodyBytes []byte) {
	req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	req.ContentLength = int64(len(bodyBytes))
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
