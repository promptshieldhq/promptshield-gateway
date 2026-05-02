package gateway

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
)

var errNoFallbackAdapter = errors.New("multi-adapter has no fallback adapter configured")

// Priority: custom exact match → custom prefix match → built-in prefixes → fallback.
type MultiAdapter struct {
	adapters    map[string]Adapter // provider name → adapter
	modelRoutes map[string]string  // model name/prefix (lower) → provider name
	fallback    Adapter
}

func NewMultiAdapter(adapters map[string]Adapter, modelRoutes map[string]string, fallback Adapter) *MultiAdapter {
	if fallback == nil {
		for _, adapter := range adapters {
			if adapter != nil {
				fallback = adapter
				break
			}
		}
	}

	return &MultiAdapter{
		adapters:    adapters,
		modelRoutes: modelRoutes,
		fallback:    fallback,
	}
}

func (m *MultiAdapter) Route(model string) Adapter {
	lower := strings.ToLower(strings.TrimSpace(model))

	// Exact match in custom routes.
	if provider, ok := m.modelRoutes[lower]; ok {
		if a, ok := m.adapters[provider]; ok {
			return a
		}
	}

	// Longest prefix match in custom routes.
	best, bestLen := "", 0
	for route, provider := range m.modelRoutes {
		if strings.HasPrefix(lower, route) && len(route) > bestLen {
			best, bestLen = provider, len(route)
		}
	}
	if best != "" {
		if a, ok := m.adapters[best]; ok {
			return a
		}
	}

	// Built-in prefix rules.
	switch {
	case isOpenAIModel(lower):
		if a, ok := m.adapters[ProviderOpenAI]; ok {
			return a
		}
	case isGeminiModel(lower):
		if a, ok := m.adapters[ProviderGemini]; ok {
			return a
		}
	case isAnthropicModel(lower):
		if a, ok := m.adapters[ProviderAnthropic]; ok {
			return a
		}
	}

	if m.fallback != nil {
		return m.fallback
	}
	for _, adapter := range m.adapters {
		if adapter != nil {
			return adapter
		}
	}

	return nil
}

func isOpenAIModel(model string) bool {
	if strings.HasPrefix(model, "gpt-") || strings.HasPrefix(model, "chatgpt-") {
		return true
	}
	// Match the o-series: o1, o3, o4, o5, … (o followed by one or more digits,
	// optionally followed by '-' or end-of-string). Checking for a digit avoids
	// false-positives on model names that start with the letter 'o' from other providers.
	if len(model) >= 2 && model[0] == 'o' && model[1] >= '1' && model[1] <= '9' {
		return len(model) == 2 || model[2] == '-'
	}
	return false
}

func isGeminiModel(model string) bool {
	return strings.HasPrefix(model, "gemini")
}

func isAnthropicModel(model string) bool {
	return strings.HasPrefix(model, "claude-") || strings.HasPrefix(model, "claude.")
}

// The methods below delegate to fallback. In practice the handler always routes first via
// selectAdapter, so these are only called on the MultiAdapter itself in tests.

func (m *MultiAdapter) Name() string {
	if m.fallback == nil {
		return "multi"
	}
	return m.fallback.Name()
}

func (m *MultiAdapter) Model() string {
	if m.fallback == nil {
		return ""
	}
	return m.fallback.Model()
}

func (m *MultiAdapter) RequiresKey() bool {
	if m.fallback == nil {
		return false
	}
	return m.fallback.RequiresKey()
}

func (m *MultiAdapter) ResolveAPIKey(r *http.Request) string {
	if m.fallback == nil {
		return ""
	}
	return m.fallback.ResolveAPIKey(r)
}

func (m *MultiAdapter) Forward(ctx context.Context, requestID string, req *ChatRequest, apiKey string) (int, []byte, http.Header, io.ReadCloser, error) {
	if m.fallback == nil {
		return 0, nil, nil, nil, errNoFallbackAdapter
	}
	return m.fallback.Forward(ctx, requestID, req, apiKey)
}

func (m *MultiAdapter) ExtractTokenUsage(body []byte) TokenUsage {
	if m.fallback == nil {
		return TokenUsage{}
	}
	return m.fallback.ExtractTokenUsage(body)
}

func (m *MultiAdapter) ExtractStreamTokenUsage(payload []byte, prior TokenUsage) TokenUsage {
	if m.fallback == nil {
		return prior
	}
	return m.fallback.ExtractStreamTokenUsage(payload, prior)
}

func (m *MultiAdapter) ScanResponse(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte {
	if m.fallback == nil {
		return body
	}
	return m.fallback.ScanResponse(ctx, body, maskFn)
}

func (m *MultiAdapter) BuildStreamChunk(text string) []byte {
	if m.fallback == nil {
		return nil
	}
	return m.fallback.BuildStreamChunk(text)
}
