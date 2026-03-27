package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
)

// Priority: custom exact match → custom prefix match → built-in prefixes → fallback.
type MultiAdapter struct {
	adapters    map[string]Adapter // provider name → adapter
	modelRoutes map[string]string  // model name/prefix (lower) → provider name
	fallback    Adapter
}

func NewMultiAdapter(adapters map[string]Adapter, modelRoutes map[string]string, fallback Adapter) *MultiAdapter {
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

	return m.fallback
}

func isOpenAIModel(model string) bool {
	for _, prefix := range []string{"gpt-", "o1", "o3", "o4", "chatgpt-"} {
		if strings.HasPrefix(model, prefix) {
			return true
		}
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

func (m *MultiAdapter) Name() string      { return m.fallback.Name() }
func (m *MultiAdapter) Model() string     { return m.fallback.Model() }
func (m *MultiAdapter) RequiresKey() bool { return m.fallback.RequiresKey() }

func (m *MultiAdapter) ResolveAPIKey(r *http.Request) string {
	return m.fallback.ResolveAPIKey(r)
}

func (m *MultiAdapter) Forward(ctx context.Context, requestID string, req *ChatRequest, apiKey string) (int, []byte, http.Header, io.ReadCloser, error) {
	return m.fallback.Forward(ctx, requestID, req, apiKey)
}

func (m *MultiAdapter) ExtractTokenUsage(body []byte) TokenUsage {
	return m.fallback.ExtractTokenUsage(body)
}

func (m *MultiAdapter) ExtractStreamTokenUsage(payload []byte, prior TokenUsage) TokenUsage {
	return m.fallback.ExtractStreamTokenUsage(payload, prior)
}

func (m *MultiAdapter) ScanResponse(ctx context.Context, body []byte, maskFn func(context.Context, string) (string, bool)) []byte {
	return m.fallback.ScanResponse(ctx, body, maskFn)
}
