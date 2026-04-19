package metrics

import (
	"strings"
	"unicode"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/promptshieldhq/promptshield-gateway/internal/audit"
)

// Registry is a clean Prometheus registry — no default Go runtime metrics.
var Registry = prometheus.NewRegistry()

var (
	requestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "promptshield_requests_total",
		Help: "Total requests processed, labeled by action, provider, and model.",
	}, []string{"action", "provider", "model"})

	requestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "promptshield_request_duration_seconds",
		Help:    "End-to-end request latency in seconds (including upstream LLM).",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60},
	}, []string{"action", "provider", "model"})

	tokensTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "promptshield_tokens_total",
		Help: "Total LLM tokens counted, labeled by type (prompt|completion|total), provider, and model.",
	}, []string{"token_type", "provider", "model"})

	entitiesDetectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "promptshield_entities_detected_total",
		Help: "Total PII entities detected, labeled by entity type and provider.",
	}, []string{"entity_type", "provider"})

	injectionsDetectedTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "promptshield_injections_detected_total",
		Help: "Total prompt injection attacks detected, labeled by provider, model, and injection reason.",
	}, []string{"provider", "model", "reason"})

	responseScansTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "promptshield_response_scans_total",
		Help: "Total LLM responses scanned for PII/injection, labeled by provider and model.",
	}, []string{"provider", "model"})
)

func init() {
	Registry.MustRegister(
		requestsTotal,
		requestDuration,
		tokensTotal,
		entitiesDetectedTotal,
		injectionsDetectedTotal,
		responseScansTotal,
	)
}

// maxModelLabelLen caps the model label to prevent unbounded Prometheus cardinality.
const maxModelLabelLen = 64

// maxEntityTypeLabelLen limits entity labels to a small bounded size.
const maxEntityTypeLabelLen = 48

func normalizeModelLabel(model string) string {
	model = strings.TrimSpace(model)
	if model == "" {
		return "unknown"
	}
	runes := []rune(model)
	if len(runes) <= maxModelLabelLen {
		return model
	}
	return string(runes[:maxModelLabelLen])
}

func normalizeEntityTypeLabel(entityType string) string {
	entityType = strings.TrimSpace(strings.ToUpper(entityType))
	if entityType == "" {
		return "UNKNOWN"
	}

	runes := make([]rune, 0, len(entityType))
	for _, r := range entityType {
		switch {
		case unicode.IsUpper(r), unicode.IsDigit(r), r == '_':
			runes = append(runes, r)
		case r == '-' || unicode.IsSpace(r):
			runes = append(runes, '_')
		}
		if len(runes) >= maxEntityTypeLabelLen {
			break
		}
	}

	if len(runes) == 0 {
		return "OTHER"
	}
	return string(runes)
}

func normalizeInjectionReasonLabel(reason string) string {
	r := strings.ToLower(strings.TrimSpace(reason))
	if r == "" {
		return "unknown"
	}

	switch {
	case strings.Contains(r, "jailbreak"):
		return "jailbreak"
	case strings.Contains(r, "system prompt") || strings.Contains(r, "prompt leak") || strings.Contains(r, "exfil"):
		return "prompt_leak"
	case strings.Contains(r, "ignore") || strings.Contains(r, "override") || strings.Contains(r, "instruction"):
		return "instruction_override"
	case strings.Contains(r, "tool") || strings.Contains(r, "function call"):
		return "tool_misuse"
	default:
		return "other"
	}
}

func Record(ev audit.Event) {
	model := normalizeModelLabel(ev.Model)
	requestsTotal.WithLabelValues(ev.Action, ev.Provider, model).Inc()
	requestDuration.WithLabelValues(ev.Action, ev.Provider, model).Observe(float64(ev.LatencyMS) / 1000)

	if ev.TotalTokens > 0 {
		tokensTotal.WithLabelValues("prompt", ev.Provider, model).Add(float64(ev.PromptTokens))
		tokensTotal.WithLabelValues("completion", ev.Provider, model).Add(float64(ev.CompletionTokens))
		tokensTotal.WithLabelValues("total", ev.Provider, model).Add(float64(ev.TotalTokens))
	}

	for _, entityType := range ev.EntitiesDetected {
		entitiesDetectedTotal.WithLabelValues(normalizeEntityTypeLabel(entityType), ev.Provider).Inc()
	}

	if ev.InjectionDetected {
		reason := normalizeInjectionReasonLabel(ev.InjectionReason)
		injectionsDetectedTotal.WithLabelValues(ev.Provider, model, reason).Inc()
	}

	if ev.ResponseScanned {
		responseScansTotal.WithLabelValues(ev.Provider, model).Inc()
	}
}
