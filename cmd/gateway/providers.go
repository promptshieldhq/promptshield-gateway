package main

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/promptshieldhq/promptshield-gateway/internal/budget"
	"github.com/promptshieldhq/promptshield-gateway/internal/config"
	"github.com/promptshieldhq/promptshield-gateway/internal/detector"
	"github.com/promptshieldhq/promptshield-gateway/internal/gateway"
	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
	"github.com/rs/zerolog"
)

func initSecretsBackend(log zerolog.Logger) detector.Analyzer {
	backend := strings.ToLower(strings.TrimSpace(config.GetEnv("PROMPTSHIELD_SECRETS_BACKEND", "gitleaks")))

	if backend == "gitleaks" && envTruthy("PROMPTSHIELD_GITLEAKS_DISABLED") {
		log.Warn().Msg("PROMPTSHIELD_GITLEAKS_DISABLED is deprecated — use PROMPTSHIELD_SECRETS_BACKEND=none")
		backend = "none"
	}

	switch backend {
	case "gitleaks":
		gl, err := detector.NewGitleaksAnalyzer()
		if err != nil {
			log.Warn().Err(err).Msg("gitleaks init failed — secret scanning disabled")
			return nil
		}
		return gl

	case "none":
		log.Info().Msg("secrets backend: disabled (PROMPTSHIELD_SECRETS_BACKEND=none)")
		return nil

	default:
		log.Warn().Str("value", backend).Msg("unknown PROMPTSHIELD_SECRETS_BACKEND — defaulting to gitleaks")
		gl, err := detector.NewGitleaksAnalyzer()
		if err != nil {
			log.Warn().Err(err).Msg("gitleaks init failed — secret scanning disabled")
			return nil
		}
		return gl
	}
}

func initAnalyzer(log zerolog.Logger) (detector.Analyzer, error) {
	secrets := initSecretsBackend(log)

	detectorURL := config.GetEnv("PROMPTSHIELD_ENGINE_URL", engineURLNone)
	switch detectorURL {
	case engineURLNone, "":
		log.Info().Msg("engine disabled — running in gateway mode (no PII/injection detection)")
		if secrets != nil {
			return detector.NewCompositeAnalyzer(secrets, nil, log), nil
		}
		return detector.NewPassthroughAnalyzer(), nil
	default:
		if err := validateConfiguredURL("engine URL", detectorURL); err != nil {
			return nil, fmt.Errorf("invalid engine URL %q: must be a valid http/https URL or 'none'", detectorURL)
		}
		warnIfPlaintextRemote(log, "engine_url", detectorURL)
		engineAPIKey := strings.TrimSpace(os.Getenv("PROMPTSHIELD_ENGINE_API_KEY"))
		httpAnalyzer := detector.NewHTTPAnalyzer(detectorURL, engineAPIKey)
		if engineAPIKey != "" {
			log.Info().Str("engine_url", detectorURL).Msg("detection engine enabled (authenticated)")
		} else {
			log.Info().Str("engine_url", detectorURL).Msg("detection engine enabled")
		}
		if secrets != nil {
			return detector.NewCompositeAnalyzer(secrets, httpAnalyzer, log), nil
		}
		return httpAnalyzer, nil
	}
}

func initBudget(log zerolog.Logger, tb *policy.TokenBudgetPolicy) budget.Tracker {
	if tb == nil {
		return nil
	}
	if !tb.IsEnabled() {
		log.Info().Msg("token budget: disabled by policy (token_budget.enabled=false)")
		return nil
	}
	redisURL := strings.TrimSpace(os.Getenv("PROMPTSHIELD_REDIS_URL"))
	tracker, err := budget.NewTracker(tb, redisURL)
	switch {
	case err != nil:
		log.Warn().Err(err).Msg("Redis budget tracker unavailable — falling back to in-memory (not HA-safe)")
		tracker = budget.New(tb)
	case redisURL != "":
		log.Info().Str("redis_host", redactedRedisHost(redisURL)).Msg("token budget: Redis backend (HA-safe, survives restart)")
	default:
		log.Warn().Msg("token budget: in-memory backend (resets on restart; set PROMPTSHIELD_REDIS_URL for HA)")
	}

	budgetUsesIP := false
	if tb.Daily != nil && tb.Daily.Tokens > 0 {
		log.Info().Int("tokens", tb.Daily.Tokens).Str("key_by", tb.Daily.KeyBy).Msg("daily token budget enabled")
		if tb.Daily.KeyBy != keyByAPIKey && tb.Daily.KeyBy != keyByGlobal {
			budgetUsesIP = true
		}
	}
	if tb.Weekly != nil && tb.Weekly.Tokens > 0 {
		log.Info().Int("tokens", tb.Weekly.Tokens).Str("key_by", tb.Weekly.KeyBy).Msg("weekly token budget enabled")
		if tb.Weekly.KeyBy != keyByAPIKey && tb.Weekly.KeyBy != keyByGlobal {
			budgetUsesIP = true
		}
	}
	if tb.Monthly != nil && tb.Monthly.Tokens > 0 {
		log.Info().Int("tokens", tb.Monthly.Tokens).Str("key_by", tb.Monthly.KeyBy).Msg("monthly token budget enabled")
		if tb.Monthly.KeyBy != keyByAPIKey && tb.Monthly.KeyBy != keyByGlobal {
			budgetUsesIP = true
		}
	}
	if budgetUsesIP {
		log.Warn().Msg("IP-based token budget uses RemoteAddr unless request comes from loopback or PROMPTSHIELD_TRUST_PROXY_CIDRS")
	}
	return tracker
}

func warnIfPlaintextRemote(log zerolog.Logger, label, rawURL string) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "http" {
		return
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return
		}
	} else if strings.EqualFold(host, "localhost") {
		return
	}
	log.Warn().Str(label, rawURL).Msg("upstream URL uses plaintext HTTP to a non-loopback host — use HTTPS")
}

func validProvider(provider string) error {
	switch provider {
	case gateway.ProviderGemini, gateway.ProviderOpenAI, gateway.ProviderAnthropic, gateway.ProviderOpenAICompatible, gateway.ProviderSelfHosted:
		return nil
	default:
		return fmt.Errorf("unknown provider %q: must be gemini, openai, anthropic, openai-compatible, or selfhosted", provider)
	}
}

func buildAdapter(provider, upstreamURL string) (gateway.Adapter, error) {
	if err := validProvider(provider); err != nil {
		return nil, err
	}
	switch provider {
	case gateway.ProviderGemini:
		return gateway.NewGeminiAdapter(upstreamURL), nil
	case gateway.ProviderOpenAI:
		return gateway.NewOpenAIAdapter(gateway.ProviderOpenAI, upstreamURL), nil
	case gateway.ProviderAnthropic:
		return gateway.NewAnthropicAdapter(upstreamURL), nil
	default:
		return gateway.NewOpenAIAdapter(provider, upstreamURL), nil
	}
}

func buildMultiAdapter(log zerolog.Logger, providersEnv string) (gateway.Adapter, error) {
	names := strings.Split(providersEnv, ",")
	adapters := make(map[string]gateway.Adapter, len(names))
	var fallback gateway.Adapter

	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, exists := adapters[name]; exists {
			continue
		}
		providerURL := resolveProviderURL(name)
		if err := validateConfiguredURL(fmt.Sprintf("upstream URL for provider %q", name), providerURL); err != nil {
			return nil, err
		}
		warnIfPlaintextRemote(log, "upstream_url", providerURL)
		a, err := buildAdapter(name, providerURL)
		if err != nil {
			return nil, err
		}
		if a.RequiresKey() {
			if key := a.ResolveAPIKey(emptyRequest()); key == "" {
				log.Warn().Str("provider", name).Msg("no API key configured — requests to this provider will fail at runtime")
			}
		}
		log.Info().Str("provider", name).Str("url", providerURL).Str("model", a.Model()).Msg("provider configured")
		adapters[name] = a
		if fallback == nil {
			fallback = a
		}
	}

	if fallback == nil {
		return nil, fmt.Errorf("no valid providers configured in PROMPTSHIELD_PROVIDERS")
	}

	modelRoutes := parseModelRoutes(log, config.GetEnv("PROMPTSHIELD_MODEL_ROUTES", ""))
	for model, provider := range modelRoutes {
		if _, ok := adapters[provider]; !ok {
			log.Warn().Str("model", model).Str("provider", provider).Msg("PROMPTSHIELD_MODEL_ROUTES: provider not configured — route will use fallback")
		}
	}
	return gateway.NewMultiAdapter(adapters, modelRoutes, fallback), nil
}

func parseModelRoutes(log zerolog.Logger, raw string) map[string]string {
	routes := make(map[string]string)
	for _, entry := range strings.Split(raw, ",") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		key, val, ok := strings.Cut(entry, "=")
		if !ok {
			log.Warn().Str("entry", entry).Msg("PROMPTSHIELD_MODEL_ROUTES: skipping invalid entry (expected model=provider)")
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		val = strings.ToLower(strings.TrimSpace(val))
		if key == "" || val == "" {
			log.Warn().Str("entry", entry).Msg("PROMPTSHIELD_MODEL_ROUTES: skipping entry with empty model or provider")
			continue
		}
		routes[key] = val
	}
	return routes
}

func resolveUpstreamURL(provider string) string {
	if u := config.GetEnv("PROMPTSHIELD_UPSTREAM_URL", ""); u != "" {
		return u
	}
	return resolveProviderURL(provider)
}

func resolveProviderURL(provider string) string {
	envKey := "PROMPTSHIELD_" + strings.ToUpper(strings.ReplaceAll(provider, "-", "_")) + "_UPSTREAM_URL"
	if u := strings.TrimSpace(os.Getenv(envKey)); u != "" {
		return u
	}
	switch provider {
	case gateway.ProviderOpenAI:
		return "https://api.openai.com/v1"
	case gateway.ProviderAnthropic:
		return "https://api.anthropic.com/v1"
	case gateway.ProviderOpenAICompatible, gateway.ProviderSelfHosted:
		return "http://localhost:11434/v1"
	default:
		return "https://generativelanguage.googleapis.com/v1beta"
	}
}

func emptyRequest() *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", http.NoBody) //nolint:errcheck // static URL, cannot fail
	return r
}
