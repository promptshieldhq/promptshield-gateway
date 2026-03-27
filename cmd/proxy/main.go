package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/promptshieldhq/promptshield-proxy/internal/audit"
	"github.com/promptshieldhq/promptshield-proxy/internal/budget"
	"github.com/promptshieldhq/promptshield-proxy/internal/config"
	"github.com/promptshieldhq/promptshield-proxy/internal/detector"
	"github.com/promptshieldhq/promptshield-proxy/internal/metrics"
	"github.com/promptshieldhq/promptshield-proxy/internal/policy"
	"github.com/promptshieldhq/promptshield-proxy/internal/proxy"
	"github.com/promptshieldhq/promptshield-proxy/internal/ratelimit"
	"github.com/rs/zerolog"
)

// version, commit, and date are set at build time via GoReleaser ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

const engineURLNone = "none" // sentinel value meaning "no detection engine"

const (
	keyByAPIKey = "api_key"
	keyByGlobal = "global"
)

func main() {
	log := zerolog.New(os.Stderr).With().Timestamp().Str("service", "promptshield-proxy").Logger()

	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
		// No subcommand or flags-only: default to serve (backward compatible).
		if err := runServe(log, os.Args[1:]); err != nil {
			log.Fatal().Err(err).Msg("startup failed")
		}
		return
	}

	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "serve":
		if err := runServe(log, args); err != nil {
			log.Fatal().Err(err).Msg("startup failed")
		}
	case "validate":
		if err := runValidate(args); err != nil {
			fmt.Fprintf(os.Stderr, "validate: %v\n", err)
			os.Exit(1)
		}
	case "version":
		fmt.Printf("promptshield-proxy %s (commit=%s, built=%s)\n", version, commit, date)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\nUsage: promptshield-proxy <serve|validate|version> [flags]\n", sub)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`promptshield-proxy — LLM security proxy

Usage:
  promptshield-proxy [serve] [flags]   Start the proxy server (default)
  promptshield-proxy validate [flags]  Validate config and print summary
  promptshield-proxy version           Print version and exit

Serve flags:
  --port        PORT   Listen port                          (PROMPTSHIELD_PORT, default: 8080)
  --provider    NAME   gemini|openai|anthropic|selfhosted   (PROMPTSHIELD_PROVIDER, default: gemini)
  --providers   LIST   Multi-provider comma list            (PROMPTSHIELD_PROVIDERS)
  --policy      PATH   Policy YAML path                     (PROMPTSHIELD_POLICY_PATH, default: config/policy.yaml)
  --engine      URL    Detection engine URL or 'none'       (PROMPTSHIELD_ENGINE_URL, default: none)
  --log-level   LEVEL  debug|info|warn|error                (default: info)
  --env         PATH   .env file path                       (default: .env)

Flags override environment variables; environment variables override defaults.
`)
}

type serveFlags struct {
	port      string
	provider  string
	providers string
	policy    string
	engine    string
	logLevel  string
	envFile   string
}

func parseServeFlags(cmd string, args []string) (serveFlags, error) {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	var f serveFlags

	fs.StringVar(&f.port, "port", "", "listen port (PROMPTSHIELD_PORT, default: 8080)")
	fs.StringVar(&f.provider, "provider", "", "LLM provider: gemini|openai|selfhosted (PROMPTSHIELD_PROVIDER)")
	fs.StringVar(&f.providers, "providers", "", "multi-provider comma list (PROMPTSHIELD_PROVIDERS)")
	fs.StringVar(&f.policy, "policy", "", "policy YAML path (PROMPTSHIELD_POLICY_PATH)")
	fs.StringVar(&f.engine, "engine", "", "detection engine URL or 'none' (PROMPTSHIELD_ENGINE_URL)")
	fs.StringVar(&f.logLevel, "log-level", "", "log level: debug|info|warn|error (default: info)")
	fs.StringVar(&f.envFile, "env", "", ".env file path (default: .env)")

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		return serveFlags{}, err
	}
	return f, nil
}

// applyToEnv copies non-empty flag values into env so startup reads os.Getenv uniformly.
func (f serveFlags) applyToEnv() {
	if f.port != "" {
		os.Setenv("PROMPTSHIELD_PORT", f.port)
	}
	if f.provider != "" {
		os.Setenv("PROMPTSHIELD_PROVIDER", f.provider)
	}
	if f.providers != "" {
		os.Setenv("PROMPTSHIELD_PROVIDERS", f.providers)
	}
	if f.policy != "" {
		os.Setenv("PROMPTSHIELD_POLICY_PATH", f.policy)
	}
	if f.engine != "" {
		os.Setenv("PROMPTSHIELD_ENGINE_URL", f.engine)
	}
}

func configureLogLevel(log zerolog.Logger, level string) zerolog.Logger {
	switch strings.ToLower(level) {
	case "debug":
		return log.Level(zerolog.DebugLevel)
	case "warn":
		return log.Level(zerolog.WarnLevel)
	case "error":
		return log.Level(zerolog.ErrorLevel)
	default:
		return log.Level(zerolog.InfoLevel)
	}
}

func runServe(log zerolog.Logger, args []string) error {
	f, err := parseServeFlags("serve", args)
	if err != nil {
		return err
	}

	envFile := f.envFile
	if envFile == "" {
		envFile = ".env"
	}
	if err := config.LoadDotEnv(envFile); err != nil {
		return fmt.Errorf("failed to load %s: %w", envFile, err)
	}

	f.applyToEnv()
	log = configureLogLevel(log, f.logLevel)
	log.Info().Str("version", version).Msg("starting")

	return serve(log)
}

func runValidate(args []string) error {
	f, err := parseServeFlags("validate", args)
	if err != nil {
		return err
	}

	envFile := f.envFile
	if envFile == "" {
		envFile = ".env"
	}
	if err := config.LoadDotEnv(envFile); err != nil {
		return fmt.Errorf("failed to load %s: %w", envFile, err)
	}
	f.applyToEnv()

	policyPath, err := config.ResolvePolicyPath(os.Getenv("PROMPTSHIELD_POLICY_PATH"), "config/policy.yaml")
	if err != nil {
		return err
	}
	var p *policy.Policy
	if policyPath == "" {
		p = policy.DefaultPolicy()
		fmt.Println("Warning: no policy file found — using default (allow-all) policy")
	} else {
		p, err = policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("policy load: %w", err)
		}
	}

	port := config.GetEnv("PROMPTSHIELD_PORT", "8080")
	if err := config.ValidatePort(port); err != nil {
		return fmt.Errorf("invalid port %q: must be 1-65535", port)
	}

	provider := strings.ToLower(config.GetEnv("PROMPTSHIELD_PROVIDER", "gemini"))
	providers := strings.TrimSpace(os.Getenv("PROMPTSHIELD_PROVIDERS"))
	engineURL := config.GetEnv("PROMPTSHIELD_ENGINE_URL", engineURLNone)
	if engineURL != engineURLNone && engineURL != "" {
		if err := config.ValidateURL(engineURL); err != nil {
			return fmt.Errorf("PROMPTSHIELD_ENGINE_URL: %w", err)
		}
		if err := config.ValidateNotLinkLocalURL(engineURL); err != nil {
			return fmt.Errorf("PROMPTSHIELD_ENGINE_URL: %w", err)
		}
	}

	if providers == "" {
		if err := validProvider(provider); err != nil {
			return fmt.Errorf("PROMPTSHIELD_PROVIDER: %w", err)
		}
		upstreamURL := resolveUpstreamURL(provider)
		if err := config.ValidateURL(upstreamURL); err != nil {
			return fmt.Errorf("upstream URL for provider %q: %w", provider, err)
		}
		if err := config.ValidateNotLinkLocalURL(upstreamURL); err != nil {
			return fmt.Errorf("upstream URL for provider %q: %w", provider, err)
		}
	} else {
		for _, name := range strings.Split(providers, ",") {
			name = strings.ToLower(strings.TrimSpace(name))
			if name == "" {
				continue
			}
			if err := validProvider(name); err != nil {
				return fmt.Errorf("PROMPTSHIELD_PROVIDERS: %w", err)
			}
			upstreamURL := resolveProviderURL(name)
			if err := config.ValidateURL(upstreamURL); err != nil {
				return fmt.Errorf("upstream URL for provider %q: %w", name, err)
			}
			if err := config.ValidateNotLinkLocalURL(upstreamURL); err != nil {
				return fmt.Errorf("upstream URL for provider %q: %w", name, err)
			}
		}
	}

	fmt.Println("Configuration valid")
	fmt.Println()
	if policyPath == "" {
		fmt.Printf("  Policy file   : (default — no file found)\n")
	} else {
		fmt.Printf("  Policy file   : %s\n", policyPath)
	}
	fmt.Printf("  Port          : %s\n", port)

	if providers != "" {
		fmt.Printf("  Providers     : %s (multi-provider mode)\n", providers)
	} else {
		fmt.Printf("  Provider      : %s\n", provider)
	}

	if engineURL == engineURLNone || engineURL == "" {
		fmt.Printf("  Engine        : disabled (gateway mode)\n")
	} else {
		fmt.Printf("  Engine        : %s\n", engineURL)
	}

	fmt.Println()
	fmt.Println("  Policy summary:")
	fmt.Printf("    Injection action    : %s\n", p.Injection.Action)
	fmt.Printf("    On detector error   : %s\n", p.OnDetectorError)

	if p.RateLimit != nil {
		fmt.Printf("    Rate limit          : %d rpm, burst %d, key_by=%s\n",
			p.RateLimit.RequestsPerMinute, p.RateLimit.Burst, p.RateLimit.KeyBy)
	} else {
		fmt.Printf("    Rate limit          : disabled\n")
	}

	if p.ResponseScan != nil && p.ResponseScan.Enabled {
		fmt.Printf("    Response scanning   : enabled\n")
	} else {
		fmt.Printf("    Response scanning   : disabled\n")
	}

	if tl := p.TokenLimits; tl != nil {
		if tl.MaxTokens > 0 {
			fmt.Printf("    Max output tokens   : %d\n", tl.MaxTokens)
		}
		if tl.MaxPromptLength > 0 {
			fmt.Printf("    Max prompt length   : %d chars\n", tl.MaxPromptLength)
		}
	} else {
		fmt.Printf("    Token limits        : disabled\n")
	}

	if tb := p.TokenBudget; tb != nil {
		if tb.Daily != nil && tb.Daily.Tokens > 0 {
			fmt.Printf("    Daily token budget  : %d tokens, key_by=%s\n", tb.Daily.Tokens, tb.Daily.KeyBy)
		}
		if tb.Weekly != nil && tb.Weekly.Tokens > 0 {
			fmt.Printf("    Weekly token budget : %d tokens, key_by=%s\n", tb.Weekly.Tokens, tb.Weekly.KeyBy)
		}
		if tb.Monthly != nil && tb.Monthly.Tokens > 0 {
			fmt.Printf("    Monthly token budget: %d tokens, key_by=%s\n", tb.Monthly.Tokens, tb.Monthly.KeyBy)
		}
	} else {
		fmt.Printf("    Token budgets       : disabled\n")
	}

	if len(p.PII) > 0 {
		fmt.Printf("    PII rules           : %d configured\n", len(p.PII))
		for entity, action := range p.PII {
			fmt.Printf("      %-20s %s\n", entity, action)
		}
	} else {
		fmt.Printf("    PII rules           : none\n")
	}

	return nil
}

func serve(log zerolog.Logger) error {
	policyPath, err := config.ResolvePolicyPath(os.Getenv("PROMPTSHIELD_POLICY_PATH"), "config/policy.yaml")
	if err != nil {
		return err
	}
	var p *policy.Policy
	if policyPath == "" {
		p = policy.DefaultPolicy()
		log.Warn().Msg("no policy file found — using default (allow-all) policy; create config/policy.yaml to configure rules")
	} else {
		p, err = policy.Load(policyPath)
		if err != nil {
			return fmt.Errorf("failed to load policy %s: %w", policyPath, err)
		}
	}

	port := config.GetEnv("PROMPTSHIELD_PORT", "8080")
	if err := config.ValidatePort(port); err != nil {
		return fmt.Errorf("invalid port %q: must be 1-65535", port)
	}
	startPort, _ := strconv.Atoi(port) //nolint:errcheck // port already validated by ValidatePort above

	provider := strings.ToLower(config.GetEnv("PROMPTSHIELD_PROVIDER", "gemini"))

	var adapter proxy.Adapter
	if multiProviders := strings.TrimSpace(os.Getenv("PROMPTSHIELD_PROVIDERS")); multiProviders != "" {
		adapter, err = buildMultiAdapter(log, multiProviders)
		if err != nil {
			return err
		}
		log.Info().Str("providers", multiProviders).Msg("multi-provider mode enabled")
	} else {
		upstreamURL := resolveUpstreamURL(provider)
		if err := config.ValidateURL(upstreamURL); err != nil {
			return fmt.Errorf("invalid upstream URL for provider %q: %w", provider, err)
		}
		if err := config.ValidateNotLinkLocalURL(upstreamURL); err != nil {
			return fmt.Errorf("upstream URL for provider %q: %w", provider, err)
		}
		warnIfPlaintextRemote(log, "upstream_url", upstreamURL)
		adapter, err = buildAdapter(provider, upstreamURL)
		if err != nil {
			return err
		}
	}

	analyzer, err := initAnalyzer(log)
	if err != nil {
		return err
	}

	evaluator := policy.NewEvaluator(p)
	auditLogger := audit.NewLogger()

	var limiter *ratelimit.Limiter
	if rl := p.RateLimit; rl != nil {
		limiter = ratelimit.New(rl.RequestsPerMinute, rl.Burst, rl.KeyBy)
		log.Info().Int("rpm", rl.RequestsPerMinute).Int("burst", rl.Burst).Str("key_by", rl.KeyBy).Msg("rate limiting enabled")
		if rl.KeyBy != keyByAPIKey {
			log.Warn().Msg("IP rate limiting trusts X-Real-IP — ensure a reverse proxy sets this header, or clients can spoof it")
		}
	}

	tokenBudget := initBudget(log, p.TokenBudget)

	scanResponse := p.ResponseScan != nil && p.ResponseScan.Enabled
	if scanResponse {
		log.Info().Msg("response scanning enabled")
	}

	chatRoute := config.GetEnv("PROMPTSHIELD_CHAT_ROUTE", "/v1/chat/completions")
	if !strings.HasPrefix(chatRoute, "/") {
		return fmt.Errorf("invalid chat route %q: must start with '/'", chatRoute)
	}

	handler := proxy.NewHandler(adapter, analyzer, evaluator, p.OnDetectorError == "fail_closed", log, auditLogger, limiter, tokenBudget, scanResponse, p.TokenLimits, p)

	var watcher *policy.Watcher
	if policyPath != "" {
		watcher = policy.NewWatcher(policyPath, log, func(newPolicy *policy.Policy, err error) {
			if err == nil {
				handler.ReloadPolicy(newPolicy)
			}
		})
	}

	metricsHandler := promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{})
	metricsAddr := strings.TrimSpace(os.Getenv("PROMPTSHIELD_METRICS_ADDR"))

	mux := http.NewServeMux()
	mux.Handle("POST "+chatRoute, handler)
	mux.HandleFunc("GET /health", handleHealth)
	if metricsAddr == "" {
		// Warning: the /metrics endpoint is unauthenticated.
		mux.Handle("GET /metrics", metricsHandler)
		log.Warn().Msg("/metrics is exposed on the public port, set PROMPTSHIELD_METRICS_ADDR to bind it to an internal address")
	}

	certFile := os.Getenv("PROMPTSHIELD_TLS_CERT")
	keyFile := os.Getenv("PROMPTSHIELD_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("TLS_CERT and TLS_KEY must both be set or both be unset")
	}
	if certFile != "" {
		// Parse the pair now — os.Stat alone misses corrupt or mismatched PEM files.
		if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
			return fmt.Errorf("invalid TLS cert/key pair: %w", err)
		}
	}

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", startPort))
	if err != nil {
		return fmt.Errorf("could not bind to port %d: %w", startPort, err)
	}

	srv := &http.Server{
		Addr:           fmt.Sprintf(":%d", startPort),
		Handler:        mux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   120 * time.Second,
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		log.Info().Str("addr", srv.Addr).Msg("promptshield proxy started")
		var serveErr error
		if certFile != "" && keyFile != "" {
			log.Info().Str("cert", certFile).Msg("TLS enabled")
			serveErr = srv.ServeTLS(ln, certFile, keyFile)
		} else {
			serveErr = srv.Serve(ln)
		}
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			log.Fatal().Err(serveErr).Msg("server error")
		}
	}()

	var metricsSrv *http.Server
	if metricsAddr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("GET /metrics", metricsHandler)
		metricsSrv = &http.Server{
			Addr:           metricsAddr,
			Handler:        metricsMux,
			ReadTimeout:    10 * time.Second,
			WriteTimeout:   10 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxHeaderBytes: 1 << 20,
		}
		go func() {
			log.Info().Str("addr", metricsAddr).Msg("metrics server started")
			if err := metricsSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error().Err(err).Msg("metrics server error")
			}
		}()
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if watcher != nil {
		go watcher.Start(ctx)
	}

	<-ctx.Done()

	log.Info().Msg("shutting down")
	if limiter != nil {
		limiter.Stop()
	}
	if tokenBudget != nil {
		tokenBudget.Stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("shutdown error")
	}
	if metricsSrv != nil {
		if err := metricsSrv.Shutdown(shutdownCtx); err != nil {
			log.Error().Err(err).Msg("metrics server shutdown error")
		}
	}
	return nil
}

func initAnalyzer(log zerolog.Logger) (detector.Analyzer, error) {
	detectorURL := config.GetEnv("PROMPTSHIELD_ENGINE_URL", engineURLNone)
	switch detectorURL {
	case engineURLNone, "":
		log.Info().Msg("engine disabled — running in gateway mode (no PII/injection detection)")
		return detector.NewPassthroughAnalyzer(), nil
	default:
		if err := config.ValidateURL(detectorURL); err != nil {
			return nil, fmt.Errorf("invalid engine URL %q: must be a valid http/https URL or 'none'", detectorURL)
		}
		if err := config.ValidateNotLinkLocalURL(detectorURL); err != nil {
			return nil, fmt.Errorf("engine URL: %w", err)
		}
		warnIfPlaintextRemote(log, "engine_url", detectorURL)
		engineAPIKey := strings.TrimSpace(os.Getenv("PROMPTSHIELD_ENGINE_API_KEY"))
		a := detector.NewHTTPAnalyzer(detectorURL, engineAPIKey)
		if engineAPIKey != "" {
			log.Info().Str("engine_url", detectorURL).Msg("detection engine enabled (authenticated)")
		} else {
			log.Info().Str("engine_url", detectorURL).Msg("detection engine enabled")
		}
		return a, nil
	}
}

func initBudget(log zerolog.Logger, tb *policy.TokenBudgetPolicy) *budget.Tracker {
	if tb == nil {
		return nil
	}
	tracker := budget.New(tb)
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
		log.Warn().Msg("IP-based token budget trusts X-Real-IP — ensure a reverse proxy sets this header, or clients can spoof it")
	}
	return tracker
}

// warnIfPlaintextRemote warns when a non-loopback URL uses plaintext HTTP.
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
	case proxy.ProviderGemini, proxy.ProviderOpenAI, proxy.ProviderAnthropic, proxy.ProviderOpenAICompatible, proxy.ProviderSelfHosted:
		return nil
	default:
		return fmt.Errorf("unknown provider %q: must be gemini, openai, anthropic, openai-compatible, or selfhosted", provider)
	}
}

func buildAdapter(provider, upstreamURL string) (proxy.Adapter, error) {
	if err := validProvider(provider); err != nil {
		return nil, err
	}
	switch provider {
	case proxy.ProviderGemini:
		return proxy.NewGeminiAdapter(upstreamURL), nil
	case proxy.ProviderOpenAI:
		return proxy.NewOpenAIAdapter(proxy.ProviderOpenAI, upstreamURL), nil
	case proxy.ProviderAnthropic:
		return proxy.NewAnthropicAdapter(upstreamURL), nil
	default: // openai-compatible, selfhosted
		return proxy.NewOpenAIAdapter(provider, upstreamURL), nil
	}
}

// buildMultiAdapter builds a MultiAdapter from PROMPTSHIELD_PROVIDERS.
// The first provider listed is the fallback for unrecognised models.
func buildMultiAdapter(log zerolog.Logger, providersEnv string) (proxy.Adapter, error) {
	names := strings.Split(providersEnv, ",")
	adapters := make(map[string]proxy.Adapter, len(names))
	var fallback proxy.Adapter

	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, exists := adapters[name]; exists {
			continue // skip duplicates
		}
		providerURL := resolveProviderURL(name)
		if err := config.ValidateURL(providerURL); err != nil {
			return nil, fmt.Errorf("invalid upstream URL for provider %q: %w", name, err)
		}
		if err := config.ValidateNotLinkLocalURL(providerURL); err != nil {
			return nil, fmt.Errorf("upstream URL for provider %q: %w", name, err)
		}
		warnIfPlaintextRemote(log, "upstream_url", providerURL)
		a, err := buildAdapter(name, providerURL)
		if err != nil {
			return nil, err
		}
		if a.RequiresKey() {
			if key := a.ResolveAPIKey(emptyRequest()); key == "" {
				log.Warn().Str("provider", name).
					Msg("no API key configured — requests to this provider will fail at runtime")
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
			log.Warn().Str("model", model).Str("provider", provider).
				Msg("PROMPTSHIELD_MODEL_ROUTES: provider not configured — route will use fallback")
		}
	}
	return proxy.NewMultiAdapter(adapters, modelRoutes, fallback), nil
}

// parseModelRoutes parses "model=provider,model2=provider2" into a lookup map.
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

// resolveProviderURL checks for a per-provider URL override before returning the default.
func resolveProviderURL(provider string) string {
	envKey := "PROMPTSHIELD_" + strings.ToUpper(strings.ReplaceAll(provider, "-", "_")) + "_UPSTREAM_URL"
	if u := strings.TrimSpace(os.Getenv(envKey)); u != "" {
		return u
	}
	switch provider {
	case proxy.ProviderOpenAI:
		return "https://api.openai.com/v1"
	case proxy.ProviderAnthropic:
		return "https://api.anthropic.com/v1"
	case proxy.ProviderOpenAICompatible, proxy.ProviderSelfHosted:
		return "http://localhost:11434/v1"
	default:
		return "https://generativelanguage.googleapis.com/v1beta"
	}
}

// emptyRequest returns a headerless request used to probe an adapter's key pool at startup.
func emptyRequest() *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/", http.NoBody) //nolint:errcheck // static URL, cannot fail
	return r
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"promptshield-proxy"}`)) //nolint:errcheck // health check, write errors are inconsequential
}
