package main

import (
	"context"
	"crypto/tls"
	"errors"
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
	"github.com/promptshieldhq/promptshield-gateway/internal/admin"
	"github.com/promptshieldhq/promptshield-gateway/internal/audit"
	"github.com/promptshieldhq/promptshield-gateway/internal/budget"
	"github.com/promptshieldhq/promptshield-gateway/internal/config"
	"github.com/promptshieldhq/promptshield-gateway/internal/gateway"
	"github.com/promptshieldhq/promptshield-gateway/internal/metrics"
	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
	"github.com/promptshieldhq/promptshield-gateway/internal/ratelimit"
	"github.com/rs/zerolog"
)

func serve(log zerolog.Logger, envFile string) error {
	p, policyPath, err := loadServePolicy(log)
	if err != nil {
		return err
	}

	port := config.GetEnv("PROMPTSHIELD_PORT", "8080")
	if err := config.ValidatePort(port); err != nil {
		return fmt.Errorf("invalid port %q: must be 1-65535", port)
	}
	startPort, err := strconv.Atoi(port)
	if err != nil {
		return fmt.Errorf("invalid port %q: must be 1-65535", port)
	}

	adapter, err := initServeAdapter(log)
	if err != nil {
		return err
	}

	analyzer, err := initAnalyzer(log)
	if err != nil {
		return err
	}

	waitForEngineIfConfigured(log)

	evaluator := policy.NewEvaluator(p)
	auditLogger := audit.NewLogger(log)

	var limiter ratelimit.RateLimiter
	if rl := p.RateLimit; rl != nil {
		redisURL := strings.TrimSpace(os.Getenv("PROMPTSHIELD_REDIS_URL"))
		var limErr error
		limiter, limErr = ratelimit.NewLimiter(rl.RequestsPerMinute, rl.Burst, rl.KeyBy, redisURL)
		switch {
		case limErr != nil:
			log.Warn().Err(limErr).Msg("Redis rate limiter unavailable; falling back to in-memory (not HA-safe)")
			limiter = ratelimit.New(rl.RequestsPerMinute, rl.Burst, rl.KeyBy)
		case redisURL != "":
			log.Info().Int("rpm", rl.RequestsPerMinute).Int("burst", rl.Burst).Str("key_by", rl.KeyBy).Str("redis_host", redactedRedisHost(redisURL)).Msg("rate limiting enabled (Redis backend, HA-safe)")
		default:
			log.Info().Int("rpm", rl.RequestsPerMinute).Int("burst", rl.Burst).Str("key_by", rl.KeyBy).Msg("rate limiting enabled (in-memory; set PROMPTSHIELD_REDIS_URL for HA)")
		}
		if rl.KeyBy != keyByAPIKey {
			log.Warn().Msg("IP rate limiting uses RemoteAddr unless request comes from loopback or PROMPTSHIELD_TRUST_GATEWAY_CIDRS")
		}
	}

	tokenBudget := initBudget(log, p.TokenBudget)

	scanResponse, responseScanMaxBuffer := configureResponseScan(log, p)

	chatRoute := config.GetEnv("PROMPTSHIELD_CHAT_ROUTE", "/v1/chat/completions")
	if !strings.HasPrefix(chatRoute, "/") {
		return fmt.Errorf("invalid chat route %q: must start with '/'", chatRoute)
	}

	redisURL := strings.TrimSpace(os.Getenv("PROMPTSHIELD_REDIS_URL"))
	handler := gateway.NewHandler(adapter, analyzer, evaluator, p.OnDetectorError == "fail_closed", log, auditLogger, limiter, tokenBudget, scanResponse, responseScanMaxBuffer, p.TokenLimits, p, redisURL)

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
	adminAddr := strings.TrimSpace(os.Getenv("PROMPTSHIELD_ADMIN_ADDR"))

	mux := http.NewServeMux()
	adminAPI := registerRoutes(log, mux, chatRoute, handler, policyPath, envFile, metricsHandler, adminAddr)

	certFile := os.Getenv("PROMPTSHIELD_TLS_CERT")
	keyFile := os.Getenv("PROMPTSHIELD_TLS_KEY")
	if (certFile == "") != (keyFile == "") {
		return fmt.Errorf("TLS_CERT and TLS_KEY must both be set or both be unset")
	}
	if certFile != "" {
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
		WriteTimeout:   0, // streaming responses set per-write deadlines via ResponseController
		IdleTimeout:    120 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	go func() {
		log.Info().Str("addr", srv.Addr).Msg("promptshield gateway started")
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

	metricsSrv := startMetricsServer(log, metricsAddr, metricsHandler)
	adminSrv := startAdminServer(log, adminAddr, adminAPI)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startPolicyWatcher(ctx, watcher)

	<-ctx.Done()

	log.Info().Msg("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	shutdownHTTPServers(shutdownCtx, log, srv, metricsSrv, adminSrv)
	stopRuntimeControllers(limiter, tokenBudget)
	return nil
}

func loadServePolicy(log zerolog.Logger) (*policy.Policy, string, error) {
	policyPath, err := config.ResolvePolicyPath(os.Getenv("PROMPTSHIELD_POLICY_PATH"), "config/policy.yaml")
	if err != nil {
		return nil, "", err
	}
	if policyPath != "" {
		p, err := policy.Load(policyPath)
		if err != nil {
			return nil, "", fmt.Errorf("failed to load policy %s: %w", policyPath, err)
		}
		return p, policyPath, nil
	}
	if !envTruthy(allowDefaultPolicyEnv) {
		return nil, "", fmt.Errorf("no policy file found - set PROMPTSHIELD_POLICY_PATH or explicitly set %s=true (unsafe)", allowDefaultPolicyEnv)
	}
	log.Warn().Str("env", allowDefaultPolicyEnv).Msg("no policy file found - using default (allow-all) policy due to explicit unsafe override")
	return policy.DefaultPolicy(), "", nil
}

func initServeAdapter(log zerolog.Logger) (gateway.Adapter, error) {
	provider := strings.ToLower(config.GetEnv("PROMPTSHIELD_PROVIDER", "gemini"))
	if multiProviders := strings.TrimSpace(os.Getenv("PROMPTSHIELD_PROVIDERS")); multiProviders != "" {
		adapter, err := buildMultiAdapter(log, multiProviders)
		if err != nil {
			return nil, err
		}
		log.Info().Str("providers", multiProviders).Msg("multi-provider mode enabled")
		return adapter, nil
	}

	upstreamURL := resolveUpstreamURL(provider)
	if err := validateConfiguredURL(fmt.Sprintf("upstream URL for provider %q", provider), upstreamURL); err != nil {
		return nil, err
	}
	warnIfPlaintextRemote(log, "upstream_url", upstreamURL)
	adapter, err := buildAdapter(provider, upstreamURL)
	if err != nil {
		return nil, err
	}
	if adapter.RequiresKey() && adapter.ResolveAPIKey(emptyRequest()) == "" {
		log.Warn().Str("provider", provider).Msg("no API key configured")
	}
	return adapter, nil
}

func waitForEngineIfConfigured(log zerolog.Logger) {
	engineURL := config.GetEnv("PROMPTSHIELD_ENGINE_URL", engineURLNone)
	if engineURL == engineURLNone || engineURL == "" {
		return
	}
	startupTimeout := 120 * time.Second
	if raw := strings.TrimSpace(os.Getenv("PROMPTSHIELD_ENGINE_STARTUP_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			startupTimeout = d
		}
	}
	waitForEngine(context.Background(), log, engineURL, startupTimeout)
}

func configureResponseScan(log zerolog.Logger, p *policy.Policy) (bool, int) {
	scanResponse := p.ResponseScan != nil && p.ResponseScan.Enabled
	responseScanMaxBuffer := 0
	if p.ResponseScan == nil {
		return scanResponse, responseScanMaxBuffer
	}

	responseScanMaxBuffer = p.ResponseScan.MaxBufferBytes
	if !scanResponse {
		return scanResponse, responseScanMaxBuffer
	}

	if responseScanMaxBuffer > 0 {
		log.Info().Int("max_buffer_bytes", responseScanMaxBuffer).Msg("response scanning enabled (streaming buffered)")
	} else {
		log.Info().Msg("response scanning enabled (streaming buffered, default 2 MiB)")
	}
	log.Warn().Msg("response_scan: streaming responses are buffered and collapsed into one chunk when PII is masked; progressive rendering is disabled for masked responses")
	return scanResponse, responseScanMaxBuffer
}

func registerRoutes(log zerolog.Logger, mux *http.ServeMux, chatRoute string, handler *gateway.Handler, policyPath, envFile string, metricsHandler http.Handler, adminAddr string) *admin.API {
	mux.Handle("POST "+chatRoute, handler)
	mux.HandleFunc("GET /health", handleHealth)
	mux.HandleFunc("GET /ready", handleReady)

	adminAPI := admin.New(log, policyPath, envFile, handler.ReloadPolicy)
	if adminAddr != "" {
		// Admin routes will be served on the dedicated internal listener; do not
		// register them on the public mux so they are unreachable from the internet.
		log.Info().Str("admin_addr", adminAddr).Msg("admin API bound to internal listener (not exposed on public port)")
	} else {
		adminAPI.RegisterRoutes(mux)
		log.Warn().Msg("admin API is on the public port; set PROMPTSHIELD_ADMIN_ADDR to bind it to an internal-only listener")
	}

	if envTruthy(publicMetricsEnv) {
		mux.Handle("GET /metrics", metricsHandler)
		log.Warn().Str("env", publicMetricsEnv).Msg("/metrics is exposed on the public port due to explicit unsafe override")
		return adminAPI
	}
	if strings.TrimSpace(os.Getenv("PROMPTSHIELD_METRICS_ADDR")) == "" {
		log.Info().Msg("/metrics is disabled on the public port; set PROMPTSHIELD_METRICS_ADDR for an internal metrics listener")
	}
	return adminAPI
}

func startMetricsServer(log zerolog.Logger, metricsAddr string, metricsHandler http.Handler) *http.Server {
	if metricsAddr == "" {
		return nil
	}
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", metricsHandler)
	metricsSrv := &http.Server{
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
	return metricsSrv
}

func startAdminServer(log zerolog.Logger, adminAddr string, adminAPI *admin.API) *http.Server {
	if adminAddr == "" {
		return nil
	}
	adminMux := http.NewServeMux()
	adminAPI.RegisterRoutes(adminMux)
	adminSrv := &http.Server{
		Addr:           adminAddr,
		Handler:        adminMux,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go func() {
		log.Info().Str("addr", adminAddr).Msg("admin server started on internal listener")
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("admin server error")
		}
	}()
	return adminSrv
}

func startPolicyWatcher(ctx context.Context, watcher *policy.Watcher) {
	if watcher != nil {
		go watcher.Start(ctx)
	}
}

func stopRuntimeControllers(limiter ratelimit.RateLimiter, tokenBudget budget.Tracker) {
	if limiter != nil {
		limiter.Stop()
	}
	if tokenBudget != nil {
		tokenBudget.Stop()
	}
}

func shutdownHTTPServers(ctx context.Context, log zerolog.Logger, primary *http.Server, others ...*http.Server) {
	if err := primary.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("gateway shutdown error")
	}
	for _, srv := range others {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil {
			log.Error().Err(err).Str("addr", srv.Addr).Msg("internal server shutdown error")
		}
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok","service":"promptshield-gateway"}`)) //nolint:errcheck // probe write ignored
}

// handleReady is a Kubernetes-style readiness probe. It returns 200 only once
// the server is accepting connections (this is called after the listener is up).
// Use /ready for readiness probes and /health for liveness probes.
func handleReady(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ready","service":"promptshield-gateway"}`)) //nolint:errcheck // probe write ignored
}

// redactedRedisHost returns only the host:port from a Redis URL so credentials
// are not written to the log. Returns the raw value if parsing fails.
func redactedRedisHost(redisURL string) string {
	u, err := url.Parse(redisURL)
	if err != nil {
		return "[invalid redis url]"
	}
	return u.Host
}

func waitForEngine(ctx context.Context, log zerolog.Logger, engineURL string, timeout time.Duration) {
	readyURL := strings.TrimRight(engineURL, "/") + "/ready"
	client := &http.Client{Timeout: 3 * time.Second}
	deadline := time.Now().Add(timeout)

	log.Info().Str("url", readyURL).Str("timeout", timeout.String()).Msg("waiting for engine to become ready")

	for {
		if time.Now().After(deadline) {
			log.Warn().Str("url", readyURL).Msg("engine did not become ready within timeout; proceeding anyway; first requests may fail")
			return
		}

		select {
		case <-ctx.Done():
			return
		default:
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, readyURL, http.NoBody)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					log.Info().Str("url", readyURL).Msg("engine is ready")
					return
				}
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}
