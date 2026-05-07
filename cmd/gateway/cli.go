package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/promptshieldhq/promptshield-gateway/internal/config"
	"github.com/promptshieldhq/promptshield-gateway/internal/policy"
	"github.com/rs/zerolog"
)

type serveFlags struct {
	port      string
	provider  string
	providers string
	policy    string
	engine    string
	logLevel  string
	envFile   string
}

func main() {
	log := zerolog.New(os.Stderr).With().Timestamp().Str("service", "promptshield-gateway").Logger()

	if len(os.Args) < 2 || strings.HasPrefix(os.Args[1], "-") {
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
		fmt.Printf("promptshield-gateway %s (commit=%s, built=%s)\n", version, commit, date)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\nUsage: promptshield-gateway <serve|validate|version> [flags]\n", sub)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`promptshield-gateway - LLM security gateway

Usage:
  promptshield [serve] [flags]   Start the gateway server (default)
  promptshield validate [flags]  Validate config and print summary
  promptshield version           Print version and exit

Serve flags:
  --port        PORT   Listen port                          (PROMPTSHIELD_PORT, default: 8080)
  --provider    NAME   gemini|openai|anthropic|selfhosted   (PROMPTSHIELD_PROVIDER, default: gemini)
  --providers   LIST   Multi-provider comma list            (PROMPTSHIELD_PROVIDERS)
  --policy      PATH   Policy YAML path                     (PROMPTSHIELD_POLICY_PATH, default: config/policy.yaml)
  --engine      URL    Detection engine URL or 'none'       (PROMPTSHIELD_ENGINE_URL, default: none)
  --log-level   LEVEL  debug|info|warn|error                (default: info)
  --env         PATH   .env file path                       (default: .env)

Flags override environment variables; environment variables override defaults.

Secrets backend:
	PROMPTSHIELD_SECRETS_BACKEND=gitleaks      In-process Gitleaks scanning (~1-3 ms, default)
	PROMPTSHIELD_SECRETS_BACKEND=none         Disable secrets scanning entirely

Security toggles:
	PROMPTSHIELD_ALLOW_DEFAULT_POLICY=true          Allow startup with fallback allow-all policy when policy file is missing (unsafe)
	PROMPTSHIELD_EXPOSE_METRICS_ON_MAIN_PORT=true   Expose unauthenticated /metrics on main listener (unsafe)
`)
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

func (f serveFlags) applyToEnv() error {
	pairs := []struct{ key, val string }{
		{"PROMPTSHIELD_PORT", f.port},
		{"PROMPTSHIELD_PROVIDER", f.provider},
		{"PROMPTSHIELD_PROVIDERS", f.providers},
		{"PROMPTSHIELD_POLICY_PATH", f.policy},
		{"PROMPTSHIELD_ENGINE_URL", f.engine},
	}
	for _, kv := range pairs {
		if kv.val == "" {
			continue
		}
		if err := os.Setenv(kv.key, kv.val); err != nil {
			return fmt.Errorf("set %s: %w", kv.key, err)
		}
	}
	return nil
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
		envFile = defaultEnvFile
	}
	if err := config.LoadDotEnv(envFile); err != nil {
		return fmt.Errorf("failed to load %s: %w", envFile, err)
	}
	if err := os.Setenv("PROMPTSHIELD_ENV_FILE", envFile); err != nil {
		return fmt.Errorf("failed to set PROMPTSHIELD_ENV_FILE: %w", err)
	}

	if err := f.applyToEnv(); err != nil {
		return err
	}
	log = configureLogLevel(log, f.logLevel)
	log.Info().Str("version", version).Msg("starting")

	return serve(log, envFile)
}

func runValidate(args []string) error {
	f, err := parseServeFlags("validate", args)
	if err != nil {
		return err
	}

	envFile := f.envFile
	if envFile == "" {
		envFile = defaultEnvFile
	}
	if err := config.LoadDotEnv(envFile); err != nil {
		return fmt.Errorf("failed to load %s: %w", envFile, err)
	}
	if err := f.applyToEnv(); err != nil {
		return err
	}

	p, policyPath, err := loadValidatePolicy()
	if err != nil {
		return err
	}

	port := config.GetEnv("PROMPTSHIELD_PORT", "8080")
	if err := config.ValidatePort(port); err != nil {
		return fmt.Errorf("invalid port %q: must be 1-65535", port)
	}

	provider := strings.ToLower(config.GetEnv("PROMPTSHIELD_PROVIDER", "gemini"))
	providers := strings.TrimSpace(os.Getenv("PROMPTSHIELD_PROVIDERS"))
	engineURL := config.GetEnv("PROMPTSHIELD_ENGINE_URL", engineURLNone)
	if err := validateEngineURLForValidate(engineURL); err != nil {
		return err
	}
	if err := validateProviderUpstreamsForValidate(provider, providers); err != nil {
		return err
	}

	printValidateSummary(p, policyPath, port, provider, providers, engineURL)
	return nil
}

func loadValidatePolicy() (*policy.Policy, string, error) {
	policyPath, err := config.ResolvePolicyPath(os.Getenv("PROMPTSHIELD_POLICY_PATH"), "config/policy.yaml")
	if err != nil {
		return nil, "", err
	}

	if policyPath == "" {
		if !envTruthy(allowDefaultPolicyEnv) {
			return nil, "", fmt.Errorf("no policy file found - set PROMPTSHIELD_POLICY_PATH or explicitly set %s=true (unsafe)", allowDefaultPolicyEnv)
		}
		fmt.Printf("Warning: no policy file found - using default (allow-all) policy because %s=true\n", allowDefaultPolicyEnv)
		return policy.DefaultPolicy(), "", nil
	}

	p, err := policy.Load(policyPath)
	if err != nil {
		return nil, "", fmt.Errorf("policy load: %w", err)
	}
	return p, policyPath, nil
}

func validateEngineURLForValidate(engineURL string) error {
	if engineURL == engineURLNone || engineURL == "" {
		return nil
	}
	return validateConfiguredURL("PROMPTSHIELD_ENGINE_URL", engineURL)
}

func validateProviderUpstreamsForValidate(provider, providers string) error {
	if providers == "" {
		if err := validProvider(provider); err != nil {
			return fmt.Errorf("PROMPTSHIELD_PROVIDER: %w", err)
		}
		return validateUpstreamForProvider(provider, resolveUpstreamURL(provider))
	}

	for _, name := range strings.Split(providers, ",") {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if err := validProvider(name); err != nil {
			return fmt.Errorf("PROMPTSHIELD_PROVIDERS: %w", err)
		}
		if err := validateUpstreamForProvider(name, resolveProviderURL(name)); err != nil {
			return err
		}
	}

	return nil
}

func validateUpstreamForProvider(provider, upstreamURL string) error {
	return validateConfiguredURL(fmt.Sprintf("upstream URL for provider %q", provider), upstreamURL)
}

func validateConfiguredURL(label, rawURL string) error {
	if err := config.ValidateURL(rawURL); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if err := config.ValidateNotLinkLocalURL(rawURL); err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	return nil
}

func printValidateSummary(p *policy.Policy, policyPath, port, provider, providers, engineURL string) {
	fmt.Println("Configuration valid")
	fmt.Println()
	printValidatePolicyPath(policyPath)
	fmt.Printf("  Port          : %s\n", port)
	printValidateProviderSelection(provider, providers)
	printValidateEngine(engineURL)

	fmt.Println()
	printValidatePolicySummary(p)
}

func printValidatePolicyPath(policyPath string) {
	if policyPath == "" {
		fmt.Printf("  Policy file   : (default - no file found)\n")
		return
	}
	fmt.Printf("  Policy file   : %s\n", policyPath)
}

func printValidateProviderSelection(provider, providers string) {
	if providers != "" {
		fmt.Printf("  Providers     : %s (multi-provider mode)\n", providers)
		return
	}
	fmt.Printf("  Provider      : %s\n", provider)
}

func printValidateEngine(engineURL string) {
	if engineURL == engineURLNone || engineURL == "" {
		fmt.Printf("  Engine        : disabled (gateway mode)\n")
		return
	}
	fmt.Printf("  Engine        : %s\n", engineURL)
}

func printValidatePolicySummary(p *policy.Policy) {
	fmt.Println("  Policy summary:")
	fmt.Printf("    Injection action    : %s\n", p.Injection.Action)
	fmt.Printf("    On detector error   : %s\n", p.OnDetectorError)
	printValidateRateLimit(p)
	printValidateResponseScan(p)
	printValidateTokenLimits(p)
	printValidateTokenBudgets(p)
	printValidatePIIRules(p)
}

func printValidateRateLimit(p *policy.Policy) {
	if p.RateLimit != nil {
		fmt.Printf("    Rate limit          : %d rpm, burst %d, key_by=%s\n",
			p.RateLimit.RequestsPerMinute, p.RateLimit.Burst, p.RateLimit.KeyBy)
		return
	}
	fmt.Printf("    Rate limit          : disabled\n")
}

func printValidateResponseScan(p *policy.Policy) {
	if p.ResponseScan != nil && p.ResponseScan.Enabled {
		fmt.Printf("    Response scanning   : enabled\n")
		return
	}
	fmt.Printf("    Response scanning   : disabled\n")
}

func printValidateTokenLimits(p *policy.Policy) {
	if tl := p.TokenLimits; tl != nil {
		if tl.MaxTokens > 0 {
			fmt.Printf("    Max output tokens   : %d\n", tl.MaxTokens)
		}
		if tl.MaxPromptLength > 0 {
			fmt.Printf("    Max prompt length   : %d chars\n", tl.MaxPromptLength)
		}
		return
	}
	fmt.Printf("    Token limits        : disabled\n")
}

func printValidateTokenBudgets(p *policy.Policy) {
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
		return
	}
	fmt.Printf("    Token budgets       : disabled\n")
}

func printValidatePIIRules(p *policy.Policy) {
	if len(p.PII) == 0 {
		fmt.Printf("    PII rules           : none\n")
		return
	}
	fmt.Printf("    PII rules           : %d configured\n", len(p.PII))
	for entity, ep := range p.PII {
		if ep.MinScore != nil {
			fmt.Printf("      %-20s %s (min_score=%.2f)\n", entity, ep.Action, *ep.MinScore)
		} else {
			fmt.Printf("      %-20s %s\n", entity, ep.Action)
		}
	}
}
