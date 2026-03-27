package policy

import (
	"crypto/sha256"
	"fmt"

	"gopkg.in/yaml.v3"
)

// Hash returns a hex SHA-256 of the policy's canonical YAML representation.
func Hash(p *Policy) string {
	b, err := yaml.Marshal(p)
	if err != nil {
		return "unknown"
	}
	return fmt.Sprintf("%x", sha256.Sum256(b))
}

type Action string

const (
	ActionAllow Action = "allow"
	ActionMask  Action = "mask"
	ActionBlock Action = "block"
)

type PIIPolicy map[string]Action

type InjectionPolicy struct {
	Action Action `yaml:"action"`
}

type RateLimitPolicy struct {
	RequestsPerMinute int    `yaml:"requests_per_minute"`
	Burst             int    `yaml:"burst"`
	KeyBy             string `yaml:"key_by"` // "ip" or "api_key"
}

// ResponseScanPolicy enables PII scanning on non-streaming LLM responses.
type ResponseScanPolicy struct {
	Enabled bool `yaml:"enabled"`
}

// TokenLimitsPolicy caps output tokens and/or total prompt length.
type TokenLimitsPolicy struct {
	MaxTokens       int `yaml:"max_tokens"`        // 0 = no limit
	MaxPromptLength int `yaml:"max_prompt_length"` // 0 = no limit
}

// TokenBudgetWindow is a rolling-window token budget for one time period.
type TokenBudgetWindow struct {
	Tokens int    `yaml:"tokens"` // 0 = no limit
	KeyBy  string `yaml:"key_by"` // "global" | "ip" | "api_key" (default: "ip")
}

// TokenBudgetPolicy caps cumulative token usage over daily, weekly, and/or monthly windows.
type TokenBudgetPolicy struct {
	Daily   *TokenBudgetWindow `yaml:"daily"`
	Weekly  *TokenBudgetWindow `yaml:"weekly"`
	Monthly *TokenBudgetWindow `yaml:"monthly"`
}

type Policy struct {
	PII             PIIPolicy           `yaml:"pii"`
	PIIMinScore     float64             `yaml:"pii_min_score"` // 0.0–1.0; 0 = accept all
	Injection       InjectionPolicy     `yaml:"injection"`
	OnDetectorError string              `yaml:"on_detector_error"` // fail_open | fail_closed
	RateLimit       *RateLimitPolicy    `yaml:"rate_limit"`
	ResponseScan    *ResponseScanPolicy `yaml:"response_scan"`
	TokenLimits     *TokenLimitsPolicy  `yaml:"token_limits"`
	TokenBudget     *TokenBudgetPolicy  `yaml:"token_budget"`
}

// DefaultPolicy is used when no policy file is found.
// fail_closed is safe with no engine configured: PassthroughAnalyzer never errors,
// so it only matters when an engine URL is set but the engine becomes unreachable.
func DefaultPolicy() *Policy {
	return &Policy{
		PII:             PIIPolicy{},
		Injection:       InjectionPolicy{Action: ActionBlock},
		OnDetectorError: "fail_closed",
	}
}
