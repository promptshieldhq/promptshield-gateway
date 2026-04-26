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

// PIIEntityPolicy defines the action and optional per-entity confidence threshold.
// It unmarshals from either a plain action string ("block") or an object
// ({action: block, min_score: 0.85}), so existing policy files stay compatible.
type PIIEntityPolicy struct {
	Action   Action   `yaml:"action"`
	MinScore *float64 `yaml:"min_score,omitempty"`
}

// UnmarshalYAML handles both scalar and mapping forms:
//
//	EMAIL_ADDRESS: mask
//	EMAIL_ADDRESS:
//	  action: block
//	  min_score: 0.85
func (p *PIIEntityPolicy) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		p.Action = Action(value.Value)
		return nil
	case yaml.MappingNode:
		type plain PIIEntityPolicy
		return value.Decode((*plain)(p))
	default:
		return fmt.Errorf("unsupported YAML node kind %v for PIIEntityPolicy", value.Kind)
	}
}

type PIIPolicy map[string]PIIEntityPolicy

type InjectionPolicy struct {
	Action Action `yaml:"action"`
}

type RateLimitPolicy struct {
	RequestsPerMinute int    `yaml:"requests_per_minute"`
	Burst             int    `yaml:"burst"`
	KeyBy             string `yaml:"key_by"` // "ip" or "api_key"
}

// ResponseScanPolicy enables PII scanning on LLM responses.
// For streaming responses, the stream is buffered up to MaxBufferBytes before scanning.
// If the stream exceeds the buffer the response passes through unscanned.
type ResponseScanPolicy struct {
	Enabled        bool `yaml:"enabled"`
	MaxBufferBytes int  `yaml:"max_buffer_bytes"` // 0 = 2 MiB default
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
	Enabled *bool              `yaml:"enabled,omitempty"` // default true
	Daily   *TokenBudgetWindow `yaml:"daily"`
	Weekly  *TokenBudgetWindow `yaml:"weekly"`
	Monthly *TokenBudgetWindow `yaml:"monthly"`
}

// IsEnabled reports whether token budgeting is enabled.
// Missing "enabled" defaults to true for backward compatibility.
func (p *TokenBudgetPolicy) IsEnabled() bool {
	if p == nil || p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

type Policy struct {
	PII             PIIPolicy           `yaml:"pii"`
	PIIMinScore     float64             `yaml:"pii_min_score"`     // 0.0–1.0; 0 = accept all
	OnUnknownEntity string              `yaml:"on_unknown_entity"` // allow (default) | block
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
		PII:             make(PIIPolicy),
		Injection:       InjectionPolicy{Action: ActionBlock},
		OnDetectorError: "fail_closed",
	}
}
