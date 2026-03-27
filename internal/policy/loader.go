package policy

import (
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

// maxPolicyFileBytes caps the policy file size to prevent YAML bomb expansion.
const maxPolicyFileBytes = 1 << 20 // 1 MiB

var validActions = map[Action]bool{
	ActionAllow: true,
	ActionMask:  true,
	ActionBlock: true,
}

var validDetectorErrors = map[string]bool{
	"fail_open":   true,
	"fail_closed": true,
}

func Load(path string) (*Policy, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not read policy file: %w", err)
	}
	defer f.Close()

	// LimitReader prevents a crafted YAML file from expanding into gigabytes of memory.
	data, err := io.ReadAll(io.LimitReader(f, maxPolicyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("could not read policy file: %w", err)
	}
	if len(data) > maxPolicyFileBytes {
		return nil, fmt.Errorf("policy file exceeds maximum allowed size of %d bytes", maxPolicyFileBytes)
	}

	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("could not parse policy file: %w", err)
	}

	if err := validate(&p); err != nil {
		return nil, err
	}

	return &p, nil
}

func validate(p *Policy) error {
	if p.PIIMinScore < 0 || p.PIIMinScore > 1 {
		return fmt.Errorf("pii_min_score must be between 0.0 and 1.0, got %g", p.PIIMinScore)
	}

	for entityType, action := range p.PII {
		if !validActions[action] {
			return fmt.Errorf("invalid action %q for entity %q: must be allow, mask, or block", action, entityType)
		}
	}

	switch p.Injection.Action {
	case "", ActionAllow, ActionBlock:
		// valid
	case ActionMask:
		return fmt.Errorf("injection.action %q is not supported — injections have no span to redact; use block or allow", ActionMask)
	default:
		return fmt.Errorf("invalid injection action %q: must be allow or block", p.Injection.Action)
	}

	if p.OnDetectorError != "" && !validDetectorErrors[p.OnDetectorError] {
		return fmt.Errorf("invalid on_detector_error %q: must be fail_open or fail_closed", p.OnDetectorError)
	}

	if rl := p.RateLimit; rl != nil {
		if rl.RequestsPerMinute <= 0 {
			return fmt.Errorf("rate_limit.requests_per_minute must be a positive integer")
		}
		if rl.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be a positive integer")
		}
		if rl.KeyBy != "" && rl.KeyBy != "ip" && rl.KeyBy != "api_key" {
			return fmt.Errorf("rate_limit.key_by must be ip or api_key")
		}
	}

	if tl := p.TokenLimits; tl != nil {
		if tl.MaxTokens < 0 {
			return fmt.Errorf("token_limits.max_tokens must be >= 0")
		}
		if tl.MaxPromptLength < 0 {
			return fmt.Errorf("token_limits.max_prompt_length must be >= 0")
		}
	}

	if tb := p.TokenBudget; tb != nil {
		validBudgetKeyBy := map[string]bool{"": true, "ip": true, "api_key": true, "global": true}
		if tb.Daily != nil {
			if tb.Daily.Tokens < 0 {
				return fmt.Errorf("token_budget.daily.tokens must be >= 0")
			}
			if !validBudgetKeyBy[tb.Daily.KeyBy] {
				return fmt.Errorf("token_budget.daily.key_by %q must be ip, api_key, or global", tb.Daily.KeyBy)
			}
		}
		if tb.Weekly != nil {
			if tb.Weekly.Tokens < 0 {
				return fmt.Errorf("token_budget.weekly.tokens must be >= 0")
			}
			if !validBudgetKeyBy[tb.Weekly.KeyBy] {
				return fmt.Errorf("token_budget.weekly.key_by %q must be ip, api_key, or global", tb.Weekly.KeyBy)
			}
		}
		if tb.Monthly != nil {
			if tb.Monthly.Tokens < 0 {
				return fmt.Errorf("token_budget.monthly.tokens must be >= 0")
			}
			if !validBudgetKeyBy[tb.Monthly.KeyBy] {
				return fmt.Errorf("token_budget.monthly.key_by %q must be ip, api_key, or global", tb.Monthly.KeyBy)
			}
		}
	}

	return nil
}
