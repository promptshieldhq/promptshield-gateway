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

var validUnknownEntityActions = map[string]bool{"": true, "allow": true, "block": true}

var validRateLimitKeyBy = map[string]bool{"": true, "ip": true, "api_key": true}

var validBudgetKeyBy = map[string]bool{"": true, "ip": true, "api_key": true, "global": true}

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

	validators := []func(*Policy) error{
		validatePIIEntities,
		validateInjectionAction,
		validateOnDetectorError,
		validateOnUnknownEntity,
		validateRateLimit,
		validateTokenLimits,
		validateTokenBudget,
	}

	for _, fn := range validators {
		if err := fn(p); err != nil {
			return err
		}
	}

	return nil
}

func validatePIIEntities(p *Policy) error {
	for entityType, ep := range p.PII {
		if !validActions[ep.Action] {
			return fmt.Errorf("invalid action %q for entity %q: must be allow, mask, or block", ep.Action, entityType)
		}
		if ep.MinScore != nil && (*ep.MinScore < 0 || *ep.MinScore > 1) {
			return fmt.Errorf("min_score for entity %q must be between 0.0 and 1.0, got %g", entityType, *ep.MinScore)
		}
	}

	return nil
}

func validateInjectionAction(p *Policy) error {
	switch p.Injection.Action {
	case "", ActionAllow, ActionBlock:
		// valid
	case ActionMask:
		return fmt.Errorf("injection.action %q is not supported — injections have no span to redact; use block or allow", ActionMask)
	default:
		return fmt.Errorf("invalid injection action %q: must be allow or block", p.Injection.Action)
	}

	return nil
}

func validateOnDetectorError(p *Policy) error {
	if p.OnDetectorError != "" && !validDetectorErrors[p.OnDetectorError] {
		return fmt.Errorf("invalid on_detector_error %q: must be fail_open or fail_closed", p.OnDetectorError)
	}

	return nil
}

func validateOnUnknownEntity(p *Policy) error {
	if !validUnknownEntityActions[p.OnUnknownEntity] {
		return fmt.Errorf("invalid on_unknown_entity %q: must be allow or block", p.OnUnknownEntity)
	}

	return nil
}

func validateRateLimit(p *Policy) error {
	if rl := p.RateLimit; rl != nil {
		if rl.RequestsPerMinute <= 0 {
			return fmt.Errorf("rate_limit.requests_per_minute must be a positive integer")
		}
		if rl.Burst <= 0 {
			return fmt.Errorf("rate_limit.burst must be a positive integer")
		}
		if !validRateLimitKeyBy[rl.KeyBy] {
			return fmt.Errorf("rate_limit.key_by must be ip or api_key")
		}
	}

	return nil
}

func validateTokenLimits(p *Policy) error {
	if tl := p.TokenLimits; tl != nil {
		if tl.MaxTokens < 0 {
			return fmt.Errorf("token_limits.max_tokens must be >= 0")
		}
		if tl.MaxPromptLength < 0 {
			return fmt.Errorf("token_limits.max_prompt_length must be >= 0")
		}
	}

	return nil
}

func validateTokenBudget(p *Policy) error {
	if tb := p.TokenBudget; tb != nil {
		if err := validateTokenBudgetWindow("daily", tb.Daily); err != nil {
			return err
		}
		if err := validateTokenBudgetWindow("weekly", tb.Weekly); err != nil {
			return err
		}
		if err := validateTokenBudgetWindow("monthly", tb.Monthly); err != nil {
			return err
		}
	}

	return nil
}

func validateTokenBudgetWindow(name string, window *TokenBudgetWindow) error {
	if window == nil {
		return nil
	}
	if window.Tokens < 0 {
		return fmt.Errorf("token_budget.%s.tokens must be >= 0", name)
	}
	if !validBudgetKeyBy[window.KeyBy] {
		return fmt.Errorf("token_budget.%s.key_by %q must be ip, api_key, or global", name, window.KeyBy)
	}

	return nil
}
