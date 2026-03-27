package policy

import (
	"fmt"

	"github.com/promptshieldhq/promptshield-proxy/internal/detector"
)

type Decision struct {
	Action  Action
	Reasons []string
	ToMask  []detector.Entity
}

type Evaluator struct {
	policy *Policy
}

func NewEvaluator(p *Policy) *Evaluator {
	return &Evaluator{policy: p}
}

func (e *Evaluator) Evaluate(result *detector.DetectResponse) Decision {
	if result == nil {
		return Decision{Action: ActionAllow}
	}

	decision := Decision{Action: ActionAllow}

	if result.InjectionDetected {
		injectionAction := e.policy.Injection.Action
		if injectionAction == "" {
			injectionAction = ActionBlock
		}

		reason := "prompt injection detected"
		if result.InjectionReason != "" {
			reason = fmt.Sprintf("prompt injection detected: %s", result.InjectionReason)
		}

		switch injectionAction {
		case ActionBlock:
			return Decision{Action: ActionBlock, Reasons: []string{reason}}
		case ActionAllow:
			decision.Reasons = append(decision.Reasons, reason)
		}
	}

	// Collect all blocked/masked entities before returning so the audit log is complete.
	var blockReasons []string
	for _, entity := range result.Entities {
		if e.policy.PIIMinScore > 0 && entity.Score < e.policy.PIIMinScore {
			continue
		}

		action := e.policy.PII[entity.Type]
		if action == "" {
			action = ActionAllow
		}

		switch action {
		case ActionBlock:
			blockReasons = append(blockReasons, fmt.Sprintf("blocked PII entity detected: %s", entity.Type))
		case ActionMask:
			decision.Action = ActionMask
			decision.ToMask = append(decision.ToMask, entity)
			decision.Reasons = append(decision.Reasons, fmt.Sprintf("masked PII entity detected: %s", entity.Type))
		case ActionAllow:
		}
	}

	if len(blockReasons) > 0 {
		return Decision{Action: ActionBlock, Reasons: blockReasons}
	}

	return decision
}
