package policy

import (
	"fmt"

	"github.com/promptshieldhq/promptshield-gateway/internal/detector"
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
	if injectionDecision, blocked := e.evaluateInjection(result); blocked {
		return injectionDecision
	} else if len(injectionDecision.Reasons) > 0 {
		decision.Reasons = append(decision.Reasons, injectionDecision.Reasons...)
	}

	blockReasons := e.applyEntityDecisions(result.Entities, &decision)
	if len(blockReasons) > 0 {
		return Decision{Action: ActionBlock, Reasons: blockReasons}
	}

	return decision
}

func (e *Evaluator) evaluateInjection(result *detector.DetectResponse) (Decision, bool) {
	if !result.InjectionDetected {
		return Decision{}, false
	}

	injectionAction := e.policy.Injection.Action
	if injectionAction == "" {
		injectionAction = ActionBlock
	}

	reason := "prompt injection detected"
	if result.InjectionReason != "" {
		reason = fmt.Sprintf("prompt injection detected: %s", result.InjectionReason)
	}

	if injectionAction == ActionBlock {
		return Decision{Action: ActionBlock, Reasons: []string{reason}}, true
	}

	return Decision{Action: ActionAllow, Reasons: []string{reason}}, false
}

func (e *Evaluator) applyEntityDecisions(entities []detector.Entity, decision *Decision) []string {
	blockReasons := make([]string, 0)

	for _, entity := range entities {
		entityPolicy := e.policy.PII[entity.Type]
		if !passesEntityScore(entity, entityPolicy, e.policy.PIIMinScore) {
			continue
		}

		action, unknownBlocked := e.resolveEntityAction(entityPolicy)
		switch action {
		case ActionBlock:
			blockReasons = append(blockReasons, blockReasonForEntity(entity, unknownBlocked))
		case ActionMask:
			decision.Action = ActionMask
			decision.ToMask = append(decision.ToMask, entity)
			decision.Reasons = append(decision.Reasons, fmt.Sprintf("masked PII entity detected: %s", entity.Type))
		}
	}

	return blockReasons
}

func passesEntityScore(entity detector.Entity, entityPolicy PIIEntityPolicy, globalMin float64) bool {
	minScore := globalMin
	if entityPolicy.MinScore != nil {
		minScore = *entityPolicy.MinScore
	}
	return minScore <= 0 || entity.Score >= minScore
}

func (e *Evaluator) resolveEntityAction(entityPolicy PIIEntityPolicy) (Action, bool) {
	if entityPolicy.Action != "" {
		return entityPolicy.Action, false
	}
	if e.policy.OnUnknownEntity == string(ActionBlock) {
		return ActionBlock, true
	}
	return ActionAllow, false
}

func blockReasonForEntity(entity detector.Entity, unknownBlocked bool) string {
	if unknownBlocked {
		return fmt.Sprintf("blocked unknown entity type: %s (on_unknown_entity=block)", entity.Type)
	}
	return fmt.Sprintf("blocked PII entity detected: %s", entity.Type)
}
