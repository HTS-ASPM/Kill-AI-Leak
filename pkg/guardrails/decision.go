package guardrails

import (
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// decisionWeight assigns a numeric weight to each decision for comparison.
// Higher weight means the decision takes priority when merging.
var decisionWeight = map[models.Decision]int{
	models.DecisionLog:       0,
	models.DecisionAllow:     1,
	models.DecisionCoach:     2,
	models.DecisionThrottle:  3,
	models.DecisionAlert:     4,
	models.DecisionModify:    5,
	models.DecisionAnonymize: 6,
	models.DecisionBlock:     7,
}

// MergeDecisions takes a set of guardrail evaluations and produces a single
// final decision. The merge priority (highest wins):
//
//	BLOCK > ANONYMIZE > MODIFY > ALERT > THROTTLE > COACH > ALLOW > LOG
//
// If no evaluations are provided the final decision is ALLOW.
func MergeDecisions(evals []models.GuardrailEvaluation) models.Decision {
	if len(evals) == 0 {
		return models.DecisionAllow
	}

	best := models.DecisionAllow
	bestWeight := decisionWeight[best]

	for i := range evals {
		w, ok := decisionWeight[evals[i].Decision]
		if !ok {
			continue
		}
		if w > bestWeight {
			bestWeight = w
			best = evals[i].Decision
		}
	}
	return best
}

// ApplyEnforcementMode adjusts a raw decision according to the active
// enforcement mode. This implements the "soft landing" semantics:
//
//	off      -> every decision becomes ALLOW (rules still run for logging)
//	discover -> every decision becomes LOG (shadow mode)
//	monitor  -> BLOCK becomes ALERT; ANONYMIZE becomes ALERT; rest unchanged
//	enforce  -> no changes; decisions applied as-is
func ApplyEnforcementMode(decision models.Decision, mode models.EnforcementMode) models.Decision {
	switch mode {
	case models.ModeOff:
		return models.DecisionAllow
	case models.ModeDiscover:
		return models.DecisionLog
	case models.ModeMonitor:
		switch decision {
		case models.DecisionBlock:
			return models.DecisionAlert
		case models.DecisionAnonymize:
			return models.DecisionAlert
		default:
			return decision
		}
	case models.ModeEnforce:
		return decision
	default:
		// Unknown mode; fail safe by enforcing.
		return decision
	}
}

// BuildPipelineResult constructs a PipelineResult from a set of evaluations
// and an enforcement mode. It merges decisions, applies enforcement mode
// semantics, and identifies the blocking rule (if any).
func BuildPipelineResult(evals []models.GuardrailEvaluation, mode models.EnforcementMode, totalLatencyMs int64) *models.PipelineResult {
	rawDecision := MergeDecisions(evals)
	finalDecision := ApplyEnforcementMode(rawDecision, mode)

	result := &models.PipelineResult{
		FinalDecision:  finalDecision,
		Evaluations:    evals,
		TotalLatencyMs: totalLatencyMs,
		Blocked:        finalDecision == models.DecisionBlock,
	}

	// Identify which rule triggered the block.
	if result.Blocked {
		result.BlockedBy = findBlockingRule(evals)
	}

	return result
}

// findBlockingRule returns the ID of the first rule that issued a BLOCK
// decision. When multiple rules block, the first one (by slice order) is
// reported because that is typically the highest-priority rule.
func findBlockingRule(evals []models.GuardrailEvaluation) string {
	for i := range evals {
		if evals[i].Decision == models.DecisionBlock {
			return evals[i].RuleID
		}
	}
	return ""
}
