package guardrails

import (
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Rule is the interface that all guardrail rules must implement.
// Each rule evaluates a specific security concern (PII detection,
// injection detection, toxicity, etc.) and returns a decision.
type Rule interface {
	// ID returns the unique identifier for this rule.
	ID() string

	// Name returns the human-readable name for this rule.
	Name() string

	// Stage returns the pipeline stage this rule executes in.
	Stage() models.GuardrailStage

	// Category returns the security category this rule belongs to.
	Category() models.RuleCategory

	// Evaluate runs the rule against the given context and returns an evaluation.
	// Implementations must respect context cancellation via ctx.Context().
	Evaluate(ctx *EvalContext) (*models.GuardrailEvaluation, error)
}

// ConfigurableRule is an optional interface for rules that accept dynamic
// configuration. The registry calls Configure when rule config changes.
type ConfigurableRule interface {
	Rule
	Configure(cfg map[string]any) error
}

// DependentRule is an optional interface for rules that depend on the
// output of other rules within the same stage. The engine ensures
// dependencies run first and passes their evaluations through the context.
type DependentRule interface {
	Rule
	Dependencies() []string
}
