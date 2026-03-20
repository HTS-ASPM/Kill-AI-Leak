package guardrails

import (
	"context"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// inputStages are the stages evaluated during input (pre-send) processing.
var inputStages = []models.GuardrailStage{
	models.StagePreInput,
	models.StageInput,
	models.StageRouting,
}

// outputStages are the stages evaluated during output (post-receive) processing.
var outputStages = []models.GuardrailStage{
	models.StageOutput,
	models.StagePostOutput,
}

// EngineAdapter wraps the guardrail Engine to satisfy the proxy.GuardrailEngine
// interface which splits evaluation into Input and Output phases.
type EngineAdapter struct {
	engine *Engine
}

// NewEngineAdapter creates an adapter around the core engine.
func NewEngineAdapter(engine *Engine) *EngineAdapter {
	return &EngineAdapter{engine: engine}
}

// EvaluateInput runs pre_input, input, and routing stages.
func (a *EngineAdapter) EvaluateInput(ctx context.Context, evalCtx *EvalContext) (*models.PipelineResult, error) {
	return a.engine.evaluateStages(evalCtx, inputStages)
}

// EvaluateOutput runs output and post_output stages.
func (a *EngineAdapter) EvaluateOutput(ctx context.Context, evalCtx *EvalContext) (*models.PipelineResult, error) {
	return a.engine.evaluateStages(evalCtx, outputStages)
}
