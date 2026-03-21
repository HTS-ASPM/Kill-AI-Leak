package guardrails

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Mock rule helpers
// ---------------------------------------------------------------------------

// mockRule is a minimal Rule implementation used throughout engine tests.
type mockRule struct {
	id       string
	name     string
	stage    models.GuardrailStage
	category models.RuleCategory
	evalFn   func(ctx *EvalContext) (*models.GuardrailEvaluation, error)
}

func (m *mockRule) ID() string                    { return m.id }
func (m *mockRule) Name() string                  { return m.name }
func (m *mockRule) Stage() models.GuardrailStage  { return m.stage }
func (m *mockRule) Category() models.RuleCategory { return m.category }

func (m *mockRule) Evaluate(ctx *EvalContext) (*models.GuardrailEvaluation, error) {
	if m.evalFn != nil {
		return m.evalFn(ctx)
	}
	return &models.GuardrailEvaluation{
		RuleID:   m.id,
		RuleName: m.name,
		Stage:    m.stage,
		Decision: models.DecisionAllow,
	}, nil
}

// blockingRule returns a mock rule that always blocks.
func blockingRule(id string, stage models.GuardrailStage) *mockRule {
	return &mockRule{
		id:       id,
		name:     "block-" + id,
		stage:    stage,
		category: models.CategoryInjection,
		evalFn: func(_ *EvalContext) (*models.GuardrailEvaluation, error) {
			return &models.GuardrailEvaluation{
				RuleID:     id,
				RuleName:   "block-" + id,
				Stage:      stage,
				Decision:   models.DecisionBlock,
				Confidence: 0.9,
				Reason:     "blocked by test rule",
			}, nil
		},
	}
}

// allowRule returns a mock rule that always allows.
func allowRule(id string, stage models.GuardrailStage) *mockRule {
	return &mockRule{
		id:       id,
		name:     "allow-" + id,
		stage:    stage,
		category: models.CategoryInjection,
	}
}

// slowRule returns a mock rule that sleeps for the given duration.
func slowRule(id string, stage models.GuardrailStage, d time.Duration) *mockRule {
	return &mockRule{
		id:       id,
		name:     "slow-" + id,
		stage:    stage,
		category: models.CategoryInjection,
		evalFn: func(ctx *EvalContext) (*models.GuardrailEvaluation, error) {
			select {
			case <-time.After(d):
			case <-ctx.Context().Done():
				return nil, ctx.Context().Err()
			}
			return &models.GuardrailEvaluation{
				RuleID:   id,
				RuleName: "slow-" + id,
				Stage:    stage,
				Decision: models.DecisionAllow,
			}, nil
		},
	}
}

// countingRule increments an atomic counter each time Evaluate is called.
func countingRule(id string, stage models.GuardrailStage, counter *atomic.Int64) *mockRule {
	return &mockRule{
		id:       id,
		name:     "counting-" + id,
		stage:    stage,
		category: models.CategoryInjection,
		evalFn: func(_ *EvalContext) (*models.GuardrailEvaluation, error) {
			counter.Add(1)
			return &models.GuardrailEvaluation{
				RuleID:   id,
				RuleName: "counting-" + id,
				Stage:    stage,
				Decision: models.DecisionAllow,
			}, nil
		},
	}
}

func makeEngineCtx(prompt string) *EvalContext {
	ctx := NewEvalContext(context.Background())
	ctx.WithPrompt(prompt)
	ctx.WithEnforcementMode(models.ModeEnforce)
	return ctx
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestEvaluate_FullPipeline_MultipleRules(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(allowRule("r-pre", models.StagePreInput), nil)
	_ = reg.Register(allowRule("r-input", models.StageInput), nil)
	_ = reg.Register(allowRule("r-output", models.StageOutput), nil)

	engine := NewEngine(reg, DefaultEngineConfig())
	evalCtx := makeEngineCtx("hello world")

	result, err := engine.Evaluate(evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FinalDecision != models.DecisionAllow {
		t.Fatalf("expected allow, got %s", result.FinalDecision)
	}
	if len(result.Evaluations) != 3 {
		t.Fatalf("expected 3 evaluations, got %d", len(result.Evaluations))
	}
}

func TestEvaluate_StageOrdering(t *testing.T) {
	var order []string
	makeOrderRule := func(id string, stage models.GuardrailStage) *mockRule {
		return &mockRule{
			id:       id,
			name:     id,
			stage:    stage,
			category: models.CategoryInjection,
			evalFn: func(_ *EvalContext) (*models.GuardrailEvaluation, error) {
				order = append(order, id)
				return &models.GuardrailEvaluation{
					RuleID:   id,
					RuleName: id,
					Stage:    stage,
					Decision: models.DecisionAllow,
				}, nil
			},
		}
	}

	reg := NewRegistry()
	_ = reg.Register(makeOrderRule("output-rule", models.StageOutput), nil)
	_ = reg.Register(makeOrderRule("pre-input-rule", models.StagePreInput), nil)
	_ = reg.Register(makeOrderRule("input-rule", models.StageInput), nil)

	engine := NewEngine(reg, DefaultEngineConfig())
	evalCtx := makeEngineCtx("test")

	_, err := engine.Evaluate(evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(order) != 3 {
		t.Fatalf("expected 3 ordered stages, got %d", len(order))
	}
	if order[0] != "pre-input-rule" {
		t.Errorf("expected pre_input first, got %s", order[0])
	}
	if order[1] != "input-rule" {
		t.Errorf("expected input second, got %s", order[1])
	}
	if order[2] != "output-rule" {
		t.Errorf("expected output third, got %s", order[2])
	}
}

func TestEvaluate_ShortCircuit_EnforceBlock(t *testing.T) {
	var outputRan atomic.Int64

	reg := NewRegistry()
	_ = reg.Register(blockingRule("blocker", models.StageInput), nil)
	_ = reg.Register(countingRule("output-rule", models.StageOutput, &outputRan), nil)

	engine := NewEngine(reg, DefaultEngineConfig())
	evalCtx := makeEngineCtx("test")

	result, err := engine.Evaluate(evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FinalDecision != models.DecisionBlock {
		t.Fatalf("expected block, got %s", result.FinalDecision)
	}
	if result.Blocked != true {
		t.Fatal("expected Blocked=true")
	}
	if outputRan.Load() != 0 {
		t.Fatalf("output stage should not have run after a block; ran %d times", outputRan.Load())
	}
}

func TestEvaluate_ModeOff_ReturnsAllow(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(blockingRule("blocker", models.StageInput), nil)

	engine := NewEngine(reg, DefaultEngineConfig())
	evalCtx := makeEngineCtx("test")
	evalCtx.WithEnforcementMode(models.ModeOff)

	result, err := engine.Evaluate(evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FinalDecision != models.DecisionAllow {
		t.Fatalf("mode=off should return allow, got %s", result.FinalDecision)
	}
	if len(result.Evaluations) != 0 {
		t.Fatalf("mode=off should not produce evaluations, got %d", len(result.Evaluations))
	}
}

func TestEvaluate_ModeMonitor_DowngradesBlockToAlert(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(blockingRule("blocker", models.StageInput), nil)

	engine := NewEngine(reg, DefaultEngineConfig())
	evalCtx := makeEngineCtx("test")
	evalCtx.WithEnforcementMode(models.ModeMonitor)

	result, err := engine.Evaluate(evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FinalDecision != models.DecisionAlert {
		t.Fatalf("monitor mode should downgrade block to alert, got %s", result.FinalDecision)
	}
	if result.Blocked {
		t.Fatal("monitor mode should not set Blocked=true")
	}
}

func TestEvaluate_ParallelExecution(t *testing.T) {
	var counter atomic.Int64
	reg := NewRegistry()

	for i := 0; i < 5; i++ {
		_ = reg.Register(countingRule(fmt.Sprintf("parallel-%d", i), models.StageInput, &counter), nil)
	}

	engine := NewEngine(reg, DefaultEngineConfig())
	evalCtx := makeEngineCtx("test")

	result, err := engine.Evaluate(evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if counter.Load() != 5 {
		t.Fatalf("expected 5 parallel rules to execute, got %d", counter.Load())
	}
	if result.FinalDecision != models.DecisionAllow {
		t.Fatalf("expected allow, got %s", result.FinalDecision)
	}
}

func TestEvaluate_StageTimeout(t *testing.T) {
	reg := NewRegistry()
	_ = reg.Register(slowRule("slow", models.StageInput, 5*time.Second), nil)

	cfg := DefaultEngineConfig()
	cfg.StageTimeouts[models.StageInput] = 50 * time.Millisecond

	engine := NewEngine(reg, cfg)
	evalCtx := makeEngineCtx("test")

	_, err := engine.Evaluate(evalCtx)
	if err == nil {
		t.Fatal("expected a timeout error, got nil")
	}
}

func TestEvaluate_EmptyRegistry_ReturnsAllow(t *testing.T) {
	reg := NewRegistry()
	engine := NewEngine(reg, DefaultEngineConfig())
	evalCtx := makeEngineCtx("test")

	result, err := engine.Evaluate(evalCtx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FinalDecision != models.DecisionAllow {
		t.Fatalf("empty registry should return allow, got %s", result.FinalDecision)
	}
}

func TestEvaluate_NilContext_ReturnsError(t *testing.T) {
	reg := NewRegistry()
	engine := NewEngine(reg, DefaultEngineConfig())

	_, err := engine.Evaluate(nil)
	if err == nil {
		t.Fatal("expected error for nil context, got nil")
	}
}

func TestBuildPipelineResult_MonitorMode(t *testing.T) {
	evals := []models.GuardrailEvaluation{
		{RuleID: "r1", Decision: models.DecisionBlock},
		{RuleID: "r2", Decision: models.DecisionAllow},
	}
	result := BuildPipelineResult(evals, models.ModeMonitor, 42)
	if result.FinalDecision != models.DecisionAlert {
		t.Fatalf("expected alert in monitor mode, got %s", result.FinalDecision)
	}
	if result.Blocked {
		t.Fatal("monitor mode should not set Blocked")
	}
}

func TestMergeDecisions(t *testing.T) {
	tests := []struct {
		name     string
		evals    []models.GuardrailEvaluation
		expected models.Decision
	}{
		{"empty returns allow", nil, models.DecisionAllow},
		{"single allow", []models.GuardrailEvaluation{{Decision: models.DecisionAllow}}, models.DecisionAllow},
		{"block wins", []models.GuardrailEvaluation{
			{Decision: models.DecisionAllow},
			{Decision: models.DecisionBlock},
		}, models.DecisionBlock},
		{"alert wins over allow", []models.GuardrailEvaluation{
			{Decision: models.DecisionAllow},
			{Decision: models.DecisionAlert},
		}, models.DecisionAlert},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeDecisions(tt.evals)
			if got != tt.expected {
				t.Errorf("MergeDecisions = %s, want %s", got, tt.expected)
			}
		})
	}
}
