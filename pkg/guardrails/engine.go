package guardrails

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// stageOrder defines the canonical execution order of pipeline stages.
var stageOrder = []models.GuardrailStage{
	models.StagePreInput,
	models.StageInput,
	models.StageRouting,
	models.StageOutput,
	models.StagePostOutput,
}

// EventPublisher is the interface for publishing guardrail decisions to an
// event bus. Implementations may send to Kafka, NATS, channels, etc.
type EventPublisher interface {
	Publish(ctx context.Context, event GuardrailEvent) error
}

// GuardrailEvent is emitted after each stage completes so external systems
// can observe decisions in real time.
type GuardrailEvent struct {
	Stage       models.GuardrailStage       `json:"stage"`
	Evaluations []models.GuardrailEvaluation `json:"evaluations"`
	Decision    models.Decision              `json:"decision"`
	Timestamp   time.Time                    `json:"timestamp"`
	SessionID   string                       `json:"session_id,omitempty"`
	ActorID     string                       `json:"actor_id,omitempty"`
}

// StageConfig holds per-stage configuration for the engine.
type StageConfig struct {
	Timeout time.Duration
}

// EngineConfig is the top-level configuration for the pipeline engine.
type EngineConfig struct {
	// StageTimeouts maps each stage to its timeout. If a stage is absent
	// the DefaultTimeout is used.
	StageTimeouts map[models.GuardrailStage]time.Duration

	// DefaultTimeout is used when no per-stage timeout is configured.
	DefaultTimeout time.Duration

	// MaxParallel limits the number of rules evaluated in parallel within
	// a single stage. Zero means unlimited.
	MaxParallel int
}

// DefaultEngineConfig returns a sensible default configuration.
func DefaultEngineConfig() *EngineConfig {
	return &EngineConfig{
		StageTimeouts: map[models.GuardrailStage]time.Duration{
			models.StagePreInput:   200 * time.Millisecond,
			models.StageInput:      2 * time.Second,
			models.StageRouting:    500 * time.Millisecond,
			models.StageOutput:     2 * time.Second,
			models.StagePostOutput: 1 * time.Second,
		},
		DefaultTimeout: 2 * time.Second,
		MaxParallel:    0,
	}
}

// Engine orchestrates the guardrail pipeline. It pulls rules from a
// Registry, evaluates them in stage order, and produces a PipelineResult.
type Engine struct {
	registry  *Registry
	config    *EngineConfig
	publisher EventPublisher // may be nil
}

// NewEngine creates an Engine with the given registry and configuration.
func NewEngine(registry *Registry, config *EngineConfig) *Engine {
	if config == nil {
		config = DefaultEngineConfig()
	}
	return &Engine{
		registry: registry,
		config:   config,
	}
}

// SetPublisher attaches an event publisher for decision logging.
func (e *Engine) SetPublisher(pub EventPublisher) {
	e.publisher = pub
}

// Evaluate runs the full pipeline. It executes stages in order, runs rules
// within each stage in parallel (respecting dependencies), and returns the
// aggregated result.
func (e *Engine) Evaluate(evalCtx *EvalContext) (*models.PipelineResult, error) {
	if evalCtx == nil {
		return nil, fmt.Errorf("guardrails: EvalContext must not be nil")
	}

	pipelineStart := time.Now()
	mode := evalCtx.GetEffectiveMode()

	// If mode is off, short-circuit: nothing to enforce.
	if mode == models.ModeOff {
		return &models.PipelineResult{
			FinalDecision:  models.DecisionAllow,
			TotalLatencyMs: time.Since(pipelineStart).Milliseconds(),
		}, nil
	}

	var allEvals []models.GuardrailEvaluation

	for _, stage := range stageOrder {
		rules := e.registry.GetByStage(stage)
		if len(rules) == 0 {
			continue
		}

		stageEvals, err := e.evaluateStage(evalCtx, stage, rules)
		if err != nil {
			return nil, fmt.Errorf("guardrails: stage %s: %w", stage, err)
		}

		allEvals = append(allEvals, stageEvals...)

		// Publish stage event for observability.
		e.publishStageEvent(evalCtx, stage, stageEvals)

		// Short-circuit: if any rule in this stage issued a BLOCK in
		// enforce mode, skip remaining stages.
		if mode == models.ModeEnforce && stageHasBlock(stageEvals) {
			break
		}
	}

	result := BuildPipelineResult(allEvals, mode, time.Since(pipelineStart).Milliseconds())
	return result, nil
}

// EvaluateStage runs a single stage. Exported so callers can run individual
// stages for testing or partial re-evaluation.
func (e *Engine) EvaluateStage(evalCtx *EvalContext, stage models.GuardrailStage) ([]models.GuardrailEvaluation, error) {
	rules := e.registry.GetByStage(stage)
	return e.evaluateStage(evalCtx, stage, rules)
}

// evaluateStage runs all rules for a single stage. Rules without
// dependencies execute in parallel; dependent rules wait for their
// prerequisites.
func (e *Engine) evaluateStage(evalCtx *EvalContext, stage models.GuardrailStage, rules []Rule) ([]models.GuardrailEvaluation, error) {
	timeout := e.stageTimeout(stage)
	stageCtx, cancel := context.WithTimeout(evalCtx.Context(), timeout)
	defer cancel()

	// Partition rules into independent and dependent sets.
	independent, dependent := partitionRules(rules)

	var (
		mu          sync.Mutex
		evals       []models.GuardrailEvaluation
		blocked     bool
		firstErr    error
		semaphore   chan struct{}
	)

	if e.config.MaxParallel > 0 {
		semaphore = make(chan struct{}, e.config.MaxParallel)
	}

	// Phase 1: run independent rules in parallel.
	var wg sync.WaitGroup
	for _, rule := range independent {
		rule := rule // capture

		wg.Add(1)
		go func() {
			defer wg.Done()

			// Acquire semaphore slot if limited.
			if semaphore != nil {
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-stageCtx.Done():
					return
				}
			}

			// Short-circuit: if another rule already blocked, skip
			// slower rules.
			mu.Lock()
			if blocked {
				mu.Unlock()
				return
			}
			mu.Unlock()

			eval, err := e.runRule(stageCtx, evalCtx, rule)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("rule %s: %w", rule.ID(), err)
				}
				return
			}
			evals = append(evals, *eval)
			evalCtx.RecordEvaluation(eval)
			if eval.Decision == models.DecisionBlock {
				blocked = true
			}
		}()
	}
	wg.Wait()

	if firstErr != nil {
		return evals, firstErr
	}

	// Phase 2: run dependent rules sequentially in dependency order.
	// (Dependencies were guaranteed to complete in phase 1 or an earlier
	// dependent rule.)
	for _, rule := range dependent {
		select {
		case <-stageCtx.Done():
			return evals, stageCtx.Err()
		default:
		}

		mu.Lock()
		if blocked {
			mu.Unlock()
			break
		}
		mu.Unlock()

		eval, err := e.runRule(stageCtx, evalCtx, rule)
		if err != nil {
			return evals, fmt.Errorf("rule %s: %w", rule.ID(), err)
		}
		mu.Lock()
		evals = append(evals, *eval)
		evalCtx.RecordEvaluation(eval)
		if eval.Decision == models.DecisionBlock {
			blocked = true
		}
		mu.Unlock()
	}

	return evals, nil
}

// runRule executes a single rule with timing and context wrapping.
func (e *Engine) runRule(stageCtx context.Context, evalCtx *EvalContext, rule Rule) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	// Create a child context that inherits the stage deadline.
	type ctxKeyType struct{}
	childCtx := &EvalContext{
		ctx:             stageCtx,
		PromptText:      evalCtx.PromptText,
		Headers:         evalCtx.Headers,
		Model:           evalCtx.Model,
		Provider:        evalCtx.Provider,
		ResponseText:    evalCtx.ResponseText,
		Actor:           evalCtx.Actor,
		Policy:          evalCtx.Policy,
		EnforcementMode: evalCtx.EnforcementMode,
		SessionID:       evalCtx.SessionID,
		sessionHistory:  evalCtx.GetSessionHistory(),
		anonMap:         evalCtx.GetAnonymizationMap(),
		completedEvals:  copyEvalMap(evalCtx),
		metadata:        copyMetadataMap(evalCtx),
	}

	eval, err := rule.Evaluate(childCtx)
	if err != nil {
		return nil, err
	}

	eval.LatencyMs = time.Since(start).Milliseconds()

	// Ensure the evaluation has the rule metadata filled in, even if the
	// rule implementation forgot.
	if eval.RuleID == "" {
		eval.RuleID = rule.ID()
	}
	if eval.RuleName == "" {
		eval.RuleName = rule.Name()
	}
	if eval.Stage == "" {
		eval.Stage = rule.Stage()
	}

	// Copy any anonymization mappings back to the parent context.
	for k, v := range childCtx.GetAnonymizationMap() {
		evalCtx.SetAnonymization(k, v)
	}

	return eval, nil
}

// stageTimeout returns the configured timeout for a stage.
func (e *Engine) stageTimeout(stage models.GuardrailStage) time.Duration {
	if t, ok := e.config.StageTimeouts[stage]; ok {
		return t
	}
	return e.config.DefaultTimeout
}

// publishStageEvent sends a GuardrailEvent to the event bus if a publisher
// is configured.
func (e *Engine) publishStageEvent(evalCtx *EvalContext, stage models.GuardrailStage, evals []models.GuardrailEvaluation) {
	if e.publisher == nil {
		return
	}

	event := GuardrailEvent{
		Stage:       stage,
		Evaluations: evals,
		Decision:    MergeDecisions(evals),
		Timestamp:   time.Now(),
		SessionID:   evalCtx.SessionID,
	}
	if evalCtx.Actor != nil {
		event.ActorID = evalCtx.Actor.ID
	}

	// Fire and forget; publishing failures should not block the pipeline.
	_ = e.publisher.Publish(evalCtx.Context(), event)
}

// stageHasBlock returns true if any evaluation in the slice is a BLOCK.
func stageHasBlock(evals []models.GuardrailEvaluation) bool {
	for i := range evals {
		if evals[i].Decision == models.DecisionBlock {
			return true
		}
	}
	return false
}

// partitionRules splits rules into independent (no dependencies) and
// dependent sets, preserving the original order for dependent rules.
func partitionRules(rules []Rule) (independent, dependent []Rule) {
	for _, r := range rules {
		if dr, ok := r.(DependentRule); ok && len(dr.Dependencies()) > 0 {
			dependent = append(dependent, r)
		} else {
			independent = append(independent, r)
		}
	}
	return
}

// copyEvalMap returns a snapshot of the eval map from an EvalContext.
func copyEvalMap(ec *EvalContext) map[string]*models.GuardrailEvaluation {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	out := make(map[string]*models.GuardrailEvaluation, len(ec.completedEvals))
	for k, v := range ec.completedEvals {
		out[k] = v
	}
	return out
}

// copyMetadataMap returns a snapshot of the metadata map from an EvalContext.
func copyMetadataMap(ec *EvalContext) map[string]any {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	out := make(map[string]any, len(ec.metadata))
	for k, v := range ec.metadata {
		out[k] = v
	}
	return out
}
