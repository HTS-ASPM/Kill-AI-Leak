package guardrails

import (
	"context"
	"sync"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// EvalContext carries all data through the guardrail pipeline.
// It is created once per request and passed to every rule. Methods that
// mutate state are safe for concurrent use.
type EvalContext struct {
	// ctx is the parent context for cancellation and deadlines.
	ctx context.Context

	// Request info
	PromptText string
	Headers    map[string]string
	Model      string
	Provider   string

	// Response info (populated for output/post_output stages)
	ResponseText string

	// Actor info
	Actor *models.Actor

	// Policy info
	Policy *models.AISecurityPolicy

	// Enforcement mode override (if set, takes precedence over Policy.Spec.Mode).
	EnforcementMode models.EnforcementMode

	// Session state for multi-turn tracking
	SessionID      string
	sessionHistory []SessionTurn

	// Anonymization mapping: original value -> anonymized placeholder.
	// Used by anonymization rules to record replacements, and by
	// de-anonymization in post_output to reverse them.
	anonMap map[string]string

	// Results from rules that have already executed in the current pipeline
	// run. Keyed by rule ID. Used to pass dependency outputs.
	completedEvals map[string]*models.GuardrailEvaluation

	// Arbitrary key-value metadata that rules can attach for downstream
	// consumers (e.g., logging enrichment, routing hints).
	metadata map[string]any

	mu sync.RWMutex
}

// SessionTurn records a single turn in a multi-turn conversation.
type SessionTurn struct {
	Role string // "user" or "assistant"
	Text string
}

// NewEvalContext creates an EvalContext with the given parent context.
func NewEvalContext(ctx context.Context) *EvalContext {
	return &EvalContext{
		ctx:            ctx,
		Headers:        make(map[string]string),
		anonMap:        make(map[string]string),
		completedEvals: make(map[string]*models.GuardrailEvaluation),
		metadata:       make(map[string]any),
	}
}

// Context returns the underlying context.Context for cancellation and
// deadline checks.
func (ec *EvalContext) Context() context.Context {
	return ec.ctx
}

// WithPrompt returns a shallow copy of the context with the prompt text set.
// This is used to chain context setup before pipeline execution.
func (ec *EvalContext) WithPrompt(prompt string) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.PromptText = prompt
	return ec
}

// WithResponse returns the context with the response text set.
// Called between the input and output stages when the LLM response arrives.
func (ec *EvalContext) WithResponse(response string) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.ResponseText = response
	return ec
}

// WithActor sets the actor on the context.
func (ec *EvalContext) WithActor(actor *models.Actor) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Actor = actor
	return ec
}

// WithPolicy sets the policy on the context.
func (ec *EvalContext) WithPolicy(policy *models.AISecurityPolicy) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Policy = policy
	return ec
}

// WithModel sets the target model on the context.
func (ec *EvalContext) WithModel(model string) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Model = model
	return ec
}

// WithProvider sets the target provider on the context.
func (ec *EvalContext) WithProvider(provider string) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Provider = provider
	return ec
}

// WithHeaders sets all request headers on the context.
func (ec *EvalContext) WithHeaders(headers map[string]string) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.Headers = headers
	return ec
}

// WithSessionID sets the session identifier for multi-turn tracking.
func (ec *EvalContext) WithSessionID(id string) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.SessionID = id
	return ec
}

// WithEnforcementMode overrides the enforcement mode for this evaluation.
func (ec *EvalContext) WithEnforcementMode(mode models.EnforcementMode) *EvalContext {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.EnforcementMode = mode
	return ec
}

// AddSessionTurn appends a turn to the session history. Safe for concurrent use.
func (ec *EvalContext) AddSessionTurn(role, text string) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.sessionHistory = append(ec.sessionHistory, SessionTurn{Role: role, Text: text})
}

// GetSessionHistory returns a copy of the session history.
func (ec *EvalContext) GetSessionHistory() []SessionTurn {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	out := make([]SessionTurn, len(ec.sessionHistory))
	copy(out, ec.sessionHistory)
	return out
}

// SetAnonymization records an anonymization mapping.
func (ec *EvalContext) SetAnonymization(original, placeholder string) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.anonMap[original] = placeholder
}

// GetAnonymizationMap returns a copy of the anonymization mapping.
func (ec *EvalContext) GetAnonymizationMap() map[string]string {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	out := make(map[string]string, len(ec.anonMap))
	for k, v := range ec.anonMap {
		out[k] = v
	}
	return out
}

// RecordEvaluation stores a completed evaluation so dependent rules can
// access it.
func (ec *EvalContext) RecordEvaluation(eval *models.GuardrailEvaluation) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.completedEvals[eval.RuleID] = eval
}

// GetEvaluation retrieves a previously completed evaluation by rule ID.
func (ec *EvalContext) GetEvaluation(ruleID string) (*models.GuardrailEvaluation, bool) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	eval, ok := ec.completedEvals[ruleID]
	return eval, ok
}

// SetMetadata stores an arbitrary key-value pair for downstream use.
func (ec *EvalContext) SetMetadata(key string, value any) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.metadata[key] = value
}

// GetMetadata retrieves a metadata value by key.
func (ec *EvalContext) GetMetadata(key string) (any, bool) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	v, ok := ec.metadata[key]
	return v, ok
}

// GetEffectiveMode returns the enforcement mode to use. If an explicit
// override is set on the context it takes precedence; otherwise the mode
// from the attached policy is used. If neither is set, ModeEnforce is the
// default.
func (ec *EvalContext) GetEffectiveMode() models.EnforcementMode {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	if ec.EnforcementMode != "" {
		return ec.EnforcementMode
	}
	if ec.Policy != nil && ec.Policy.Spec.Mode != "" {
		return ec.Policy.Spec.Mode
	}
	return models.ModeEnforce
}
