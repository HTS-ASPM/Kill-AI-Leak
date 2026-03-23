// Package circuitbreaker implements a guardrail rule (GR-022) that tracks
// per-provider failure counts in a sliding window and trips a circuit breaker
// to protect callers from repeatedly hitting a failing upstream.
//
// States:
//
//	CLOSED   (normal)    -- requests pass through, failures are counted.
//	OPEN     (failing)   -- requests are blocked with a clear reason.
//	HALF_OPEN (testing)  -- a limited number of requests pass through to test recovery.
package circuitbreaker

import (
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// CircuitState represents the current state of a per-provider circuit.
type CircuitState int

const (
	StateClosed   CircuitState = iota // normal operation
	StateOpen                         // circuit tripped, blocking requests
	StateHalfOpen                     // testing whether the provider recovered
)

// String returns the human-readable name of the circuit state.
func (s CircuitState) String() string {
	switch s {
	case StateClosed:
		return "CLOSED"
	case StateOpen:
		return "OPEN"
	case StateHalfOpen:
		return "HALF_OPEN"
	default:
		return "UNKNOWN"
	}
}

// providerCircuit tracks the state of a single provider's circuit.
type providerCircuit struct {
	state         CircuitState
	failures      []time.Time // timestamps of recent failures
	lastFailure   time.Time
	openedAt      time.Time
	halfOpenCount int // number of test requests allowed in half-open state
}

// Rule implements guardrails.Rule as a circuit breaker for upstream providers.
type Rule struct {
	mu       sync.RWMutex
	circuits map[string]*providerCircuit // keyed by provider name
	cfg      ruleConfig
}

type ruleConfig struct {
	// failureThreshold is the number of failures within the sliding window
	// that trips the circuit to OPEN. Default: 5.
	failureThreshold int

	// resetTimeout is how long the circuit stays OPEN before transitioning
	// to HALF_OPEN. Default: 60s.
	resetTimeout time.Duration

	// halfOpenMax is the maximum number of test requests allowed in HALF_OPEN
	// state before the circuit fully closes (on success) or re-opens (on failure).
	// Default: 1.
	halfOpenMax int

	// windowDuration is the sliding window for counting failures. Default: 120s.
	windowDuration time.Duration
}

// New creates a new circuit breaker Rule with sensible defaults.
func New() *Rule {
	return &Rule{
		circuits: make(map[string]*providerCircuit),
		cfg: ruleConfig{
			failureThreshold: 5,
			resetTimeout:     60 * time.Second,
			halfOpenMax:      1,
			windowDuration:   120 * time.Second,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (r *Rule) ID() string                    { return "GR-022" }
func (r *Rule) Name() string                  { return "Circuit Breaker" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *Rule) Category() models.RuleCategory { return "routing" }

// Evaluate checks the circuit breaker state for the provider in the
// evaluation context. If the circuit is OPEN, the request is blocked.
func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	provider := ctx.Provider
	if provider == "" {
		// No provider specified; allow.
		return &models.GuardrailEvaluation{
			RuleID:    r.ID(),
			RuleName:  r.Name(),
			Stage:     r.Stage(),
			Decision:  models.DecisionAllow,
			Reason:    "no provider specified",
			LatencyMs: time.Since(start).Milliseconds(),
		}, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	circuit := r.getOrCreateCircuit(provider)
	now := time.Now()

	switch circuit.state {
	case StateOpen:
		// Check if the reset timeout has elapsed.
		if now.Sub(circuit.openedAt) >= r.cfg.resetTimeout {
			// Transition to HALF_OPEN.
			circuit.state = StateHalfOpen
			circuit.halfOpenCount = 0
			return r.allowEval(start, provider, "circuit half-open, testing provider recovery"), nil
		}

		// Still OPEN -- block the request.
		return &models.GuardrailEvaluation{
			RuleID:     r.ID(),
			RuleName:   r.Name(),
			Stage:      r.Stage(),
			Decision:   models.DecisionBlock,
			Confidence: 1.0,
			Reason:     fmt.Sprintf("provider circuit breaker open for %q (failures: %d, reopens in %s)", provider, len(circuit.failures), (r.cfg.resetTimeout - now.Sub(circuit.openedAt)).Round(time.Second)),
			Findings: []models.Finding{{
				Type:       "circuit_breaker_open",
				Value:      provider,
				Severity:   "high",
				Confidence: 1.0,
			}},
			LatencyMs: time.Since(start).Milliseconds(),
		}, nil

	case StateHalfOpen:
		// Allow a limited number of test requests.
		if circuit.halfOpenCount >= r.cfg.halfOpenMax {
			return &models.GuardrailEvaluation{
				RuleID:     r.ID(),
				RuleName:   r.Name(),
				Stage:      r.Stage(),
				Decision:   models.DecisionBlock,
				Confidence: 1.0,
				Reason:     fmt.Sprintf("provider circuit breaker half-open for %q, max test requests (%d) reached", provider, r.cfg.halfOpenMax),
				Findings: []models.Finding{{
					Type:       "circuit_breaker_half_open",
					Value:      provider,
					Severity:   "medium",
					Confidence: 1.0,
				}},
				LatencyMs: time.Since(start).Milliseconds(),
			}, nil
		}
		circuit.halfOpenCount++
		return r.allowEval(start, provider, "circuit half-open, test request allowed"), nil

	default: // StateClosed
		return r.allowEval(start, provider, fmt.Sprintf("circuit closed, failures in window: %d/%d", r.countRecentFailures(circuit), r.cfg.failureThreshold)), nil
	}
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "failure_threshold" (float64/int): number of failures to trip.
//   - "reset_timeout_seconds" (float64/int): seconds before half-open.
//   - "half_open_max" (float64/int): max test requests in half-open.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v, ok := cfg["failure_threshold"]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			r.cfg.failureThreshold = n
		}
	}
	if v, ok := cfg["reset_timeout_seconds"]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			r.cfg.resetTimeout = time.Duration(n) * time.Second
		}
	}
	if v, ok := cfg["half_open_max"]; ok {
		if n, ok := toInt(v); ok && n > 0 {
			r.cfg.halfOpenMax = n
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// RecordSuccess / RecordFailure -- called by the proxy after upstream response
// ---------------------------------------------------------------------------

// RecordSuccess records a successful upstream response for the provider.
// If the circuit is HALF_OPEN, it transitions back to CLOSED.
func (r *Rule) RecordSuccess(provider string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	circuit, ok := r.circuits[provider]
	if !ok {
		return
	}

	if circuit.state == StateHalfOpen {
		// Provider recovered -- close the circuit.
		circuit.state = StateClosed
		circuit.failures = nil
		circuit.halfOpenCount = 0
	}
}

// RecordFailure records a failed upstream response for the provider.
// If the failure count exceeds the threshold, the circuit trips to OPEN.
func (r *Rule) RecordFailure(provider string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	circuit := r.getOrCreateCircuit(provider)
	now := time.Now()

	// If already HALF_OPEN and we see a failure, re-open immediately.
	if circuit.state == StateHalfOpen {
		circuit.state = StateOpen
		circuit.openedAt = now
		circuit.lastFailure = now
		return
	}

	// Record the failure timestamp.
	circuit.failures = append(circuit.failures, now)
	circuit.lastFailure = now

	// Prune failures outside the sliding window.
	r.pruneFailures(circuit)

	// Check if the threshold is exceeded.
	if len(circuit.failures) >= r.cfg.failureThreshold {
		circuit.state = StateOpen
		circuit.openedAt = now
	}
}

// GetState returns the current circuit state for a provider.
// This is useful for diagnostics and health checks.
func (r *Rule) GetState(provider string) CircuitState {
	r.mu.RLock()
	defer r.mu.RUnlock()

	circuit, ok := r.circuits[provider]
	if !ok {
		return StateClosed
	}
	return circuit.state
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

// getOrCreateCircuit returns the circuit for a provider, creating one if needed.
// Caller must hold the write lock.
func (r *Rule) getOrCreateCircuit(provider string) *providerCircuit {
	circuit, ok := r.circuits[provider]
	if !ok {
		circuit = &providerCircuit{state: StateClosed}
		r.circuits[provider] = circuit
	}
	return circuit
}

// pruneFailures removes failure timestamps outside the sliding window.
// Caller must hold the write lock.
func (r *Rule) pruneFailures(circuit *providerCircuit) {
	cutoff := time.Now().Add(-r.cfg.windowDuration)
	pruned := circuit.failures[:0]
	for _, ts := range circuit.failures {
		if ts.After(cutoff) {
			pruned = append(pruned, ts)
		}
	}
	circuit.failures = pruned
}

// countRecentFailures returns the number of failures within the sliding window.
// Caller must hold at least a read lock.
func (r *Rule) countRecentFailures(circuit *providerCircuit) int {
	cutoff := time.Now().Add(-r.cfg.windowDuration)
	count := 0
	for _, ts := range circuit.failures {
		if ts.After(cutoff) {
			count++
		}
	}
	return count
}

// allowEval constructs an ALLOW evaluation result.
func (r *Rule) allowEval(start time.Time, provider, reason string) *models.GuardrailEvaluation {
	return &models.GuardrailEvaluation{
		RuleID:    r.ID(),
		RuleName:  r.Name(),
		Stage:     r.Stage(),
		Decision:  models.DecisionAllow,
		Reason:    reason,
		LatencyMs: time.Since(start).Milliseconds(),
	}
}

// toInt attempts to convert a JSON-decoded value to int.
func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case float64:
		return int(n), true
	case int:
		return n, true
	case int64:
		return int(n), true
	}
	return 0, false
}
