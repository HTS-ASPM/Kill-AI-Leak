// Package ratelimit provides a guardrail rule that enforces per-actor
// request rate limits using an in-memory sliding window counter.
package ratelimit

import (
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Sliding window counter
// ---------------------------------------------------------------------------

// entry records a single timestamp for a request.
type entry struct {
	ts time.Time
}

// windowCounter is a per-actor sliding window rate counter.
type windowCounter struct {
	mu      sync.RWMutex
	windows map[string][]entry // keyed by actor ID
}

func newWindowCounter() *windowCounter {
	return &windowCounter{
		windows: make(map[string][]entry),
	}
}

// record adds a new timestamp for the given actor and prunes entries older
// than maxAge.
func (wc *windowCounter) record(actorID string, maxAge time.Duration) {
	wc.mu.Lock()
	defer wc.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-maxAge)

	entries := wc.windows[actorID]
	// Prune expired entries.
	pruned := entries[:0]
	for _, e := range entries {
		if e.ts.After(cutoff) {
			pruned = append(pruned, e)
		}
	}
	pruned = append(pruned, entry{ts: now})
	wc.windows[actorID] = pruned
}

// count returns the number of requests for the given actor within the
// specified window duration.
func (wc *windowCounter) count(actorID string, window time.Duration) int {
	wc.mu.RLock()
	defer wc.mu.RUnlock()

	cutoff := time.Now().Add(-window)
	n := 0
	for _, e := range wc.windows[actorID] {
		if e.ts.After(cutoff) {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Rule implements guardrails.Rule
// ---------------------------------------------------------------------------

// Rule enforces per-actor rate limits as a pre-input guardrail.
type Rule struct {
	mu      sync.RWMutex
	cfg     ruleConfig
	counter *windowCounter
}

type ruleConfig struct {
	// requestsPerMinute is the maximum requests per actor per minute.
	// Default: 30
	requestsPerMinute int

	// requestsPerHour is the maximum requests per actor per hour.
	// Default: 300
	requestsPerHour int
}

// New creates a new rate-limit Rule with sensible defaults.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			requestsPerMinute: 30,
			requestsPerHour:   300,
		},
		counter: newWindowCounter(),
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (r *Rule) ID() string                    { return "GR-002" }
func (r *Rule) Name() string                  { return "Rate Limiter" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StagePreInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryRateLimit }

// Evaluate checks the current actor's request rate against the configured
// limits.
func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	// Determine actor ID.
	actorID := "unknown"
	if ctx.Actor != nil && ctx.Actor.ID != "" {
		actorID = ctx.Actor.ID
	}

	// Record this request (prune entries older than 1 hour).
	r.counter.record(actorID, time.Hour)

	// Count requests in both windows.
	minuteCount := r.counter.count(actorID, time.Minute)
	hourCount := r.counter.count(actorID, time.Hour)

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	// Check hard limits.
	if minuteCount > cfg.requestsPerMinute {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf(
			"rate limit exceeded: %d requests/min (limit: %d)",
			minuteCount, cfg.requestsPerMinute,
		)
		eval.Findings = []models.Finding{{
			Type:       "rate_limit_minute",
			Value:      fmt.Sprintf("%d/%d", minuteCount, cfg.requestsPerMinute),
			Severity:   "high",
			Confidence: 1.0,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	if hourCount > cfg.requestsPerHour {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf(
			"rate limit exceeded: %d requests/hr (limit: %d)",
			hourCount, cfg.requestsPerHour,
		)
		eval.Findings = []models.Finding{{
			Type:       "rate_limit_hour",
			Value:      fmt.Sprintf("%d/%d", hourCount, cfg.requestsPerHour),
			Severity:   "high",
			Confidence: 1.0,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Check throttle thresholds (>80% of limit).
	minuteRatio := float64(minuteCount) / float64(cfg.requestsPerMinute)
	hourRatio := float64(hourCount) / float64(cfg.requestsPerHour)

	if minuteRatio > 0.8 || hourRatio > 0.8 {
		ratio := minuteRatio
		window := "minute"
		count := minuteCount
		limit := cfg.requestsPerMinute
		if hourRatio > minuteRatio {
			ratio = hourRatio
			window = "hour"
			count = hourCount
			limit = cfg.requestsPerHour
		}

		eval.Decision = models.DecisionThrottle
		eval.Confidence = ratio
		eval.Reason = fmt.Sprintf(
			"approaching rate limit: %d/%d requests per %s (%.0f%%)",
			count, limit, window, ratio*100,
		)
		eval.Findings = []models.Finding{{
			Type:       "rate_limit_approaching",
			Value:      fmt.Sprintf("%d/%d per %s", count, limit, window),
			Severity:   "medium",
			Confidence: ratio,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Within limits.
	eval.Decision = models.DecisionAllow
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf(
		"within rate limits: %d/%d per minute, %d/%d per hour",
		minuteCount, cfg.requestsPerMinute, hourCount, cfg.requestsPerHour,
	)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "requests_per_minute" (float64/int): max requests per actor per minute.
//   - "requests_per_hour"   (float64/int): max requests per actor per hour.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v, ok := cfg["requests_per_minute"]; ok {
		switch n := v.(type) {
		case float64:
			if n <= 0 {
				return fmt.Errorf("ratelimit: requests_per_minute must be positive")
			}
			r.cfg.requestsPerMinute = int(n)
		case int:
			if n <= 0 {
				return fmt.Errorf("ratelimit: requests_per_minute must be positive")
			}
			r.cfg.requestsPerMinute = n
		}
	}

	if v, ok := cfg["requests_per_hour"]; ok {
		switch n := v.(type) {
		case float64:
			if n <= 0 {
				return fmt.Errorf("ratelimit: requests_per_hour must be positive")
			}
			r.cfg.requestsPerHour = int(n)
		case int:
			if n <= 0 {
				return fmt.Errorf("ratelimit: requests_per_hour must be positive")
			}
			r.cfg.requestsPerHour = n
		}
	}

	return nil
}
