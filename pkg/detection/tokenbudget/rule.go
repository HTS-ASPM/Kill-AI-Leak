// Package tokenbudget provides a guardrail rule (GR-006) that enforces
// cumulative token usage budgets per actor on a daily and monthly basis.
package tokenbudget

import (
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// usageEntry records token usage for a single request.
type usageEntry struct {
	tokens int64
	cost   float64
	ts     time.Time
}

// Rule implements guardrails.Rule for GR-006 Token Budget Enforcement.
type Rule struct {
	mu    sync.RWMutex
	cfg   ruleConfig
	usage map[string][]usageEntry // keyed by actor ID
}

type ruleConfig struct {
	dailyTokenLimit   int64
	monthlyCostLimit  float64
}

// New creates a new token budget rule with sensible defaults.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			dailyTokenLimit:  1000000,
			monthlyCostLimit: 500.00,
		},
		usage: make(map[string][]usageEntry),
	}
}

func (r *Rule) ID() string                    { return "GR-006" }
func (r *Rule) Name() string                  { return "Token Budget Enforcement" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StagePreInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryRateLimit }

// RecordUsage records token and cost usage for an actor (called after a response).
func (r *Rule) RecordUsage(actorID string, tokens int64, costUSD float64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.usage[actorID] = append(r.usage[actorID], usageEntry{
		tokens: tokens,
		cost:   costUSD,
		ts:     time.Now(),
	})
}

// Evaluate checks the current actor's cumulative token/cost usage against limits.
func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	actorID := "unknown"
	if ctx.Actor != nil && ctx.Actor.ID != "" {
		actorID = ctx.Actor.ID
	}

	now := time.Now()
	dayStart := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())

	r.mu.RLock()
	entries := r.usage[actorID]
	r.mu.RUnlock()

	var dailyTokens int64
	var monthlyCost float64
	for _, e := range entries {
		if e.ts.After(monthStart) {
			monthlyCost += e.cost
		}
		if e.ts.After(dayStart) {
			dailyTokens += e.tokens
		}
	}

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	if dailyTokens >= cfg.dailyTokenLimit {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("daily token budget exceeded: %d/%d tokens", dailyTokens, cfg.dailyTokenLimit)
		eval.Findings = []models.Finding{{
			Type:       "daily_token_budget",
			Value:      fmt.Sprintf("%d/%d", dailyTokens, cfg.dailyTokenLimit),
			Severity:   "high",
			Confidence: 1.0,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	if monthlyCost >= cfg.monthlyCostLimit {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("monthly cost budget exceeded: $%.2f/$%.2f", monthlyCost, cfg.monthlyCostLimit)
		eval.Findings = []models.Finding{{
			Type:       "monthly_cost_budget",
			Value:      fmt.Sprintf("$%.2f/$%.2f", monthlyCost, cfg.monthlyCostLimit),
			Severity:   "high",
			Confidence: 1.0,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Warn at 80% thresholds.
	dailyRatio := float64(dailyTokens) / float64(cfg.dailyTokenLimit)
	costRatio := monthlyCost / cfg.monthlyCostLimit

	if dailyRatio > 0.8 || costRatio > 0.8 {
		eval.Decision = models.DecisionThrottle
		eval.Confidence = maxFloat(dailyRatio, costRatio)
		eval.Reason = fmt.Sprintf("approaching budget: tokens %d/%d (%.0f%%), cost $%.2f/$%.2f (%.0f%%)",
			dailyTokens, cfg.dailyTokenLimit, dailyRatio*100,
			monthlyCost, cfg.monthlyCostLimit, costRatio*100)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionAllow
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf("within budget: tokens %d/%d, cost $%.2f/$%.2f",
		dailyTokens, cfg.dailyTokenLimit, monthlyCost, cfg.monthlyCostLimit)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v, ok := cfg["daily_token_limit"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.dailyTokenLimit = int64(n)
		case int:
			r.cfg.dailyTokenLimit = int64(n)
		}
	}
	if v, ok := cfg["monthly_cost_limit_usd"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.monthlyCostLimit = f
		}
	}
	return nil
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
