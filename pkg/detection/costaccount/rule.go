// Package costaccount provides a guardrail rule (GR-047) that calculates
// and records the cost of each request based on provider pricing and token
// counts, aggregated by team, service, and namespace.
package costaccount

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Default pricing per 1K tokens (USD) by provider and model tier.
var defaultPricing = map[string]float64{
	"openai:gpt-4o":            0.005,
	"openai:gpt-4o-mini":       0.00015,
	"openai:gpt-4":             0.03,
	"openai:gpt-3.5-turbo":     0.0005,
	"anthropic:claude-opus":    0.015,
	"anthropic:claude-sonnet":  0.003,
	"anthropic:claude-haiku":   0.00025,
	"gemini:gemini-pro":        0.00025,
	"gemini:gemini-1.5":        0.00125,
	"bedrock":                  0.008,
	"azure":                    0.03,
	"mistral":                  0.002,
}

// CostEntry records a single cost event.
type CostEntry struct {
	Timestamp time.Time
	ActorID   string
	Team      string
	Namespace string
	Provider  string
	Model     string
	Tokens    int64
	CostUSD   float64
}

// Rule implements guardrails.Rule for GR-047 Cost Accounting.
type Rule struct {
	mu      sync.RWMutex
	cfg     ruleConfig
	entries []CostEntry
}

type ruleConfig struct {
	pricingSource string
}

// New creates a new cost accounting rule.
func New() *Rule {
	return &Rule{
		cfg:     ruleConfig{pricingSource: "built_in"},
		entries: nil,
	}
}

func (r *Rule) ID() string                    { return "GR-047" }
func (r *Rule) Name() string                  { return "Cost Accounting" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StagePostOutput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryRateLimit }

func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	provider := strings.ToLower(ctx.Provider)
	model := strings.ToLower(ctx.Model)

	// Estimate tokens from prompt + response.
	promptTokens := int64(len(ctx.PromptText) / 4)
	responseTokens := int64(len(ctx.ResponseText) / 4)
	totalTokens := promptTokens + responseTokens

	// Look up pricing.
	priceKey := provider + ":" + model
	pricePerKTok, found := defaultPricing[priceKey]
	if !found {
		// Try provider-only fallback.
		pricePerKTok, found = defaultPricing[provider]
		if !found {
			pricePerKTok = 0.01 // default fallback
		}
	}

	costUSD := float64(totalTokens) / 1000.0 * pricePerKTok

	actorID := ""
	team := ""
	namespace := ""
	if ctx.Actor != nil {
		actorID = ctx.Actor.ID
		team = ctx.Actor.Team
		namespace = ctx.Actor.Namespace
	}

	entry := CostEntry{
		Timestamp: time.Now(),
		ActorID:   actorID,
		Team:      team,
		Namespace: namespace,
		Provider:  provider,
		Model:     model,
		Tokens:    totalTokens,
		CostUSD:   costUSD,
	}

	r.mu.Lock()
	r.entries = append(r.entries, entry)
	r.mu.Unlock()

	ctx.SetMetadata("request_cost_usd", costUSD)
	ctx.SetMetadata("request_total_tokens", totalTokens)

	eval.Decision = models.DecisionLog
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf("cost=$%.6f, tokens=%d (%s/%s), team=%s", costUSD, totalTokens, provider, model, team)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// GetEntries returns a copy of the cost log.
func (r *Rule) GetEntries() []CostEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]CostEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["pricing_source"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.pricingSource = s
		}
	}
	return nil
}
