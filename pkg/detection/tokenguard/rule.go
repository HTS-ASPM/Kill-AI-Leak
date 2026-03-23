// Package tokenguard provides a guardrail rule (GR-018) that rejects
// requests where the estimated input token count exceeds a configured maximum.
package tokenguard

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Rule implements guardrails.Rule for GR-018 Max Token Guard.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	maxTokens int
}

// New creates a new max token guard with a default limit.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			maxTokens: 32000,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-018" }
func (r *Rule) Name() string                  { return "Max Token Guard" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryRateLimit }

// estimateTokens provides a rough token count using the ~4 chars/token heuristic.
func estimateTokens(text string) int {
	// A reasonable approximation for English text: roughly 1 token per 4 characters.
	// Also count whitespace-delimited words as a secondary check.
	charEstimate := len(text) / 4
	wordEstimate := len(strings.Fields(text)) * 4 / 3
	if charEstimate > wordEstimate {
		return charEstimate
	}
	return wordEstimate
}

// Evaluate checks if the estimated token count of the prompt exceeds the limit.
func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	text := ctx.PromptText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no prompt text"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	estimated := estimateTokens(text)

	if estimated > cfg.maxTokens {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("estimated input tokens (%d) exceed limit (%d)", estimated, cfg.maxTokens)
		eval.Findings = []models.Finding{{
			Type:       "token_limit_exceeded",
			Value:      fmt.Sprintf("%d/%d", estimated, cfg.maxTokens),
			Severity:   "high",
			Confidence: 1.0,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	ratio := float64(estimated) / float64(cfg.maxTokens)
	if ratio > 0.8 {
		eval.Decision = models.DecisionAlert
		eval.Confidence = ratio
		eval.Reason = fmt.Sprintf("approaching token limit: %d/%d (%.0f%%)", estimated, cfg.maxTokens, ratio*100)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionAllow
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf("within token limit: ~%d/%d tokens", estimated, cfg.maxTokens)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["max_tokens"]; ok {
		switch n := v.(type) {
		case float64:
			if n <= 0 {
				return fmt.Errorf("tokenguard: max_tokens must be positive")
			}
			r.cfg.maxTokens = int(n)
		case int:
			if n <= 0 {
				return fmt.Errorf("tokenguard: max_tokens must be positive")
			}
			r.cfg.maxTokens = n
		}
	}
	return nil
}
