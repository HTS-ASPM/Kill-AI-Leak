// Package sessiondrift provides a guardrail rule (GR-053) that monitors
// multi-turn conversations for topic drift away from the original intent,
// which may indicate social engineering or gradual injection attacks.
package sessiondrift

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Rule implements guardrails.Rule for GR-053 Session Drift Detection.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	driftThreshold float64
	windowTurns    int
}

// New creates a GR-053 rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			driftThreshold: 0.60,
			windowTurns:    10,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-053" }
func (r *Rule) Name() string                  { return "Session Drift Detection" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageBehavioral }
func (r *Rule) Category() models.RuleCategory { return models.CategoryExfiltration }

func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	history := ctx.GetSessionHistory()
	if len(history) < 2 {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "insufficient session history for drift detection"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Use the configured window.
	windowStart := 0
	if len(history) > cfg.windowTurns {
		windowStart = len(history) - cfg.windowTurns
	}
	window := history[windowStart:]

	// Extract vocabulary from the first turn (original intent).
	firstUserTurn := ""
	for _, turn := range history {
		if turn.Role == "user" {
			firstUserTurn = turn.Text
			break
		}
	}
	if firstUserTurn == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no user turns in session"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Extract vocabulary from recent turns.
	var recentText strings.Builder
	for _, turn := range window {
		if turn.Role == "user" {
			recentText.WriteString(turn.Text)
			recentText.WriteString(" ")
		}
	}
	// Include current prompt.
	recentText.WriteString(ctx.PromptText)

	// Calculate drift as 1 - overlap between original and recent vocabulary.
	originalWords := extractWordSet(firstUserTurn)
	recentWords := extractWordSet(recentText.String())

	overlap := 0
	for w := range originalWords {
		if recentWords[w] {
			overlap++
		}
	}

	denom := len(originalWords)
	if denom == 0 {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "empty original vocabulary"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	overlapRatio := float64(overlap) / float64(denom)
	driftScore := 1.0 - overlapRatio

	eval.Confidence = driftScore
	var findings []models.Finding

	if driftScore >= cfg.driftThreshold {
		findings = append(findings, models.Finding{
			Type:       "session_drift",
			Value:      fmt.Sprintf("drift=%.2f (overlap=%.2f)", driftScore, overlapRatio),
			Severity:   "medium",
			Confidence: driftScore,
		})
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("session drift detected (score=%.2f, threshold=%.2f); conversation has diverged from original intent",
			driftScore, cfg.driftThreshold)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("session drift within bounds (score=%.2f, threshold=%.2f)", driftScore, cfg.driftThreshold)
	}

	eval.Findings = findings
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["drift_threshold"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.driftThreshold = f
		}
	}
	if v, ok := cfg["window_turns"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.windowTurns = int(n)
		case int:
			r.cfg.windowTurns = n
		}
	}
	return nil
}

// extractWordSet converts text to a set of normalized words (lowercase, 3+ chars).
func extractWordSet(text string) map[string]bool {
	words := strings.Fields(strings.ToLower(text))
	set := make(map[string]bool, len(words))
	for _, w := range words {
		// Strip common punctuation.
		w = strings.Trim(w, ".,;:!?\"'()[]{}/-")
		if len(w) >= 3 {
			set[w] = true
		}
	}
	return set
}
