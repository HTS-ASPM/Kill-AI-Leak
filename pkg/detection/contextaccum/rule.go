// Package contextaccum provides a guardrail rule (GR-023) that analyzes
// accumulated context across conversation turns to detect gradual data
// exfiltration or prompt injection escalation.
package contextaccum

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Exfiltration indicators across multiple turns.
var exfiltrationKeywords = []string{
	"send to", "email me", "post to", "upload", "transfer",
	"webhook", "exfil", "forward to", "copy to external",
}

// Escalation keyword sequences that build up across turns.
var escalationKeywords = []string{
	"ignore instructions", "bypass", "override", "admin mode",
	"developer mode", "jailbreak", "pretend", "roleplay",
	"you are now", "new rules", "forget everything",
}

// Rule implements guardrails.Rule for GR-023 Multi-Turn Context Accumulation.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	maxSessionTurns      int
	escalationThreshold  float64
}

// New creates a new context accumulation rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			maxSessionTurns:     50,
			escalationThreshold: 0.70,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-023" }
func (r *Rule) Name() string                  { return "Multi-Turn Context Accumulation" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryExfiltration }

// Evaluate analyzes session history for escalation and exfiltration patterns.
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

	history := ctx.GetSessionHistory()
	if len(history) == 0 {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no session history; single-turn request"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	score := 0.0

	// Check if session exceeds max turns.
	if len(history) > cfg.maxSessionTurns {
		findings = append(findings, models.Finding{
			Type:       "excessive_turns",
			Value:      fmt.Sprintf("%d turns (max %d)", len(history), cfg.maxSessionTurns),
			Severity:   "medium",
			Confidence: 0.6,
		})
		score += 0.3
	}

	// Build full conversation text for analysis.
	var allUserText strings.Builder
	for _, turn := range history {
		if turn.Role == "user" {
			allUserText.WriteString(turn.Text)
			allUserText.WriteString(" ")
		}
	}
	// Include current prompt.
	allUserText.WriteString(ctx.PromptText)

	fullText := strings.ToLower(allUserText.String())

	// Check for exfiltration indicators accumulating across turns.
	exfilHits := 0
	for _, kw := range exfiltrationKeywords {
		if strings.Contains(fullText, kw) {
			exfilHits++
		}
	}
	if exfilHits >= 2 {
		confidence := 0.5 + float64(exfilHits)*0.1
		if confidence > 1.0 {
			confidence = 1.0
		}
		findings = append(findings, models.Finding{
			Type:       "exfiltration_pattern",
			Value:      fmt.Sprintf("%d exfiltration indicators across session", exfilHits),
			Severity:   "high",
			Confidence: confidence,
		})
		score += confidence * 0.5
	}

	// Check for escalation pattern buildup.
	escalationHits := 0
	for _, kw := range escalationKeywords {
		if strings.Contains(fullText, kw) {
			escalationHits++
		}
	}
	if escalationHits >= 2 {
		confidence := 0.5 + float64(escalationHits)*0.1
		if confidence > 1.0 {
			confidence = 1.0
		}
		findings = append(findings, models.Finding{
			Type:       "escalation_buildup",
			Value:      fmt.Sprintf("%d escalation keywords across session", escalationHits),
			Severity:   "high",
			Confidence: confidence,
		})
		score += confidence * 0.5
	}

	// Detect rapid topic changes between turns (possible payload splitting).
	if len(history) >= 3 {
		shifts := 0
		prevText := ""
		for _, turn := range history {
			if turn.Role == "user" && prevText != "" {
				if calculateOverlap(prevText, turn.Text) < 0.1 {
					shifts++
				}
			}
			if turn.Role == "user" {
				prevText = turn.Text
			}
		}
		if shifts > len(history)/3 {
			findings = append(findings, models.Finding{
				Type:       "topic_shifting",
				Value:      fmt.Sprintf("%d abrupt topic changes in %d turns", shifts, len(history)),
				Severity:   "medium",
				Confidence: 0.6,
			})
			score += 0.2
		}
	}

	if score > 1.0 {
		score = 1.0
	}

	eval.Findings = findings
	eval.Confidence = score

	if score >= cfg.escalationThreshold {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("multi-turn escalation detected (score=%.2f); %d finding(s)", score, len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("possible multi-turn anomaly (score=%.2f); %d finding(s)", score, len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("session appears normal (score=%.2f, %d turns)", score, len(history))
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["max_session_turns"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.maxSessionTurns = int(n)
		case int:
			r.cfg.maxSessionTurns = n
		}
	}
	if v, ok := cfg["escalation_threshold"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.escalationThreshold = f
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// calculateOverlap computes a simple word overlap ratio between two texts.
func calculateOverlap(a, b string) float64 {
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))
	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}
	set := make(map[string]bool, len(wordsA))
	for _, w := range wordsA {
		set[w] = true
	}
	overlap := 0
	for _, w := range wordsB {
		if set[w] {
			overlap++
		}
	}
	denom := len(wordsA)
	if len(wordsB) < denom {
		denom = len(wordsB)
	}
	return float64(overlap) / float64(denom)
}
