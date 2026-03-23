// Package agentloop provides a guardrail rule (GR-054) that detects and
// breaks infinite or excessively long agent tool-use loops that waste resources.
package agentloop

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// sessionState tracks iteration count per session.
type sessionState struct {
	iterations     int
	lastMessages   []string // recent turn contents for similarity check
	lastActivityAt time.Time
}

// Rule implements guardrails.Rule for GR-054 Recursive Agent Loop Detection.
type Rule struct {
	mu       sync.RWMutex
	cfg      ruleConfig
	sessions map[string]*sessionState
}

type ruleConfig struct {
	maxIterations       int
	similarityThreshold float64
	breakAction         string // "block" or "alert"
}

// New creates a GR-054 rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			maxIterations:       25,
			similarityThreshold: 0.90,
			breakAction:         "block",
		},
		sessions: make(map[string]*sessionState),
	}
}

func (r *Rule) ID() string                    { return "GR-054" }
func (r *Rule) Name() string                  { return "Recursive Agent Loop Detection" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageBehavioral }
func (r *Rule) Category() models.RuleCategory { return models.CategoryAgentControl }

func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	sessionID := ctx.SessionID
	if sessionID == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no session ID; loop detection skipped"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	r.mu.Lock()
	state, exists := r.sessions[sessionID]
	if !exists {
		state = &sessionState{}
		r.sessions[sessionID] = state
	}
	state.iterations++
	state.lastActivityAt = time.Now()

	currentText := ctx.PromptText
	var findings []models.Finding

	// Check for repetitive content (loop indicator).
	isRepetitive := false
	if len(state.lastMessages) > 0 && currentText != "" {
		for _, prev := range state.lastMessages {
			sim := calculateSimilarity(prev, currentText)
			if sim >= cfg.similarityThreshold {
				isRepetitive = true
				findings = append(findings, models.Finding{
					Type:       "repetitive_content",
					Value:      fmt.Sprintf("similarity=%.2f with previous turn", sim),
					Severity:   "medium",
					Confidence: sim,
				})
				break
			}
		}
	}

	// Keep the last 5 messages for comparison.
	if currentText != "" {
		state.lastMessages = append(state.lastMessages, currentText)
		if len(state.lastMessages) > 5 {
			state.lastMessages = state.lastMessages[len(state.lastMessages)-5:]
		}
	}

	iterations := state.iterations
	r.mu.Unlock()

	// Check iteration limit.
	if iterations > cfg.maxIterations {
		findings = append(findings, models.Finding{
			Type:       "max_iterations_exceeded",
			Value:      fmt.Sprintf("%d/%d", iterations, cfg.maxIterations),
			Severity:   "high",
			Confidence: 1.0,
		})
	}

	eval.Findings = findings

	if iterations > cfg.maxIterations || (isRepetitive && iterations > cfg.maxIterations/2) {
		if cfg.breakAction == "block" {
			eval.Decision = models.DecisionBlock
		} else {
			eval.Decision = models.DecisionAlert
		}
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("agent loop detected: %d iterations (max %d), repetitive=%v",
			iterations, cfg.maxIterations, isRepetitive)
	} else if isRepetitive {
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.7
		eval.Reason = fmt.Sprintf("possible agent loop: repetitive content at iteration %d", iterations)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("iteration %d/%d, no loop detected", iterations, cfg.maxIterations)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["max_iterations"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.maxIterations = int(n)
		case int:
			r.cfg.maxIterations = n
		}
	}
	if v, ok := cfg["similarity_threshold"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.similarityThreshold = f
		}
	}
	if v, ok := cfg["break_action"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.breakAction = s
		}
	}
	return nil
}

// calculateSimilarity computes Jaccard similarity between two texts.
func calculateSimilarity(a, b string) float64 {
	wordsA := strings.Fields(strings.ToLower(a))
	wordsB := strings.Fields(strings.ToLower(b))

	if len(wordsA) == 0 && len(wordsB) == 0 {
		return 1.0
	}
	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0.0
	}

	setA := make(map[string]bool, len(wordsA))
	for _, w := range wordsA {
		setA[w] = true
	}
	setB := make(map[string]bool, len(wordsB))
	for _, w := range wordsB {
		setB[w] = true
	}

	intersection := 0
	for w := range setA {
		if setB[w] {
			intersection++
		}
	}

	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}
