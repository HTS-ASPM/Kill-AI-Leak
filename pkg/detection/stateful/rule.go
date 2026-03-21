// Package stateful provides a guardrail rule that wraps the multi-turn
// SessionTracker. It detects gradual escalation, topic drift, payload
// splitting, and boundary probing across conversation turns.
package stateful

import (
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/stateful"
)

// Rule is a guardrail rule that performs multi-turn escalation detection
// by delegating to a SessionTracker and its analysis suite.
type Rule struct {
	mu      sync.RWMutex
	tracker *stateful.SessionTracker
	cfg     ruleConfig
}

type ruleConfig struct {
	// blockThreshold is the escalation score above which the request is
	// blocked. Default: 0.7
	blockThreshold float64

	// alertThreshold is the escalation score above which an alert is
	// raised (but the request is still allowed). Default: 0.4
	alertThreshold float64
}

// New creates a new multi-turn escalation Rule backed by the given
// SessionTracker.
func New(tracker *stateful.SessionTracker) *Rule {
	return &Rule{
		tracker: tracker,
		cfg: ruleConfig{
			blockThreshold: 0.7,
			alertThreshold: 0.4,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (r *Rule) ID() string                    { return "GR-015" }
func (r *Rule) Name() string                  { return "Multi-Turn Escalation" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryInjection }

// Evaluate tracks the current turn and analyses the session for escalation
// patterns. If no SessionID is present on the context, the rule allows the
// request without analysis.
func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	sessionID := ctx.SessionID

	// No session -- nothing to track.
	if sessionID == "" {
		return &models.GuardrailEvaluation{
			RuleID:     r.ID(),
			RuleName:   r.Name(),
			Stage:      r.Stage(),
			Decision:   models.DecisionAllow,
			Confidence: 0,
			Reason:     "no session ID; multi-turn analysis skipped",
			LatencyMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	// Track the current user turn.
	turn := stateful.Turn{
		Role:    stateful.RoleUser,
		Content: ctx.PromptText,
	}
	if _, err := r.tracker.TrackTurn(sessionID, turn); err != nil {
		return nil, fmt.Errorf("stateful rule: track turn: %w", err)
	}

	// Analyse the full session.
	analysis, err := r.tracker.AnalyzeSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("stateful rule: analyze session: %w", err)
	}

	// Convert analysis findings to models.Finding.
	findings := make([]models.Finding, 0, len(analysis.Findings))
	for _, af := range analysis.Findings {
		findings = append(findings, models.Finding{
			Type:       af.Check,
			Value:      af.Description,
			Severity:   af.Severity,
			Confidence: af.Score,
		})
	}

	score := analysis.EscalationScore

	eval := &models.GuardrailEvaluation{
		RuleID:     r.ID(),
		RuleName:   r.Name(),
		Stage:      r.Stage(),
		Confidence: score,
		Findings:   findings,
		LatencyMs:  time.Since(start).Milliseconds(),
	}

	switch {
	case score >= cfg.blockThreshold:
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf(
			"multi-turn escalation detected (score=%.2f, threshold=%.2f); "+
				"topic_drift=%.2f, payload_split=%v, boundary_probe=%v",
			score, cfg.blockThreshold,
			analysis.TopicDriftScore,
			analysis.PayloadSplitDetected,
			analysis.BoundaryProbeDetected,
		)
	case score >= cfg.alertThreshold:
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf(
			"possible multi-turn escalation (score=%.2f, threshold=%.2f); "+
				"topic_drift=%.2f, payload_split=%v, boundary_probe=%v",
			score, cfg.alertThreshold,
			analysis.TopicDriftScore,
			analysis.PayloadSplitDetected,
			analysis.BoundaryProbeDetected,
		)
	default:
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no escalation detected (score=%.2f)", score)
	}

	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "block_threshold" (float64): escalation score above which to block [0,1].
//   - "alert_threshold" (float64): escalation score above which to alert [0,1].
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v, ok := cfg["block_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("stateful: block_threshold must be between 0 and 1")
			}
			r.cfg.blockThreshold = f
		}
	}
	if v, ok := cfg["alert_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("stateful: alert_threshold must be between 0 and 1")
			}
			r.cfg.alertThreshold = f
		}
	}

	if r.cfg.alertThreshold > r.cfg.blockThreshold {
		return fmt.Errorf("stateful: alert_threshold (%.2f) must not exceed block_threshold (%.2f)",
			r.cfg.alertThreshold, r.cfg.blockThreshold)
	}

	return nil
}
