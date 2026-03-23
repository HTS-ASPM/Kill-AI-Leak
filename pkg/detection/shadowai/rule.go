// Package shadowai provides a guardrail rule (GR-009) that detects API calls
// from services not enrolled in the gateway inventory (shadow AI usage).
package shadowai

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Rule implements guardrails.Rule for GR-009 Shadow AI Detection.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	enrolledServices map[string]bool
	alertOnUnknown   bool
}

// New creates a new shadow AI detection rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			enrolledServices: make(map[string]bool),
			alertOnUnknown:   true,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-009" }
func (r *Rule) Name() string                  { return "Shadow AI Detection" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StagePreInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryShadowAI }

// Evaluate checks whether the requesting actor/service is enrolled in the
// gateway inventory. Unknown services are flagged as potential shadow AI.
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

	actorID := ""
	actorName := ""
	if ctx.Actor != nil {
		actorID = ctx.Actor.ID
		actorName = ctx.Actor.Name
	}

	if actorID == "" {
		// No actor identity at all is suspicious.
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.9
		eval.Reason = "request has no actor identity; potential shadow AI usage"
		eval.Findings = []models.Finding{{
			Type: "no_actor_identity", Severity: "high", Confidence: 0.9,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Check if the service is in the enrolled set.
	enrolled := cfg.enrolledServices[strings.ToLower(actorID)]
	if !enrolled && actorName != "" {
		enrolled = cfg.enrolledServices[strings.ToLower(actorName)]
	}

	if !enrolled && cfg.alertOnUnknown {
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.8
		eval.Reason = fmt.Sprintf("service %q (%s) is not enrolled in the gateway inventory", actorName, actorID)
		eval.Findings = []models.Finding{{
			Type:       "unenrolled_service",
			Value:      fmt.Sprintf("%s (%s)", actorName, actorID),
			Severity:   "medium",
			Confidence: 0.8,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionAllow
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf("service %q is enrolled", actorID)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
// Supported keys:
//   - "enrolled_services" ([]string): list of enrolled service IDs/names
//   - "alert_on_unknown" (bool): raise alerts for unknown services
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if v, ok := cfg["enrolled_services"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("shadowai: enrolled_services: %w", err)
		}
		m := make(map[string]bool, len(list))
		for _, s := range list {
			m[strings.ToLower(s)] = true
		}
		r.cfg.enrolledServices = m
	}
	if v, ok := cfg["alert_on_unknown_service"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.alertOnUnknown = b
		}
	}
	return nil
}

func parseStringList(v any) ([]string, error) {
	switch vv := v.(type) {
	case []string:
		return vv, nil
	case []any:
		out := make([]string, 0, len(vv))
		for _, item := range vv {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("expected string in list, got %T", item)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("expected []string, got %T", v)
	}
}
