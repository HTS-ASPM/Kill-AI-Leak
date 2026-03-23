// Package topicallow provides a guardrail rule (GR-016) that enforces a topic
// allowlist -- in restrictive environments only prompts matching approved
// topics are permitted.
package topicallow

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// topicKeywords maps topic labels to representative keywords.
var topicKeywords = map[string][]string{
	"customer_support": {"support", "help", "ticket", "refund", "order", "account", "billing"},
	"engineering":      {"code", "deploy", "api", "server", "debug", "architecture", "database"},
	"marketing":        {"campaign", "seo", "brand", "content", "analytics", "advertising"},
	"legal":            {"contract", "compliance", "regulation", "agreement", "lawsuit", "liability"},
	"hr":               {"hiring", "interview", "employee", "onboarding", "salary", "performance"},
	"finance":          {"revenue", "expense", "budget", "forecast", "accounting", "invoice"},
	"product":          {"feature", "roadmap", "ux", "design", "user", "specification", "mvp"},
	"research":         {"study", "analysis", "experiment", "hypothesis", "data", "findings"},
	"sales":            {"lead", "prospect", "deal", "pipeline", "quota", "crm", "negotiation"},
	"security":         {"vulnerability", "patch", "audit", "penetration", "firewall", "encryption"},
}

// Rule implements guardrails.Rule for GR-016 Topic Allowlist.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	allowedTopics []string
	threshold     float64
}

// New creates a new topic allowlist rule (disabled by default since the
// allowed_topics list starts empty).
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			threshold: 0.3,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-016" }
func (r *Rule) Name() string                  { return "Topic Allowlist" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryBrandSafety }

// Evaluate checks whether the prompt relates to an allowed topic. If no topics
// are configured, it allows everything (the rule is effectively off).
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

	if len(cfg.allowedTopics) == 0 {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no topic allowlist configured; all topics allowed"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	text := strings.ToLower(ctx.PromptText)
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no prompt text to check"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Score the prompt against each allowed topic.
	bestTopic := ""
	bestScore := 0.0

	for _, topic := range cfg.allowedTopics {
		keywords, ok := topicKeywords[strings.ToLower(topic)]
		if !ok {
			// If the topic itself appears as a keyword in the prompt,
			// treat it as a match.
			if strings.Contains(text, strings.ToLower(topic)) {
				bestTopic = topic
				bestScore = 0.6
			}
			continue
		}
		hits := 0
		for _, kw := range keywords {
			if strings.Contains(text, kw) {
				hits++
			}
		}
		score := float64(hits) / float64(len(keywords))
		if score > bestScore {
			bestScore = score
			bestTopic = topic
		}
	}

	if bestScore >= cfg.threshold {
		eval.Decision = models.DecisionAllow
		eval.Confidence = bestScore
		eval.Reason = fmt.Sprintf("prompt matches allowed topic %q (score=%.2f)", bestTopic, bestScore)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionBlock
	eval.Confidence = 1.0 - bestScore
	eval.Reason = fmt.Sprintf("prompt does not match any allowed topic (best match: %q at %.2f, threshold: %.2f)",
		bestTopic, bestScore, cfg.threshold)
	eval.Findings = []models.Finding{{
		Type: "off_topic", Severity: "medium",
		Confidence: 1.0 - bestScore,
		Value:      fmt.Sprintf("best_match=%s score=%.2f", bestTopic, bestScore),
	}}
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["allowed_topics"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("topicallow: allowed_topics: %w", err)
		}
		r.cfg.allowedTopics = list
	}
	if v, ok := cfg["threshold"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.threshold = f
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
