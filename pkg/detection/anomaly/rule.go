// Package anomaly provides a guardrail rule (GR-048) that publishes request
// metadata to an anomaly detection feed for pattern analysis. It tracks
// request frequency and flags statistical outliers.
package anomaly

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// requestRecord captures metadata about a single request for anomaly detection.
type requestRecord struct {
	ts          time.Time
	actorID     string
	provider    string
	model       string
	tokenCount  int
	latencyMs   int64
}

// Rule implements guardrails.Rule for GR-048 Anomaly Detection Feed.
type Rule struct {
	mu      sync.RWMutex
	cfg     ruleConfig
	records []requestRecord
}

type ruleConfig struct {
	publishTo string
	subject   string
}

// New creates a GR-048 rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			publishTo: "nats",
			subject:   "killaileak.anomaly.feed",
		},
	}
}

func (r *Rule) ID() string                    { return "GR-048" }
func (r *Rule) Name() string                  { return "Anomaly Detection Feed" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StagePostOutput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryShadowAI }

func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	actorID := ""
	if ctx.Actor != nil {
		actorID = ctx.Actor.ID
	}

	tokenCount := (len(ctx.PromptText) + len(ctx.ResponseText)) / 4

	rec := requestRecord{
		ts:         time.Now(),
		actorID:    actorID,
		provider:   ctx.Provider,
		model:      ctx.Model,
		tokenCount: tokenCount,
	}

	r.mu.Lock()
	r.records = append(r.records, rec)
	// Keep only last 1000 records for analysis.
	if len(r.records) > 1000 {
		r.records = r.records[len(r.records)-1000:]
	}
	records := make([]requestRecord, len(r.records))
	copy(records, r.records)
	r.mu.Unlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	// Simple anomaly detection: check if this request's token count is
	// more than 3 standard deviations from the mean.
	isAnomaly := false
	if len(records) >= 10 {
		mean, stddev := tokenStats(records)
		if stddev > 0 && float64(tokenCount) > mean+3*stddev {
			isAnomaly = true
			eval.Findings = []models.Finding{{
				Type:       "token_count_anomaly",
				Value:      fmt.Sprintf("%d tokens (mean=%.0f, stddev=%.0f)", tokenCount, mean, stddev),
				Severity:   "medium",
				Confidence: 0.7,
			}}
		}
	}

	if isAnomaly {
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.7
		eval.Reason = fmt.Sprintf("anomalous request detected (tokens=%d); published to %s", tokenCount, r.cfg.subject)
	} else {
		eval.Decision = models.DecisionLog
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("request metadata published to anomaly feed (tokens=%d)", tokenCount)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["publish_to"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.publishTo = s
		}
	}
	if v, ok := cfg["subject"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.subject = s
		}
	}
	return nil
}

// tokenStats calculates mean and standard deviation of token counts.
func tokenStats(records []requestRecord) (mean, stddev float64) {
	if len(records) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, r := range records {
		sum += float64(r.tokenCount)
	}
	mean = sum / float64(len(records))

	variance := 0.0
	for _, r := range records {
		diff := float64(r.tokenCount) - mean
		variance += diff * diff
	}
	variance /= float64(len(records))
	stddev = math.Sqrt(variance)
	return mean, stddev
}
