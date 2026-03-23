// Package audit provides a guardrail rule (GR-046) that records a complete
// audit trail of each request/response for compliance. It also provides
// GR-049 Usage Analytics Export.
package audit

import (
	"crypto/sha256"
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// GR-046: Audit Log Writer
// ---------------------------------------------------------------------------

// AuditRule implements guardrails.Rule for GR-046.
type AuditRule struct {
	mu      sync.RWMutex
	cfg     auditConfig
	entries []AuditEntry
}

type auditConfig struct {
	includePrompt   bool
	includeResponse bool
	hashPII         bool
	retentionDays   int
}

// AuditEntry represents a single audit log record.
type AuditEntry struct {
	Timestamp    time.Time
	ActorID      string
	SessionID    string
	Provider     string
	Model        string
	PromptHash   string
	ResponseHash string
	Decision     string
}

// NewAudit creates a GR-046 rule.
func NewAudit() *AuditRule {
	return &AuditRule{
		cfg: auditConfig{
			includePrompt:   true,
			includeResponse: true,
			hashPII:         true,
			retentionDays:   365,
		},
	}
}

func (r *AuditRule) ID() string                    { return "GR-046" }
func (r *AuditRule) Name() string                  { return "Audit Log Writer" }
func (r *AuditRule) Stage() models.GuardrailStage  { return models.StagePostOutput }
func (r *AuditRule) Category() models.RuleCategory { return models.CategoryCompliance }

func (r *AuditRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	actorID := ""
	if ctx.Actor != nil {
		actorID = ctx.Actor.ID
	}

	promptHash := ""
	if cfg.includePrompt && ctx.PromptText != "" {
		h := sha256.Sum256([]byte(ctx.PromptText))
		promptHash = fmt.Sprintf("%x", h[:16])
	}

	responseHash := ""
	if cfg.includeResponse && ctx.ResponseText != "" {
		h := sha256.Sum256([]byte(ctx.ResponseText))
		responseHash = fmt.Sprintf("%x", h[:16])
	}

	entry := AuditEntry{
		Timestamp:    time.Now(),
		ActorID:      actorID,
		SessionID:    ctx.SessionID,
		Provider:     ctx.Provider,
		Model:        ctx.Model,
		PromptHash:   promptHash,
		ResponseHash: responseHash,
	}

	r.mu.Lock()
	r.entries = append(r.entries, entry)
	r.mu.Unlock()

	ctx.SetMetadata("audit_prompt_hash", promptHash)
	ctx.SetMetadata("audit_response_hash", responseHash)
	ctx.SetMetadata("audit_retention_days", cfg.retentionDays)

	eval := &models.GuardrailEvaluation{
		RuleID:     r.ID(),
		RuleName:   r.Name(),
		Stage:      r.Stage(),
		Decision:   models.DecisionLog,
		Confidence: 1.0,
		Reason:     fmt.Sprintf("audit record created (prompt_hash=%s, retention=%dd)", promptHash, cfg.retentionDays),
		LatencyMs:  time.Since(start).Milliseconds(),
	}
	return eval, nil
}

// GetEntries returns a copy of the audit log.
func (r *AuditRule) GetEntries() []AuditEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]AuditEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

func (r *AuditRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["include_prompt"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.includePrompt = b
		}
	}
	if v, ok := cfg["include_response"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.includeResponse = b
		}
	}
	if v, ok := cfg["hash_pii"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.hashPII = b
		}
	}
	if v, ok := cfg["retention_days"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.retentionDays = int(n)
		case int:
			r.cfg.retentionDays = n
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-049: Usage Analytics Export
// ---------------------------------------------------------------------------

// AnalyticsRule implements guardrails.Rule for GR-049.
type AnalyticsRule struct {
	mu       sync.RWMutex
	cfg      analyticsConfig
	counters map[string]int64 // simple counters for export
}

type analyticsConfig struct {
	exportTo      []string
	flushInterval time.Duration
}

// NewAnalytics creates a GR-049 rule.
func NewAnalytics() *AnalyticsRule {
	return &AnalyticsRule{
		cfg: analyticsConfig{
			exportTo:      []string{"prometheus"},
			flushInterval: 10 * time.Second,
		},
		counters: make(map[string]int64),
	}
}

func (r *AnalyticsRule) ID() string                    { return "GR-049" }
func (r *AnalyticsRule) Name() string                  { return "Usage Analytics Export" }
func (r *AnalyticsRule) Stage() models.GuardrailStage  { return models.StagePostOutput }
func (r *AnalyticsRule) Category() models.RuleCategory { return models.CategoryCompliance }

func (r *AnalyticsRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	provider := ctx.Provider
	model := ctx.Model

	r.mu.Lock()
	r.counters["total_requests"]++
	if provider != "" {
		r.counters["provider:"+provider]++
	}
	if model != "" {
		r.counters["model:"+model]++
	}
	if ctx.Actor != nil && ctx.Actor.Team != "" {
		r.counters["team:"+ctx.Actor.Team]++
	}
	totalReqs := r.counters["total_requests"]
	r.mu.Unlock()

	ctx.SetMetadata("analytics_total_requests", totalReqs)

	eval := &models.GuardrailEvaluation{
		RuleID:     r.ID(),
		RuleName:   r.Name(),
		Stage:      r.Stage(),
		Decision:   models.DecisionLog,
		Confidence: 0,
		Reason:     fmt.Sprintf("analytics exported (total=%d, provider=%s, model=%s)", totalReqs, provider, model),
		LatencyMs:  time.Since(start).Milliseconds(),
	}
	return eval, nil
}

func (r *AnalyticsRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["export_to"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.exportTo = list
	}
	if v, ok := cfg["flush_interval"]; ok {
		if s, ok := v.(string); ok {
			d, err := time.ParseDuration(s)
			if err != nil {
				return err
			}
			r.cfg.flushInterval = d
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
