// Package allowlist provides guardrail rules for provider and model allowlists
// (GR-007 Provider Allowlist, GR-008 Model Allowlist).
package allowlist

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// GR-007: Provider Allowlist
// ---------------------------------------------------------------------------

// ProviderRule enforces provider allow/deny lists.
type ProviderRule struct {
	mu  sync.RWMutex
	cfg providerConfig
}

type providerConfig struct {
	allow []string
	deny  []string
}

// NewProvider creates a new provider allowlist rule.
func NewProvider() *ProviderRule {
	return &ProviderRule{}
}

func (r *ProviderRule) ID() string                    { return "GR-007" }
func (r *ProviderRule) Name() string                  { return "Provider Allowlist" }
func (r *ProviderRule) Stage() models.GuardrailStage  { return models.StagePreInput }
func (r *ProviderRule) Category() models.RuleCategory { return models.CategoryAllowlist }

// Evaluate checks whether the target provider is in the allow/deny lists.
func (r *ProviderRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	provider := strings.ToLower(ctx.Provider)
	if provider == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no provider specified; skipping allowlist check"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Check policy-level allowlists first.
	if ctx.Policy != nil && ctx.Policy.Spec.Providers != nil {
		pp := ctx.Policy.Spec.Providers
		if len(pp.Deny) > 0 && matchesList(provider, pp.Deny) {
			eval.Decision = models.DecisionBlock
			eval.Confidence = 1.0
			eval.Reason = fmt.Sprintf("provider %q is denied by policy", provider)
			eval.Findings = []models.Finding{{
				Type: "denied_provider", Value: provider,
				Severity: "high", Confidence: 1.0,
			}}
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
		if len(pp.Allow) > 0 && !matchesList(provider, pp.Allow) {
			eval.Decision = models.DecisionBlock
			eval.Confidence = 1.0
			eval.Reason = fmt.Sprintf("provider %q is not in the allowed list", provider)
			eval.Findings = []models.Finding{{
				Type: "unlisted_provider", Value: provider,
				Severity: "high", Confidence: 1.0,
			}}
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
	}

	// Check rule-level config.
	if len(cfg.deny) > 0 && matchesList(provider, cfg.deny) {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("provider %q is in the deny list", provider)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}
	if len(cfg.allow) > 0 && !matchesList(provider, cfg.allow) {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("provider %q is not in the allow list", provider)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionAllow
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf("provider %q is allowed", provider)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *ProviderRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["allow"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("provider allowlist: allow: %w", err)
		}
		r.cfg.allow = list
	}
	if v, ok := cfg["deny"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("provider allowlist: deny: %w", err)
		}
		r.cfg.deny = list
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-008: Model Allowlist
// ---------------------------------------------------------------------------

// ModelRule enforces model allow/deny lists.
type ModelRule struct {
	mu  sync.RWMutex
	cfg modelConfig
}

type modelConfig struct {
	allow []string
	deny  []string
}

// NewModel creates a new model allowlist rule.
func NewModel() *ModelRule {
	return &ModelRule{}
}

func (r *ModelRule) ID() string                    { return "GR-008" }
func (r *ModelRule) Name() string                  { return "Model Allowlist" }
func (r *ModelRule) Stage() models.GuardrailStage  { return models.StagePreInput }
func (r *ModelRule) Category() models.RuleCategory { return models.CategoryAllowlist }

// Evaluate checks whether the target model is in the allow/deny lists.
func (r *ModelRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	model := strings.ToLower(ctx.Model)
	if model == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no model specified; skipping allowlist check"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Check policy-level model allowlists.
	if ctx.Policy != nil && ctx.Policy.Spec.Models != nil {
		mp := ctx.Policy.Spec.Models
		if len(mp.Deny) > 0 && matchesList(model, mp.Deny) {
			eval.Decision = models.DecisionBlock
			eval.Confidence = 1.0
			eval.Reason = fmt.Sprintf("model %q is denied by policy", model)
			eval.Findings = []models.Finding{{
				Type: "denied_model", Value: model,
				Severity: "high", Confidence: 1.0,
			}}
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
		if len(mp.Allow) > 0 && !matchesList(model, mp.Allow) {
			eval.Decision = models.DecisionBlock
			eval.Confidence = 1.0
			eval.Reason = fmt.Sprintf("model %q is not in the allowed list", model)
			eval.Findings = []models.Finding{{
				Type: "unlisted_model", Value: model,
				Severity: "high", Confidence: 1.0,
			}}
			eval.LatencyMs = time.Since(start).Milliseconds()
			return eval, nil
		}
	}

	// Check rule-level config.
	if len(cfg.deny) > 0 && matchesList(model, cfg.deny) {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("model %q is in the deny list", model)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}
	if len(cfg.allow) > 0 && !matchesList(model, cfg.allow) {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("model %q is not in the allow list", model)
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionAllow
	eval.Confidence = 0
	eval.Reason = fmt.Sprintf("model %q is allowed", model)
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *ModelRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["allow"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("model allowlist: allow: %w", err)
		}
		r.cfg.allow = list
	}
	if v, ok := cfg["deny"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("model allowlist: deny: %w", err)
		}
		r.cfg.deny = list
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// matchesList checks if the value matches any entry in the list.
// Supports wildcard "*" to match everything.
func matchesList(value string, list []string) bool {
	for _, item := range list {
		lower := strings.ToLower(item)
		if lower == "*" || lower == value {
			return true
		}
		// Simple prefix matching with wildcard suffix.
		if strings.HasSuffix(lower, "*") && strings.HasPrefix(value, strings.TrimSuffix(lower, "*")) {
			return true
		}
	}
	return false
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
