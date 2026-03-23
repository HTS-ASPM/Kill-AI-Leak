// Package compliance provides guardrail rules for compliance metadata tagging
// (GR-022) and model version pinning (GR-033).
package compliance

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// GR-022: Compliance Metadata Tagging
// ---------------------------------------------------------------------------

// Classification keyword heuristics.
var classificationKeywords = map[string][]string{
	"restricted":   {"top secret", "classified", "restricted access", "eyes only", "need to know"},
	"confidential": {"confidential", "internal only", "not for distribution", "private", "ssn", "social security", "credit card", "bank account"},
	"internal":     {"internal", "proprietary", "company use", "staff only", "employee"},
	"public":       {"public", "open source", "published", "press release"},
}

// ComplianceTagRule implements guardrails.Rule for GR-022 Compliance Metadata Tagging.
type ComplianceTagRule struct {
	mu  sync.RWMutex
	cfg complianceTagConfig
}

type complianceTagConfig struct {
	autoClassify         bool
	classificationLevels []string
}

// NewComplianceTag creates a new compliance metadata tagging rule.
func NewComplianceTag() *ComplianceTagRule {
	return &ComplianceTagRule{
		cfg: complianceTagConfig{
			autoClassify:         true,
			classificationLevels: []string{"public", "internal", "confidential", "restricted"},
		},
	}
}

func (r *ComplianceTagRule) ID() string                    { return "GR-022" }
func (r *ComplianceTagRule) Name() string                  { return "Compliance Metadata Tagging" }
func (r *ComplianceTagRule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *ComplianceTagRule) Category() models.RuleCategory { return models.CategoryCompliance }

// Evaluate classifies the request content and tags it with compliance metadata.
func (r *ComplianceTagRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	if !cfg.autoClassify {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "auto-classification disabled"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	text := strings.ToLower(ctx.PromptText)
	classification := "public" // default
	maxHits := 0

	// Scan from most restrictive to least restrictive.
	levels := []string{"restricted", "confidential", "internal", "public"}
	for _, level := range levels {
		keywords, ok := classificationKeywords[level]
		if !ok {
			continue
		}
		hits := 0
		for _, kw := range keywords {
			if strings.Contains(text, kw) {
				hits++
			}
		}
		if hits > maxHits {
			maxHits = hits
			classification = level
		}
	}

	// Tag the context metadata with classification.
	ctx.SetMetadata("data_classification", classification)
	ctx.SetMetadata("compliance_tagged", true)

	eval.Decision = models.DecisionLog
	eval.Confidence = float64(maxHits) / 5.0
	if eval.Confidence > 1.0 {
		eval.Confidence = 1.0
	}
	eval.Reason = fmt.Sprintf("classified as %q (keyword hits: %d)", classification, maxHits)
	eval.Findings = []models.Finding{{
		Type:       "classification",
		Value:      classification,
		Severity:   "info",
		Confidence: eval.Confidence,
	}}
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *ComplianceTagRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["auto_classify"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.autoClassify = b
		}
	}
	if v, ok := cfg["classification_levels"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("compliance: classification_levels: %w", err)
		}
		r.cfg.classificationLevels = list
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-033: Model Version Pinning
// ---------------------------------------------------------------------------

// Floating model aliases that should be pinned.
var floatingAliasRe = regexp.MustCompile(`(?i)^(?:gpt-4o|gpt-4|gpt-3\.5-turbo|claude-3|claude-sonnet|claude-opus|gemini-pro|gemini-1\.5)$`)

// ModelPinRule implements guardrails.Rule for GR-033 Model Version Pinning.
type ModelPinRule struct {
	mu  sync.RWMutex
	cfg modelPinConfig
}

type modelPinConfig struct {
	requirePinnedVersion bool
	warnOnFloating       bool
}

// NewModelPin creates a new model version pinning rule.
func NewModelPin() *ModelPinRule {
	return &ModelPinRule{
		cfg: modelPinConfig{
			requirePinnedVersion: false,
			warnOnFloating:       true,
		},
	}
}

func (r *ModelPinRule) ID() string                    { return "GR-033" }
func (r *ModelPinRule) Name() string                  { return "Model Version Pinning" }
func (r *ModelPinRule) Stage() models.GuardrailStage  { return models.StageRouting }
func (r *ModelPinRule) Category() models.RuleCategory { return models.CategoryCompliance }

// Evaluate checks if the target model uses a floating alias instead of a pinned version.
func (r *ModelPinRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	model := ctx.Model
	if model == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no model specified"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	isFloating := floatingAliasRe.MatchString(model)

	if isFloating {
		if cfg.requirePinnedVersion {
			eval.Decision = models.DecisionBlock
			eval.Confidence = 1.0
			eval.Reason = fmt.Sprintf("model %q is a floating alias; pinned version required", model)
		} else if cfg.warnOnFloating {
			eval.Decision = models.DecisionAlert
			eval.Confidence = 0.6
			eval.Reason = fmt.Sprintf("model %q is a floating alias; consider pinning to a specific version", model)
		} else {
			eval.Decision = models.DecisionAllow
			eval.Confidence = 0
			eval.Reason = fmt.Sprintf("model %q is floating but warnings are disabled", model)
		}
		eval.Findings = []models.Finding{{
			Type: "floating_model_alias", Value: model,
			Severity: "medium", Confidence: 0.8,
		}}
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("model %q appears to be a pinned version", model)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *ModelPinRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["require_pinned_version"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.requirePinnedVersion = b
		}
	}
	if v, ok := cfg["warn_on_floating"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.warnOnFloating = b
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
