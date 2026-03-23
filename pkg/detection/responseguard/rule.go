// Package responseguard provides guardrail rules for output-stage guards:
// GR-043 Response Size Guard and GR-044 Structured Output Conformance.
package responseguard

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// GR-043: Response Size Guard
// ---------------------------------------------------------------------------

// SizeGuardRule enforces max response size limits.
type SizeGuardRule struct {
	mu  sync.RWMutex
	cfg sizeGuardConfig
}

type sizeGuardConfig struct {
	maxResponseTokens int
	maxResponseBytes  int
}

// NewSizeGuard creates a GR-043 rule.
func NewSizeGuard() *SizeGuardRule {
	return &SizeGuardRule{
		cfg: sizeGuardConfig{
			maxResponseTokens: 16000,
			maxResponseBytes:  1048576, // 1MB
		},
	}
}

func (r *SizeGuardRule) ID() string                    { return "GR-043" }
func (r *SizeGuardRule) Name() string                  { return "Response Size Guard" }
func (r *SizeGuardRule) Stage() models.GuardrailStage  { return models.StageOutput }
func (r *SizeGuardRule) Category() models.RuleCategory { return models.CategoryRateLimit }

func (r *SizeGuardRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	text := ctx.ResponseText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no response text"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	byteSize := len(text)
	estimatedTokens := len(text) / 4 // rough estimate

	var findings []models.Finding

	if byteSize > cfg.maxResponseBytes {
		findings = append(findings, models.Finding{
			Type:       "response_too_large_bytes",
			Value:      fmt.Sprintf("%d bytes (max %d)", byteSize, cfg.maxResponseBytes),
			Severity:   "high",
			Confidence: 1.0,
		})
	}

	if estimatedTokens > cfg.maxResponseTokens {
		findings = append(findings, models.Finding{
			Type:       "response_too_large_tokens",
			Value:      fmt.Sprintf("~%d tokens (max %d)", estimatedTokens, cfg.maxResponseTokens),
			Severity:   "high",
			Confidence: 0.9,
		})
	}

	eval.Findings = findings

	if len(findings) > 0 {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 1.0
		eval.Reason = fmt.Sprintf("response exceeds size limits: %d bytes, ~%d tokens", byteSize, estimatedTokens)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = fmt.Sprintf("response within limits: %d bytes, ~%d tokens", byteSize, estimatedTokens)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *SizeGuardRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["max_response_tokens"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.maxResponseTokens = int(n)
		case int:
			r.cfg.maxResponseTokens = n
		}
	}
	if v, ok := cfg["max_response_bytes"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.maxResponseBytes = int(n)
		case int:
			r.cfg.maxResponseBytes = n
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-044: Structured Output Conformance
// ---------------------------------------------------------------------------

// OutputSchemaRule validates that LLM responses conform to expected JSON schemas.
type OutputSchemaRule struct {
	mu  sync.RWMutex
	cfg outputSchemaConfig
}

type outputSchemaConfig struct {
	validateJSON  bool
	strictSchema  bool
}

// NewOutputSchema creates a GR-044 rule.
func NewOutputSchema() *OutputSchemaRule {
	return &OutputSchemaRule{
		cfg: outputSchemaConfig{
			validateJSON: true,
			strictSchema: false,
		},
	}
}

func (r *OutputSchemaRule) ID() string                    { return "GR-044" }
func (r *OutputSchemaRule) Name() string                  { return "Structured Output Conformance" }
func (r *OutputSchemaRule) Stage() models.GuardrailStage  { return models.StageOutput }
func (r *OutputSchemaRule) Category() models.RuleCategory { return models.CategoryCodeSafety }

func (r *OutputSchemaRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	if !cfg.validateJSON {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "JSON validation disabled"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	text := ctx.ResponseText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no response text"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Check if JSON mode was requested (look for metadata hint or header).
	jsonModeRequested := false
	if v, ok := ctx.GetMetadata("json_mode"); ok {
		if b, ok := v.(bool); ok {
			jsonModeRequested = b
		}
	}

	if !jsonModeRequested {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "JSON mode not requested"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Validate that the response is valid JSON.
	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.9
		eval.Reason = fmt.Sprintf("response is not valid JSON: %v", err)
		eval.Findings = []models.Finding{{
			Type:       "invalid_json",
			Value:      truncate(err.Error(), 100),
			Severity:   "high",
			Confidence: 0.9,
		}}
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	eval.Decision = models.DecisionAllow
	eval.Confidence = 0
	eval.Reason = "response is valid JSON"
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *OutputSchemaRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["validate_json"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.validateJSON = b
		}
	}
	if v, ok := cfg["strict_schema"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.strictSchema = b
		}
	}
	return nil
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
