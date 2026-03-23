// Package schemaval provides a guardrail rule (GR-024) that validates
// structured output schemas and function calling definitions for injection
// payloads hidden in schema definitions.
package schemaval

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Suspicious patterns in JSON schema definitions.
var (
	// schemaInjectionRe detects injection payloads hidden in schema descriptions or enums.
	schemaInjectionRe = regexp.MustCompile(`(?i)(?:ignore\s+(?:previous|above)|system\s*prompt|you\s+are\s+now|new\s+instructions?|forget\s+everything|admin\s+mode|override|<script|javascript:)`)

	// functionNameRe detects suspicious function names.
	dangerousFuncNames = regexp.MustCompile(`(?i)^(?:exec|eval|system|shell|rm|sudo|admin|hack|exploit|override)`)

	// Detects JSON blocks in the prompt.
	jsonBlockRe = regexp.MustCompile(`(?s)\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}`)
)

// Rule implements guardrails.Rule for GR-024 Structured Output Validation.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	validateJSONSchemas bool
	validateFuncDefs    bool
}

// New creates a new structured output validation rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			validateJSONSchemas: true,
			validateFuncDefs:    true,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-024" }
func (r *Rule) Name() string                  { return "Structured Output Validation" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryInjection }

// Evaluate scans JSON schemas and function definitions in the prompt for
// hidden injection payloads.
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

	text := ctx.PromptText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no prompt text"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	maxConfidence := 0.0

	// Extract JSON blocks from the prompt.
	jsonBlocks := jsonBlockRe.FindAllString(text, 20)

	for _, block := range jsonBlocks {
		// Try to parse as JSON.
		var parsed map[string]any
		if err := json.Unmarshal([]byte(block), &parsed); err != nil {
			continue
		}

		// Recursively scan all string values for injection patterns.
		injectionFindings := scanMapForInjection(parsed, cfg)
		findings = append(findings, injectionFindings...)
		for _, f := range injectionFindings {
			if f.Confidence > maxConfidence {
				maxConfidence = f.Confidence
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if maxConfidence >= 0.8 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("injection payload detected in schema definition (confidence=%.2f); %d finding(s)",
			maxConfidence, len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("suspicious content in schema (confidence=%.2f); %d finding(s)",
			maxConfidence, len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no injection payloads found in schema definitions"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// scanMapForInjection recursively scans a JSON map for injection patterns.
func scanMapForInjection(m map[string]any, cfg ruleConfig) []models.Finding {
	var findings []models.Finding

	for key, val := range m {
		switch v := val.(type) {
		case string:
			// Check for injection patterns in string values.
			if schemaInjectionRe.MatchString(v) {
				findings = append(findings, models.Finding{
					Type:       "schema_injection",
					Value:      truncate(v, 100),
					Location:   fmt.Sprintf("key=%q", key),
					Severity:   "high",
					Confidence: 0.85,
				})
			}
			// Check for dangerous function names.
			if cfg.validateFuncDefs && (key == "name" || key == "function") {
				if dangerousFuncNames.MatchString(v) {
					findings = append(findings, models.Finding{
						Type:       "dangerous_function_name",
						Value:      v,
						Location:   fmt.Sprintf("key=%q", key),
						Severity:   "high",
						Confidence: 0.8,
					})
				}
			}
		case map[string]any:
			findings = append(findings, scanMapForInjection(v, cfg)...)
		case []any:
			for _, item := range v {
				if itemStr, ok := item.(string); ok {
					if schemaInjectionRe.MatchString(itemStr) {
						findings = append(findings, models.Finding{
							Type:       "schema_injection_in_array",
							Value:      truncate(itemStr, 100),
							Location:   fmt.Sprintf("key=%q", key),
							Severity:   "high",
							Confidence: 0.85,
						})
					}
				}
				if itemMap, ok := item.(map[string]any); ok {
					findings = append(findings, scanMapForInjection(itemMap, cfg)...)
				}
			}
		}
	}
	return findings
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["validate_json_schemas"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.validateJSONSchemas = b
		}
	}
	if v, ok := cfg["validate_function_defs"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.validateFuncDefs = b
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

