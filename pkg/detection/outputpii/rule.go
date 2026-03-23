// Package outputpii provides a guardrail rule (GR-035) that scans LLM
// responses for PII leakage, especially novel PII not present in the input
// (potential training data memorization).
package outputpii

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// PII detection patterns for output scanning.
var piiPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"email", regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	{"phone", regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`)},
	{"ssn", regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)},
	{"credit_card", regexp.MustCompile(`\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b`)},
	{"ip_address", regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)},
}

// Rule implements guardrails.Rule for GR-035 Output PII Leakage Detection.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	crossReferenceInput bool
	blockNovelPII       bool
}

// New creates a new output PII leakage detection rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			crossReferenceInput: true,
			blockNovelPII:       true,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-035" }
func (r *Rule) Name() string                  { return "Output PII Leakage Detection" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageOutput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryPII }

// Evaluate scans the LLM response for PII, flagging novel PII not present
// in the input as potential training data memorization.
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

	text := ctx.ResponseText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no response text to scan"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	maxConfidence := 0.0
	hasNovelPII := false

	inputText := ctx.PromptText

	for _, pat := range piiPatterns {
		matches := pat.re.FindAllString(text, 20)
		for _, match := range matches {
			isNovel := !cfg.crossReferenceInput || !strings.Contains(inputText, match)
			confidence := 0.7
			if isNovel {
				confidence = 0.9
				hasNovelPII = true
			}

			findings = append(findings, models.Finding{
				Type:       "output_pii:" + pat.label,
				Value:      maskValue(match),
				Severity:   severityForPII(pat.label, isNovel),
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if hasNovelPII && cfg.blockNovelPII {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("novel PII detected in response (not from input); %d finding(s)", len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("PII detected in response; %d finding(s) (confidence=%.2f)", len(findings), maxConfidence)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no PII detected in response"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["cross_reference_input"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.crossReferenceInput = b
		}
	}
	if v, ok := cfg["block_novel_pii"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.blockNovelPII = b
		}
	}
	return nil
}

func maskValue(s string) string {
	runes := []rune(s)
	if len(runes) <= 6 {
		return "***"
	}
	return string(runes[:3]) + "***" + string(runes[len(runes)-3:])
}

func severityForPII(piiType string, isNovel bool) string {
	if isNovel {
		return "critical"
	}
	switch piiType {
	case "ssn", "credit_card":
		return "high"
	default:
		return "medium"
	}
}
