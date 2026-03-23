// Package brand provides a guardrail rule that detects brand safety issues
// in LLM responses, including competitor mentions, legal claims, and
// inappropriate pricing references.
package brand

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Built-in legal claim patterns that could create liability.
var legalClaimPatterns = []struct {
	label  string
	weight float64
	re     *regexp.Regexp
}{
	{"guarantee", 0.80, regexp.MustCompile(`(?i)\bwe\s+guarantee\b`)},
	{"promise", 0.75, regexp.MustCompile(`(?i)\bwe\s+promise\b`)},
	{"entitled_to", 0.85, regexp.MustCompile(`(?i)\byou\s+are\s+entitled\s+to\b`)},
	{"legal_advice", 0.90, regexp.MustCompile(`(?i)\bthis\s+constitutes?\s+(?:legal|medical)\s+advice\b`)},
	{"warranty", 0.70, regexp.MustCompile(`(?i)\bwe\s+warrant(?:y|ee)?\b`)},
	{"liability_accept", 0.80, regexp.MustCompile(`(?i)\bwe\s+(?:accept|assume)\s+(?:full\s+)?liability\b`)},
	{"no_risk", 0.65, regexp.MustCompile(`(?i)\b(?:risk[- ]free|no\s+risk|zero\s+risk)\b`)},
	{"money_back", 0.60, regexp.MustCompile(`(?i)\bmoney[- ]back\s+guarantee\b`)},
	{"certified", 0.50, regexp.MustCompile(`(?i)\bwe\s+are\s+(?:certified|licensed|authorized)\b`)},
}

// Pricing mention patterns.
var pricingPatterns = []struct {
	label string
	re    *regexp.Regexp
}{
	{"product_costs", regexp.MustCompile(`(?i)\b(?:our\s+(?:product|service|plan|package))\s+(?:costs?|is\s+priced\s+at|starts?\s+at)\s+\$[\d,]+`)},
	{"dollar_amount", regexp.MustCompile(`(?i)\b(?:only|just|for)\s+\$[\d,]+(?:\.\d{2})?\s+(?:per|a|each)\b`)},
	{"pricing_tier", regexp.MustCompile(`(?i)\b(?:basic|pro|enterprise|premium)\s+(?:plan|tier)\s+(?:is|costs?|at)\s+\$[\d,]+`)},
}

// Detector implements guardrails.Rule for GR-035 Brand Safety.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	competitorNames []string
	legalPhrases    []string
	requiredTone    string
}

// New creates a new brand safety detector with empty defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-035" }
func (d *Detector) Name() string                  { return "Brand Safety" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageOutput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryBrandSafety }

// Evaluate checks the LLM response for brand safety issues. Returns
// DecisionAlert (not block) for brand safety violations.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	eval := &models.GuardrailEvaluation{
		RuleID:   d.ID(),
		RuleName: d.Name(),
		Stage:    d.Stage(),
	}

	text := ctx.ResponseText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "no response text to scan"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	var findings []models.Finding
	maxConfidence := 0.0

	lower := strings.ToLower(text)

	// --- Check for competitor recommendations ---
	for _, competitor := range cfg.competitorNames {
		compLower := strings.ToLower(competitor)
		if compLower == "" {
			continue
		}
		// Check if the competitor is mentioned in a recommending context.
		if strings.Contains(lower, compLower) {
			// Look for recommendation patterns near the competitor mention.
			recommendPatterns := []string{
				"recommend " + compLower,
				"try " + compLower,
				"use " + compLower,
				"switch to " + compLower,
				"consider " + compLower,
				compLower + " is better",
				compLower + " offers",
				"suggest " + compLower,
			}
			for _, rp := range recommendPatterns {
				if strings.Contains(lower, rp) {
					confidence := 0.85
					findings = append(findings, models.Finding{
						Type:       "competitor_recommendation",
						Value:      competitor,
						Severity:   "high",
						Confidence: confidence,
					})
					if confidence > maxConfidence {
						maxConfidence = confidence
					}
					break
				}
			}

			// Even a plain mention is noteworthy.
			if len(findings) == 0 || findings[len(findings)-1].Type != "competitor_recommendation" || findings[len(findings)-1].Value != competitor {
				findings = append(findings, models.Finding{
					Type:       "competitor_mention",
					Value:      competitor,
					Severity:   "medium",
					Confidence: 0.5,
				})
				if 0.5 > maxConfidence {
					maxConfidence = 0.5
				}
			}
		}
	}

	// --- Check for legal claims ---
	for _, lp := range legalClaimPatterns {
		matches := lp.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "legal_claim:" + lp.label,
				Value:      truncate(text[loc[0]:loc[1]], 100),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   "high",
				Confidence: lp.weight,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if lp.weight > maxConfidence {
				maxConfidence = lp.weight
			}
		}
	}

	// Check custom legal phrases.
	for _, phrase := range cfg.legalPhrases {
		if phrase == "" {
			continue
		}
		phraseLower := strings.ToLower(phrase)
		if strings.Contains(lower, phraseLower) {
			findings = append(findings, models.Finding{
				Type:       "custom_legal_phrase",
				Value:      phrase,
				Severity:   "high",
				Confidence: 0.80,
			})
			if 0.80 > maxConfidence {
				maxConfidence = 0.80
			}
		}
	}

	// --- Check for pricing mentions ---
	for _, pp := range pricingPatterns {
		matches := pp.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "pricing_mention:" + pp.label,
				Value:      truncate(text[loc[0]:loc[1]], 100),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   "medium",
				Confidence: 0.65,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if 0.65 > maxConfidence {
				maxConfidence = 0.65
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if len(findings) > 0 {
		// Brand safety issues produce alerts, not blocks.
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("brand safety issue(s) detected (confidence=%.2f); %d finding(s)",
			maxConfidence, len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "no brand safety issues detected"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "competitor_names" ([]string): list of competitor names to watch for
//   - "legal_phrases" ([]string): custom legal phrases to flag
//   - "required_tone" (string): expected tone of responses
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["competitor_names"]; ok {
		names, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("brand: competitor_names: %w", err)
		}
		d.cfg.competitorNames = names
	}

	if v, ok := cfg["legal_phrases"]; ok {
		phrases, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("brand: legal_phrases: %w", err)
		}
		d.cfg.legalPhrases = phrases
	}

	if v, ok := cfg["required_tone"]; ok {
		if s, ok := v.(string); ok {
			d.cfg.requiredTone = s
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
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
