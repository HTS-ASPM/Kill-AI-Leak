// Package license provides a guardrail rule (GR-039) that checks generated
// code for license-encumbered snippets (GPL, AGPL) based on known license
// header patterns and common license indicator phrases.
package license

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// License header patterns.
var licensePatterns = []struct {
	license string
	blocked bool
	re      *regexp.Regexp
}{
	{"GPL-3.0", true, regexp.MustCompile(`(?i)(?:GNU\s+General\s+Public\s+License.*(?:version\s+3|v3)|GPL[- ]?3\.0|GPLv3)`)},
	{"AGPL-3.0", true, regexp.MustCompile(`(?i)(?:GNU\s+Affero\s+General\s+Public\s+License|AGPL[- ]?3\.0|AGPLv3)`)},
	{"GPL-2.0", true, regexp.MustCompile(`(?i)(?:GNU\s+General\s+Public\s+License.*(?:version\s+2|v2)|GPL[- ]?2\.0|GPLv2)`)},
	{"LGPL", false, regexp.MustCompile(`(?i)(?:GNU\s+Lesser\s+General\s+Public|LGPL)`)},
	{"MIT", false, regexp.MustCompile(`(?i)(?:MIT\s+License|Permission\s+is\s+hereby\s+granted,\s+free\s+of\s+charge)`)},
	{"Apache-2.0", false, regexp.MustCompile(`(?i)(?:Apache\s+License,?\s+Version\s+2\.0|Licensed\s+under\s+the\s+Apache)`)},
	{"BSD", false, regexp.MustCompile(`(?i)(?:BSD\s+(?:2|3)[- ]?Clause|Redistribution\s+and\s+use\s+in\s+source\s+and\s+binary)`)},
}

// Copyleft indicator phrases.
var copyleftIndicators = []string{
	"you must distribute", "derivative works", "same license",
	"convey", "copyleft", "source code must be made available",
}

// Fenced code block extraction.
var fencedBlockRe = regexp.MustCompile("(?s)(?:```|~~~)[a-zA-Z0-9_+-]*\\n(.*?)(?:```|~~~)")

// Rule implements guardrails.Rule for GR-039 License Compliance Check.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	blockedLicenses     []string
	similarityThreshold float64
}

// New creates a new license compliance rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			blockedLicenses:     []string{"GPL-3.0", "AGPL-3.0", "GPL-2.0"},
			similarityThreshold: 0.90,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-039" }
func (r *Rule) Name() string                  { return "License Compliance Check" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageOutput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryCompliance }

// Evaluate checks generated code for license-encumbered content.
func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
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

	// Scan the full response (comments and code blocks).
	var findings []models.Finding
	maxConfidence := 0.0
	hasBlockedLicense := false

	blockedSet := make(map[string]bool)
	for _, bl := range cfg.blockedLicenses {
		blockedSet[strings.ToUpper(bl)] = true
	}

	for _, lp := range licensePatterns {
		if lp.re.MatchString(text) {
			isBlocked := blockedSet[strings.ToUpper(lp.license)]
			confidence := 0.85
			sev := "medium"
			if isBlocked {
				confidence = 0.9
				sev = "high"
				hasBlockedLicense = true
			}
			findings = append(findings, models.Finding{
				Type:       "license:" + lp.license,
				Value:      truncate(lp.re.FindString(text), 100),
				Severity:   sev,
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	// Check for copyleft indicator phrases.
	lower := strings.ToLower(text)
	for _, indicator := range copyleftIndicators {
		if strings.Contains(lower, indicator) {
			findings = append(findings, models.Finding{
				Type:       "copyleft_indicator",
				Value:      indicator,
				Severity:   "medium",
				Confidence: 0.6,
			})
			if 0.6 > maxConfidence {
				maxConfidence = 0.6
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if hasBlockedLicense {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("blocked license detected in generated code; %d finding(s)", len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("license indicators found in generated code; %d finding(s)", len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no license compliance issues"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["blocked_licenses"]; ok {
		list, err := parseStringList(v)
		if err != nil {
			return err
		}
		r.cfg.blockedLicenses = list
	}
	if v, ok := cfg["similarity_threshold"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.similarityThreshold = f
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
