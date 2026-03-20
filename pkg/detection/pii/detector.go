// Package pii provides a guardrail rule that detects personally identifiable
// information and sensitive credentials in prompt text using compiled regular
// expressions. Each PII type carries a severity that drives the decision
// (block, anonymize, or alert).
package pii

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
// PII pattern definitions
// ---------------------------------------------------------------------------

// piiPattern bundles a compiled regex with metadata about the PII type it
// detects. Patterns are compiled exactly once during init.
type piiPattern struct {
	piiType  models.PIIType
	label    string
	severity models.PIISeverity
	re       *regexp.Regexp
}

var (
	patterns     []piiPattern
	patternsOnce sync.Once
)

// initPatterns compiles all regular expressions once. Called via sync.Once
// from Evaluate to guarantee thread safety without using package-level init.
func initPatterns() {
	patternsOnce.Do(func() {
		patterns = []piiPattern{
			// Emails
			{
				piiType:  models.PIIEmail,
				label:    "email",
				severity: models.PIISeverityMedium,
				re:       regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`),
			},
			// US/international phone numbers
			{
				piiType:  models.PIIPhone,
				label:    "phone",
				severity: models.PIISeverityMedium,
				re:       regexp.MustCompile(`(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}`),
			},
			// US Social Security Numbers
			{
				piiType:  models.PIISSN,
				label:    "ssn",
				severity: models.PIISeverityCritical,
				re:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			},
			// Credit card numbers (Visa, MC, Amex, Discover)
			{
				piiType:  models.PIICreditCard,
				label:    "credit_card",
				severity: models.PIISeverityCritical,
				re:       regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`),
			},
			// Credit cards with dashes/spaces
			{
				piiType:  models.PIICreditCard,
				label:    "credit_card",
				severity: models.PIISeverityCritical,
				re:       regexp.MustCompile(`\b(?:\d{4}[-\s]){3}\d{4}\b`),
			},
			// IPv4 addresses
			{
				piiType:  models.PIIIPAddress,
				label:    "ip_address",
				severity: models.PIISeverityLow,
				re:       regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			},
			// IPv6 addresses (simplified)
			{
				piiType:  models.PIIIPAddress,
				label:    "ip_address",
				severity: models.PIISeverityLow,
				re:       regexp.MustCompile(`\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`),
			},
			// AWS access key IDs
			{
				piiType:  models.PIIEmployeeID, // closest category for key credentials
				label:    "aws_access_key",
				severity: models.PIISeverityCritical,
				re:       regexp.MustCompile(`\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`),
			},
			// GitHub personal access tokens (classic and fine-grained)
			{
				piiType:  models.PIIEmployeeID,
				label:    "github_token",
				severity: models.PIISeverityCritical,
				re:       regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b`),
			},
			// JWTs (three base64url sections separated by dots)
			{
				piiType:  models.PIIEmployeeID,
				label:    "jwt",
				severity: models.PIISeverityHigh,
				re:       regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
			},
		}
	})
}

// ---------------------------------------------------------------------------
// Detector implements guardrails.Rule
// ---------------------------------------------------------------------------

// Detector is a regex-based PII detection guardrail rule. It scans the
// prompt text against a set of patterns and returns findings with positions,
// types, and severity levels.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	// enabledTypes, if non-empty, restricts scanning to these PII types.
	enabledTypes map[string]bool
	// severityThreshold sets the minimum severity that produces a blocking
	// decision. Types below this threshold produce an alert instead.
	severityThreshold models.PIISeverity
	// blockOnDetect, if true, returns DecisionBlock; otherwise DecisionAnonymize.
	blockOnDetect bool
	// maxFindings caps the number of findings returned. Zero means unlimited.
	maxFindings int
}

var severityRank = map[models.PIISeverity]int{
	models.PIISeverityLow:      1,
	models.PIISeverityMedium:   2,
	models.PIISeverityHigh:     3,
	models.PIISeverityCritical: 4,
}

// New creates a new PII Detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			severityThreshold: models.PIISeverityLow,
			blockOnDetect:     false, // default to anonymize
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-010" }
func (d *Detector) Name() string                  { return "PII Detection" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageInput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryPII }

// Evaluate scans the prompt text for PII patterns and returns an evaluation
// containing all findings with their positions and severity levels.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	initPatterns()

	text := ctx.PromptText
	if text == "" {
		return &models.GuardrailEvaluation{
			RuleID:     d.ID(),
			RuleName:   d.Name(),
			Stage:      d.Stage(),
			Decision:   models.DecisionAllow,
			Confidence: 1.0,
			Reason:     "no input text to scan",
			LatencyMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	var findings []models.Finding
	highestSeverity := models.PIISeverityLow

	for _, p := range patterns {
		// If the caller has restricted to specific types, skip others.
		if len(cfg.enabledTypes) > 0 && !cfg.enabledTypes[p.label] {
			continue
		}

		matches := p.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			matchText := text[loc[0]:loc[1]]
			masked := maskValue(matchText)

			findings = append(findings, models.Finding{
				Type:       p.label,
				Value:      masked,
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   string(p.severity),
				Confidence: 0.95,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})

			if severityRank[p.severity] > severityRank[highestSeverity] {
				highestSeverity = p.severity
			}

			if cfg.maxFindings > 0 && len(findings) >= cfg.maxFindings {
				break
			}
		}
		if cfg.maxFindings > 0 && len(findings) >= cfg.maxFindings {
			break
		}
	}

	eval := &models.GuardrailEvaluation{
		RuleID:     d.ID(),
		RuleName:   d.Name(),
		Stage:      d.Stage(),
		Findings:   findings,
		Confidence: 1.0,
		LatencyMs:  time.Since(start).Milliseconds(),
	}

	if len(findings) == 0 {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no PII detected"
		return eval, nil
	}

	// Determine decision based on severity and configuration.
	meetsThreshold := severityRank[highestSeverity] >= severityRank[cfg.severityThreshold]
	if meetsThreshold && cfg.blockOnDetect {
		eval.Decision = models.DecisionBlock
	} else if meetsThreshold {
		eval.Decision = models.DecisionAnonymize
	} else {
		eval.Decision = models.DecisionAlert
	}

	eval.Reason = fmt.Sprintf("detected %d PII finding(s); highest severity: %s", len(findings), highestSeverity)
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration from the rule config map.
// Supported keys:
//   - "enabled_types" ([]string): restrict scanning to the listed PII labels.
//   - "severity_threshold" (string): minimum severity to block/anonymize.
//   - "block" (bool): if true, use block decision instead of anonymize.
//   - "max_findings" (int/float64): cap the number of reported findings.
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["enabled_types"]; ok {
		if arr, ok := v.([]any); ok {
			m := make(map[string]bool, len(arr))
			for _, item := range arr {
				if s, ok := item.(string); ok {
					m[s] = true
				}
			}
			d.cfg.enabledTypes = m
		}
	}

	if v, ok := cfg["severity_threshold"]; ok {
		if s, ok := v.(string); ok {
			switch models.PIISeverity(s) {
			case models.PIISeverityLow, models.PIISeverityMedium,
				models.PIISeverityHigh, models.PIISeverityCritical:
				d.cfg.severityThreshold = models.PIISeverity(s)
			default:
				return fmt.Errorf("pii: unknown severity threshold %q", s)
			}
		}
	}

	if v, ok := cfg["block"]; ok {
		if b, ok := v.(bool); ok {
			d.cfg.blockOnDetect = b
		}
	}

	if v, ok := cfg["max_findings"]; ok {
		switch n := v.(type) {
		case float64:
			d.cfg.maxFindings = int(n)
		case int:
			d.cfg.maxFindings = n
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// maskValue partially redacts a matched value for safe inclusion in findings.
// The first and last characters are kept; everything in between is replaced
// with asterisks. Very short values are fully masked.
func maskValue(s string) string {
	if len(s) <= 4 {
		return strings.Repeat("*", len(s))
	}
	runes := []rune(s)
	masked := make([]rune, len(runes))
	masked[0] = runes[0]
	masked[len(runes)-1] = runes[len(runes)-1]
	for i := 1; i < len(runes)-1; i++ {
		masked[i] = '*'
	}
	return string(masked)
}
