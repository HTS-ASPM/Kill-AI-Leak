// Package residency provides a guardrail rule that enforces data residency
// requirements by detecting EU PII patterns and ensuring requests are routed
// to approved EU-based providers/regions.
package residency

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// EU PII detection patterns.
var (
	// IBAN: 2 letter country code + 2 check digits + up to 30 alphanumeric chars.
	ibanRe = regexp.MustCompile(`\b[A-Z]{2}\d{2}\s?[\dA-Z]{4}\s?[\dA-Z]{4}\s?[\dA-Z]{4}(?:\s?[\dA-Z]{4}){0,5}(?:\s?[\dA-Z]{1,4})?\b`)

	// EU phone formats: +31, +33, +34, +39, +49, etc.
	euPhoneRe = regexp.MustCompile(`\+(?:30|31|32|33|34|35[0-9]|36|37[0-9]|38[0-9]|39|40|41|42[0-9]|43|44|45|46|47|48|49)\s?\d[\d\s\-]{6,14}`)

	// EU postal code patterns (a simplified set covering major EU countries).
	euPostalRe = regexp.MustCompile(`\b(?:` +
		`[A-Z]{1,2}\d{1,2}\s?\d[A-Z]{2}` + // UK format (historical)
		`|\d{5}` + // DE, FR, ES, IT, etc.
		`|\d{4}\s?[A-Z]{2}` + // NL format
		`|\d{4}` + // BE, AT, CH, DK, etc.
		`)\b`)

	// EU VAT number patterns.
	euVATRe = regexp.MustCompile(`\b(?:ATU\d{8}|BE\d{10}|BG\d{9,10}|HR\d{11}|CY\d{8}[A-Z]|CZ\d{8,10}|DK\d{8}|EE\d{9}|FI\d{8}|FR[\dA-Z]{2}\d{9}|DE\d{9}|EL\d{9}|HU\d{8}|IE\d{7}[A-Z]{1,2}|IT\d{11}|LV\d{11}|LT\d{9,12}|LU\d{8}|MT\d{8}|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|RO\d{2,10}|SK\d{10}|SI\d{8}|ES[A-Z]\d{7}[A-Z]|SE\d{12})\b`)
)

// EU country codes for IBAN prefix detection.
var euCountryCodes = map[string]bool{
	"AT": true, "BE": true, "BG": true, "HR": true, "CY": true,
	"CZ": true, "DK": true, "EE": true, "FI": true, "FR": true,
	"DE": true, "GR": true, "HU": true, "IE": true, "IT": true,
	"LV": true, "LT": true, "LU": true, "MT": true, "NL": true,
	"PL": true, "PT": true, "RO": true, "SK": true, "SI": true,
	"ES": true, "SE": true,
}

// Detector implements guardrails.Rule for GR-020 Data Residency.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	euProviders     map[string]bool // providers approved for EU data
	requireEURouting bool
}

// New creates a new data residency detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			euProviders: map[string]bool{
				"azure":   true,
				"bedrock": true,
			},
			requireEURouting: true,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-020" }
func (d *Detector) Name() string                  { return "Data Residency" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageRouting }
func (d *Detector) Category() models.RuleCategory { return models.CategoryDataResidency }

// Evaluate detects EU PII in the prompt and verifies that the target provider
// is approved for EU data processing.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	eval := &models.GuardrailEvaluation{
		RuleID:   d.ID(),
		RuleName: d.Name(),
		Stage:    d.Stage(),
	}

	text := ctx.PromptText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "no input text to scan for EU data"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	var findings []models.Finding
	euDataDetected := false

	// Check for EU IBANs.
	ibanMatches := ibanRe.FindAllString(text, -1)
	for _, match := range ibanMatches {
		cleaned := strings.ReplaceAll(match, " ", "")
		prefix := ""
		if len(cleaned) >= 2 {
			prefix = cleaned[:2]
		}
		if euCountryCodes[prefix] {
			euDataDetected = true
			findings = append(findings, models.Finding{
				Type:       "eu_iban",
				Value:      maskValue(match),
				Severity:   "high",
				Confidence: 0.95,
			})
		}
	}

	// Check for EU phone numbers.
	phoneMatches := euPhoneRe.FindAllString(text, -1)
	for _, match := range phoneMatches {
		euDataDetected = true
		findings = append(findings, models.Finding{
			Type:       "eu_phone",
			Value:      maskValue(match),
			Severity:   "medium",
			Confidence: 0.85,
		})
	}

	// Check for EU VAT numbers.
	vatMatches := euVATRe.FindAllString(text, -1)
	for _, match := range vatMatches {
		euDataDetected = true
		findings = append(findings, models.Finding{
			Type:       "eu_vat",
			Value:      maskValue(match),
			Severity:   "medium",
			Confidence: 0.90,
		})
	}

	if !euDataDetected {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0.0
		eval.Reason = "no EU PII data detected in request"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// EU data detected -- check if provider is approved.
	if !cfg.requireEURouting {
		eval.Decision = models.DecisionAlert
		eval.Confidence = 0.7
		eval.Reason = fmt.Sprintf("EU PII detected (%d finding(s)) but EU routing is not required", len(findings))
		eval.Findings = findings
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	provider := ctx.Provider
	if provider == "" {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 0.9
		eval.Reason = "EU PII detected but no provider specified for routing validation"
		eval.Findings = findings
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	if !cfg.euProviders[strings.ToLower(provider)] {
		eval.Decision = models.DecisionBlock
		eval.Confidence = 0.95
		eval.Reason = fmt.Sprintf("EU PII detected but provider %q is not approved for EU data; approved: %s",
			provider, joinMapKeys(cfg.euProviders))
		eval.Findings = findings
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Provider is EU-approved.
	eval.Decision = models.DecisionAllow
	eval.Confidence = 0.0
	eval.Reason = fmt.Sprintf("EU PII detected; provider %q is approved for EU data processing", provider)
	eval.Findings = findings
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "eu_providers" ([]string): list of provider names approved for EU data
//   - "require_eu_routing" (bool): if true, block non-EU-approved providers
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["eu_providers"]; ok {
		providers, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("residency: eu_providers: %w", err)
		}
		d.cfg.euProviders = make(map[string]bool, len(providers))
		for _, p := range providers {
			d.cfg.euProviders[strings.ToLower(p)] = true
		}
	}

	if v, ok := cfg["require_eu_routing"]; ok {
		if b, ok := v.(bool); ok {
			d.cfg.requireEURouting = b
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func maskValue(s string) string {
	runes := []rune(s)
	if len(runes) <= 6 {
		return "***"
	}
	return string(runes[:3]) + "***" + string(runes[len(runes)-3:])
}

func joinMapKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
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
