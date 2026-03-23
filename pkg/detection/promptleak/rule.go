// Package promptleak provides a guardrail rule that detects when an LLM
// response contains indicators of system prompt leakage.
package promptleak

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// leakageIndicators are phrases that suggest the model is revealing its
// system prompt or internal instructions.
var leakageIndicators = []struct {
	pattern string
	weight  float64
	re      *regexp.Regexp
}{
	{"my instructions are", 0.90, regexp.MustCompile(`(?i)my\s+instructions\s+are`)},
	{"my system prompt", 0.95, regexp.MustCompile(`(?i)my\s+system\s+prompt`)},
	{"I was told to", 0.70, regexp.MustCompile(`(?i)i\s+was\s+told\s+to`)},
	{"my guidelines say", 0.75, regexp.MustCompile(`(?i)my\s+guidelines?\s+say`)},
	{"as instructed in my prompt", 0.90, regexp.MustCompile(`(?i)as\s+instructed\s+in\s+my\s+prompt`)},
	{"my programming says", 0.80, regexp.MustCompile(`(?i)my\s+programming\s+says`)},
	{"I was programmed to", 0.75, regexp.MustCompile(`(?i)i\s+was\s+programmed\s+to`)},
	{"my instructions say", 0.85, regexp.MustCompile(`(?i)my\s+instructions?\s+say`)},
	{"the system prompt states", 0.95, regexp.MustCompile(`(?i)the\s+system\s+prompt\s+states`)},
	{"according to my instructions", 0.85, regexp.MustCompile(`(?i)according\s+to\s+my\s+instructions`)},
	{"I am instructed to", 0.80, regexp.MustCompile(`(?i)i\s+am\s+instructed\s+to`)},
	{"my hidden instructions", 0.95, regexp.MustCompile(`(?i)my\s+hidden\s+instructions`)},
	{"my initial prompt", 0.90, regexp.MustCompile(`(?i)my\s+initial\s+prompt`)},
}

// systemPromptPrefixes are common beginnings of system prompts that, if found
// in the response, strongly indicate leakage.
var systemPromptPrefixes = []struct {
	pattern string
	weight  float64
	re      *regexp.Regexp
}{
	{"You are a helpful", 0.60, regexp.MustCompile(`(?i)you\s+are\s+a\s+helpful`)},
	{"Your role is to", 0.65, regexp.MustCompile(`(?i)your\s+role\s+is\s+to`)},
	{"Instructions:", 0.55, regexp.MustCompile(`(?i)^instructions\s*:`)},
	{"System:", 0.60, regexp.MustCompile(`(?i)^system\s*:`)},
	{"You are an AI assistant", 0.55, regexp.MustCompile(`(?i)you\s+are\s+an\s+ai\s+assistant`)},
	{"Your task is to", 0.55, regexp.MustCompile(`(?i)your\s+task\s+is\s+to`)},
	{"You must always", 0.50, regexp.MustCompile(`(?i)you\s+must\s+always`)},
	{"You should never", 0.50, regexp.MustCompile(`(?i)you\s+should\s+never`)},
}

// Detector implements guardrails.Rule for GR-032 System Prompt Leakage.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	blockThreshold       float64
	systemPromptFragments []string // known system prompt fragments to compare against
}

// New creates a new prompt leakage detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			blockThreshold: 0.70,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-032" }
func (d *Detector) Name() string                  { return "System Prompt Leakage Detection" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageOutput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryInjection }

// Evaluate checks the LLM response for phrases that indicate system prompt leakage.
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

	// Check for leakage indicator phrases.
	for _, indicator := range leakageIndicators {
		matches := indicator.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "prompt_leak_indicator",
				Value:      truncate(text[loc[0]:loc[1]], 100),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   severityFromWeight(indicator.weight),
				Confidence: indicator.weight,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if indicator.weight > maxConfidence {
				maxConfidence = indicator.weight
			}
		}
	}

	// Check for system prompt prefixes in the response.
	for _, prefix := range systemPromptPrefixes {
		matches := prefix.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "system_prompt_prefix",
				Value:      truncate(text[loc[0]:loc[1]], 100),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   "medium",
				Confidence: prefix.weight,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if prefix.weight > maxConfidence {
				maxConfidence = prefix.weight
			}
		}
	}

	// Compare response against known system prompt fragments if available.
	for _, fragment := range cfg.systemPromptFragments {
		if fragment == "" {
			continue
		}
		lowerFrag := strings.ToLower(fragment)
		lowerText := strings.ToLower(text)
		if strings.Contains(lowerText, lowerFrag) {
			confidence := 0.95
			findings = append(findings, models.Finding{
				Type:       "system_prompt_fragment",
				Value:      truncate(fragment, 100),
				Severity:   "critical",
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	switch {
	case maxConfidence >= cfg.blockThreshold:
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("system prompt leakage detected (confidence=%.2f); %d indicator(s) found",
			maxConfidence, len(findings))
	case maxConfidence >= 0.4:
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("possible system prompt leakage (confidence=%.2f); %d indicator(s) found",
			maxConfidence, len(findings))
	default:
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no prompt leakage detected (confidence=%.2f)", maxConfidence)
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "block_threshold" (float64): confidence above which to block [0,1]
//   - "system_prompt_fragments" ([]string): known system prompt fragments
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["block_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("promptleak: block_threshold must be between 0 and 1")
			}
			d.cfg.blockThreshold = f
		}
	}

	if v, ok := cfg["system_prompt_fragments"]; ok {
		frags, err := parseStringList(v)
		if err != nil {
			return fmt.Errorf("promptleak: system_prompt_fragments: %w", err)
		}
		d.cfg.systemPromptFragments = frags
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

func severityFromWeight(w float64) string {
	switch {
	case w >= 0.85:
		return "critical"
	case w >= 0.70:
		return "high"
	case w >= 0.50:
		return "medium"
	default:
		return "low"
	}
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
