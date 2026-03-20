// Package injection provides a guardrail rule that detects prompt injection
// attacks using a two-layer approach: signature-based pattern matching and
// heuristic scoring of instruction-like language.
package injection

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Signature patterns (Layer 1)
// ---------------------------------------------------------------------------

type signaturePattern struct {
	label  string
	weight float64 // contribution to the final score (0-1)
	re     *regexp.Regexp
}

var (
	signatures     []signaturePattern
	signaturesOnce sync.Once
)

func initSignatures() {
	signaturesOnce.Do(func() {
		signatures = []signaturePattern{
			// Direct override instructions
			{label: "ignore_previous", weight: 0.85, re: regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|directives?|rules?)`)},
			{label: "disregard_instructions", weight: 0.85, re: regexp.MustCompile(`(?i)disregard\s+(?:all\s+)?(?:previous|prior|above|your)\s+(?:instructions?|prompts?|guidelines?)`)},
			{label: "forget_instructions", weight: 0.80, re: regexp.MustCompile(`(?i)(?:forget|override|bypass|skip)\s+(?:all\s+)?(?:previous|prior|your|the)\s+(?:instructions?|rules?|constraints?|guidelines?)`)},
			{label: "do_not_follow", weight: 0.80, re: regexp.MustCompile(`(?i)do\s+not\s+follow\s+(?:your|the|any)\s+(?:previous|original|prior)\s+(?:instructions?|rules?)`)},

			// Role reassignment
			{label: "you_are_now", weight: 0.75, re: regexp.MustCompile(`(?i)you\s+are\s+now\s+(?:a|an|the)\s+`)},
			{label: "new_identity", weight: 0.75, re: regexp.MustCompile(`(?i)(?:from\s+now\s+on|henceforth|starting\s+now)\s*,?\s*(?:you\s+are|act\s+as|behave\s+as|respond\s+as)`)},
			{label: "pretend_you_are", weight: 0.70, re: regexp.MustCompile(`(?i)(?:pretend|imagine|suppose|assume)\s+(?:you\s+are|you're|to\s+be)`)},

			// System prompt markers
			{label: "system_prompt_marker", weight: 0.90, re: regexp.MustCompile(`(?i)system\s*prompt\s*:`)},
			{label: "system_prompt_marker", weight: 0.90, re: regexp.MustCompile(`(?i)\[system\]`)},
			{label: "system_prompt_marker", weight: 0.90, re: regexp.MustCompile(`(?i)<<\s*SYS\s*>>`)},

			// Chat-ML / instruction format markers
			{label: "chatml_marker", weight: 0.90, re: regexp.MustCompile(`<\|im_start\|>system`)},
			{label: "chatml_marker", weight: 0.85, re: regexp.MustCompile(`<\|im_start\|>`)},
			{label: "chatml_marker", weight: 0.85, re: regexp.MustCompile(`<\|im_end\|>`)},

			// Llama / instruction format markers
			{label: "inst_marker", weight: 0.90, re: regexp.MustCompile(`\[INST\]`)},
			{label: "inst_marker", weight: 0.85, re: regexp.MustCompile(`\[/INST\]`)},
			{label: "inst_marker", weight: 0.85, re: regexp.MustCompile(`(?i)###\s*(?:instruction|system|human|assistant)\s*:`)},

			// Prompt leaking attempts
			{label: "prompt_leak", weight: 0.80, re: regexp.MustCompile(`(?i)(?:show|reveal|display|print|output|repeat|echo)\s+(?:your|the|my)?\s*(?:system\s+)?(?:prompt|instructions?|rules?|directives?)`)},
			{label: "prompt_leak", weight: 0.75, re: regexp.MustCompile(`(?i)what\s+(?:are|is|were)\s+your\s+(?:original\s+)?(?:instructions?|system\s+prompt|directives?|rules?)`)},

			// Delimiter injection
			{label: "delimiter_injection", weight: 0.70, re: regexp.MustCompile(`(?i)---\s*(?:new|begin|start)\s+(?:conversation|session|instructions?)`)},
			{label: "delimiter_injection", weight: 0.65, re: regexp.MustCompile(`(?i)(?:end|stop)\s+(?:of\s+)?(?:system|user)\s+(?:message|prompt)`)},

			// Payload / code injection markers
			{label: "payload_injection", weight: 0.65, re: regexp.MustCompile(`(?i)(?:execute|run|eval)\s+(?:the\s+following|this)\s+(?:code|command|script)`)},
		}
	})
}

// ---------------------------------------------------------------------------
// Heuristic patterns (Layer 2)
// ---------------------------------------------------------------------------

type heuristicPattern struct {
	label  string
	weight float64
	re     *regexp.Regexp
}

var (
	heuristics     []heuristicPattern
	heuristicsOnce sync.Once
)

func initHeuristics() {
	heuristicsOnce.Do(func() {
		heuristics = []heuristicPattern{
			// Imperative commands
			{label: "imperative_command", weight: 0.30, re: regexp.MustCompile(`(?i)^\s*(?:always|never|must|do\s+not|don't|you\s+must|you\s+should|you\s+will)\b`)},
			{label: "imperative_override", weight: 0.35, re: regexp.MustCompile(`(?i)(?:instead|rather),?\s+(?:you\s+(?:should|must|will)|do\s+the\s+following)`)},

			// Instruction-like language
			{label: "instruction_language", weight: 0.25, re: regexp.MustCompile(`(?i)(?:your\s+(?:new\s+)?(?:task|job|role|purpose|objective|goal)\s+is)`)},
			{label: "instruction_language", weight: 0.25, re: regexp.MustCompile(`(?i)(?:i\s+(?:want|need)\s+you\s+to\s+(?:ignore|forget|disregard|override))`)},
			{label: "instruction_continuation", weight: 0.20, re: regexp.MustCompile(`(?i)(?:for\s+the\s+rest\s+of\s+this\s+conversation|from\s+this\s+point\s+(?:forward|on))`)},

			// System-role references in user messages
			{label: "system_role_ref", weight: 0.35, re: regexp.MustCompile(`(?i)(?:as\s+(?:a|the)\s+system|in\s+(?:your|the)\s+system\s+(?:prompt|message|role))`)},
			{label: "system_role_ref", weight: 0.30, re: regexp.MustCompile(`(?i)(?:developer|admin|root|operator)\s+mode`)},

			// Output format manipulation
			{label: "output_manipulation", weight: 0.20, re: regexp.MustCompile(`(?i)(?:respond|reply|answer)\s+(?:only|exclusively)\s+(?:with|in|using)`)},
			{label: "output_manipulation", weight: 0.25, re: regexp.MustCompile(`(?i)(?:do\s+not|don't|never)\s+(?:mention|reveal|disclose|tell|say)\s+(?:that|this|anything\s+about)`)},
		}
	})
}

// ---------------------------------------------------------------------------
// Detector implements guardrails.Rule
// ---------------------------------------------------------------------------

// Detector performs two-layer prompt injection detection and returns a
// confidence score between 0 and 1.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	// signatureWeight controls how much Layer 1 contributes to the final
	// score. Layer 2 gets (1 - signatureWeight). Default: 0.7
	signatureWeight float64
	// blockThreshold is the confidence above which the decision becomes
	// block. Default: 0.7
	blockThreshold float64
	// alertThreshold is the confidence above which we alert (but below
	// block). Default: 0.4
	alertThreshold float64
}

// New creates a new injection Detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			signatureWeight: 0.7,
			blockThreshold:  0.7,
			alertThreshold:  0.4,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-013" }
func (d *Detector) Name() string                  { return "Prompt Injection Detection" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageInput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryInjection }

// Evaluate runs both detection layers against the prompt text and returns
// a combined confidence score.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	initSignatures()
	initHeuristics()

	text := ctx.PromptText
	if text == "" {
		return &models.GuardrailEvaluation{
			RuleID:     d.ID(),
			RuleName:   d.Name(),
			Stage:      d.Stage(),
			Decision:   models.DecisionAllow,
			Confidence: 0.0,
			Reason:     "no input text to scan",
			LatencyMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	// Normalize text for analysis.
	normalized := normalizeText(text)

	// --- Layer 1: Signature matching ---
	var sigFindings []models.Finding
	sigScore := 0.0
	for _, sig := range signatures {
		matches := sig.re.FindAllStringIndex(normalized, -1)
		for _, loc := range matches {
			sigFindings = append(sigFindings, models.Finding{
				Type:       sig.label,
				Value:      truncate(normalized[loc[0]:loc[1]], 100),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   severityFromWeight(sig.weight),
				Confidence: sig.weight,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if sig.weight > sigScore {
				sigScore = sig.weight
			}
		}
	}

	// --- Layer 2: Heuristic scoring ---
	heuristicScore := 0.0
	var heurFindings []models.Finding
	for _, h := range heuristics {
		matches := h.re.FindAllStringIndex(normalized, -1)
		if len(matches) > 0 {
			for _, loc := range matches {
				heurFindings = append(heurFindings, models.Finding{
					Type:       "heuristic:" + h.label,
					Value:      truncate(normalized[loc[0]:loc[1]], 100),
					Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
					Severity:   "medium",
					Confidence: h.weight,
					StartPos:   loc[0],
					EndPos:     loc[1],
				})
			}
			heuristicScore += h.weight * float64(len(matches))
		}
	}
	// Cap the heuristic score at 1.0
	heuristicScore = math.Min(heuristicScore, 1.0)

	// --- Combine scores ---
	combined := cfg.signatureWeight*sigScore + (1.0-cfg.signatureWeight)*heuristicScore
	combined = math.Min(combined, 1.0)

	// Merge findings.
	allFindings := append(sigFindings, heurFindings...)

	eval := &models.GuardrailEvaluation{
		RuleID:     d.ID(),
		RuleName:   d.Name(),
		Stage:      d.Stage(),
		Confidence: combined,
		Findings:   allFindings,
		LatencyMs:  time.Since(start).Milliseconds(),
	}

	switch {
	case combined >= cfg.blockThreshold:
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("prompt injection detected (confidence=%.2f); %d signature match(es), %d heuristic match(es)",
			combined, len(sigFindings), len(heurFindings))
	case combined >= cfg.alertThreshold:
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("possible prompt injection (confidence=%.2f); %d signature match(es), %d heuristic match(es)",
			combined, len(sigFindings), len(heurFindings))
	default:
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no injection detected (confidence=%.2f)", combined)
	}

	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "signature_weight" (float64): weight for Layer 1 in combined score [0,1].
//   - "block_threshold" (float64): combined score above which to block [0,1].
//   - "alert_threshold" (float64): combined score above which to alert [0,1].
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["signature_weight"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("injection: signature_weight must be between 0 and 1")
			}
			d.cfg.signatureWeight = f
		}
	}
	if v, ok := cfg["block_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("injection: block_threshold must be between 0 and 1")
			}
			d.cfg.blockThreshold = f
		}
	}
	if v, ok := cfg["alert_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("injection: alert_threshold must be between 0 and 1")
			}
			d.cfg.alertThreshold = f
		}
	}

	if d.cfg.alertThreshold > d.cfg.blockThreshold {
		return fmt.Errorf("injection: alert_threshold (%.2f) must not exceed block_threshold (%.2f)",
			d.cfg.alertThreshold, d.cfg.blockThreshold)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// normalizeText applies light normalization to reduce evasion via spacing
// and unicode tricks. It collapses runs of whitespace, strips zero-width
// characters, and maps common lookalike substitutions.
func normalizeText(s string) string {
	// Strip zero-width characters.
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad':
			// zero-width / soft-hyphen - skip
		default:
			b.WriteRune(r)
		}
	}
	normalized := b.String()

	// Collapse whitespace.
	spaceRe := regexp.MustCompile(`\s+`)
	normalized = spaceRe.ReplaceAllString(normalized, " ")
	normalized = strings.TrimSpace(normalized)

	return normalized
}

// severityFromWeight maps a pattern weight to a severity string.
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

// truncate returns at most maxLen characters from s, appending "..." if
// truncated.
func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

// isUpperRatio returns the fraction of alphabetic characters that are
// uppercase. Used internally for heuristic checks (exported for tests).
func isUpperRatio(s string) float64 {
	total := 0
	upper := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			total++
			if unicode.IsUpper(r) {
				upper++
			}
		}
	}
	if total == 0 {
		return 0
	}
	return float64(upper) / float64(total)
}
