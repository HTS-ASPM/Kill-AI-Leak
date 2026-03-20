// Package jailbreak provides a guardrail rule that detects jailbreak
// attempts including role-play manipulation, encoding bypass tricks,
// DAN-mode patterns, and other constraint-removal strategies.
package jailbreak

import (
	"encoding/base64"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ---------------------------------------------------------------------------
// Pattern categories
// ---------------------------------------------------------------------------

type jailbreakPattern struct {
	category string  // "roleplay", "encoding_bypass", "dan_mode", "constraint_removal"
	label    string  // human-readable match label
	weight   float64 // contribution to the confidence score
	re       *regexp.Regexp
}

var (
	jbPatterns     []jailbreakPattern
	jbPatternsOnce sync.Once
)

func initPatterns() {
	jbPatternsOnce.Do(func() {
		jbPatterns = []jailbreakPattern{
			// ---- Role-play manipulation ----
			{category: "roleplay", label: "pretend_you_are", weight: 0.70,
				re: regexp.MustCompile(`(?i)(?:pretend|imagine|suppose|assume)\s+(?:you\s+are|you're|to\s+be)\s+(?:a|an|the)?\s*\w+`)},
			{category: "roleplay", label: "act_as_if", weight: 0.70,
				re: regexp.MustCompile(`(?i)(?:act|behave|respond|operate)\s+(?:as\s+if|as\s+though|like)\s+(?:you\s+(?:are|were|have)|there\s+(?:are|were))`)},
			{category: "roleplay", label: "roleplay_scenario", weight: 0.65,
				re: regexp.MustCompile(`(?i)(?:let'?s?\s+)?(?:play|do)\s+(?:a\s+)?(?:role\s*play|roleplay|game|scenario)\s+(?:where|in\s+which)`)},
			{category: "roleplay", label: "character_assignment", weight: 0.65,
				re: regexp.MustCompile(`(?i)(?:you\s+will\s+(?:play|be|act\s+as)|your\s+(?:character|role|persona)\s+is)`)},
			{category: "roleplay", label: "fictional_framing", weight: 0.60,
				re: regexp.MustCompile(`(?i)(?:in\s+this\s+(?:story|scenario|fiction|narrative|simulation)|for\s+(?:a|this)\s+(?:story|creative\s+writing|fiction))`)},
			{category: "roleplay", label: "opposite_day", weight: 0.75,
				re: regexp.MustCompile(`(?i)(?:opposite\s+day|everything\s+is\s+reversed|answer\s+(?:the\s+)?opposite)`)},

			// ---- DAN-mode patterns ----
			{category: "dan_mode", label: "dan_activation", weight: 0.90,
				re: regexp.MustCompile(`(?i)\bDAN\b.*(?:mode|enabled|activated|jailbreak)`)},
			{category: "dan_mode", label: "dan_prompt", weight: 0.90,
				re: regexp.MustCompile(`(?i)(?:do\s+anything\s+now|DAN\s+mode|DAN\s+[0-9.]+)`)},
			{category: "dan_mode", label: "no_restrictions", weight: 0.80,
				re: regexp.MustCompile(`(?i)(?:you\s+(?:have|has)\s+no\s+(?:restrictions?|limitations?|boundaries|filters?|rules?|constraints?|guidelines?))`)},
			{category: "dan_mode", label: "no_ethical_guidelines", weight: 0.85,
				re: regexp.MustCompile(`(?i)(?:(?:without|no|ignore|bypass|remove)\s+(?:any\s+)?(?:ethical|moral|safety)\s+(?:guidelines?|constraints?|filters?|restrictions?))`)},
			{category: "dan_mode", label: "unrestricted_mode", weight: 0.85,
				re: regexp.MustCompile(`(?i)(?:(?:un)?(?:restricted|filtered|censored|limited)\s+mode|(?:enable|activate|enter|switch\s+to)\s+(?:un)?(?:restricted|filtered|censored)\s+mode)`)},
			{category: "dan_mode", label: "jailbreak_keyword", weight: 0.85,
				re: regexp.MustCompile(`(?i)\bjailbreak(?:ed|ing)?\b`)},
			{category: "dan_mode", label: "dual_personality", weight: 0.80,
				re: regexp.MustCompile(`(?i)(?:two\s+(?:responses?|answers?|outputs?)|respond\s+(?:twice|in\s+two\s+ways)|one\s+(?:normal|filtered)\s+and\s+one\s+(?:unfiltered|uncensored))`)},

			// ---- Constraint removal ----
			{category: "constraint_removal", label: "remove_constraints", weight: 0.80,
				re: regexp.MustCompile(`(?i)(?:remove|disable|turn\s+off|deactivate|override)\s+(?:all\s+)?(?:your\s+)?(?:safety|content|ethical|output)\s+(?:filters?|restrictions?|guidelines?|constraints?|measures?)`)},
			{category: "constraint_removal", label: "hypothetical_bypass", weight: 0.65,
				re: regexp.MustCompile(`(?i)(?:hypothetically|theoretically|in\s+theory)\s*,?\s*(?:if\s+you\s+(?:could|had\s+no|were\s+(?:free|allowed))|what\s+would)`)},
			{category: "constraint_removal", label: "developer_override", weight: 0.80,
				re: regexp.MustCompile(`(?i)(?:i\s+am\s+(?:your|the)\s+(?:developer|creator|programmer|admin)|developer\s+(?:mode|override)|maintenance\s+mode|sudo\s+mode)`)},
			{category: "constraint_removal", label: "token_manipulation", weight: 0.75,
				re: regexp.MustCompile(`(?i)(?:ignore\s+(?:your\s+)?(?:training|programming|alignment)|override\s+(?:your\s+)?(?:training|programming)|break\s+(?:free\s+)?(?:from|out\s+of)\s+(?:your\s+)?(?:constraints?|limitations?))`)},
		}
	})
}

// ---------------------------------------------------------------------------
// Detector implements guardrails.Rule
// ---------------------------------------------------------------------------

// Detector performs jailbreak detection across multiple attack vectors and
// returns a confidence score between 0 and 1.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	blockThreshold float64
	alertThreshold float64
	// checkEncoding enables base64 / unicode bypass detection.
	checkEncoding bool
}

// New creates a jailbreak Detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			blockThreshold: 0.7,
			alertThreshold: 0.4,
			checkEncoding:  true,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-014" }
func (d *Detector) Name() string                  { return "Jailbreak Detection" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageInput }
func (d *Detector) Category() models.RuleCategory { return models.CategoryJailbreak }

// Evaluate scans the prompt text for jailbreak indicators across all
// categories and returns a combined confidence score.
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
			Confidence: 0.0,
			Reason:     "no input text to scan",
			LatencyMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	d.mu.RLock()
	cfg := d.cfg
	d.mu.RUnlock()

	normalized := stripZeroWidth(text)

	var findings []models.Finding
	categoryScores := map[string]float64{
		"roleplay":            0,
		"dan_mode":            0,
		"constraint_removal":  0,
		"encoding_bypass":     0,
	}

	// --- Pattern matching ---
	for _, pat := range jbPatterns {
		matches := pat.re.FindAllStringIndex(normalized, -1)
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       pat.category + ":" + pat.label,
				Value:      truncate(normalized[loc[0]:loc[1]], 120),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   severityFromWeight(pat.weight),
				Confidence: pat.weight,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if pat.weight > categoryScores[pat.category] {
				categoryScores[pat.category] = pat.weight
			}
		}
	}

	// --- Encoding bypass detection ---
	if cfg.checkEncoding {
		encFindings, encScore := detectEncodingBypass(normalized)
		findings = append(findings, encFindings...)
		if encScore > categoryScores["encoding_bypass"] {
			categoryScores["encoding_bypass"] = encScore
		}
	}

	// --- Combine category scores ---
	// Take the maximum category score as the primary signal, then add a
	// small boost for each additional category that fired (multi-vector
	// attacks are more suspicious).
	maxScore := 0.0
	activeCategories := 0
	for _, s := range categoryScores {
		if s > 0 {
			activeCategories++
			if s > maxScore {
				maxScore = s
			}
		}
	}
	// Each additional active category beyond the first adds 0.05.
	combined := maxScore
	if activeCategories > 1 {
		combined += float64(activeCategories-1) * 0.05
	}
	combined = math.Min(combined, 1.0)

	eval := &models.GuardrailEvaluation{
		RuleID:     d.ID(),
		RuleName:   d.Name(),
		Stage:      d.Stage(),
		Confidence: combined,
		Findings:   findings,
		LatencyMs:  time.Since(start).Milliseconds(),
	}

	switch {
	case combined >= cfg.blockThreshold:
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("jailbreak attempt detected (confidence=%.2f); %d finding(s) across %d category/categories",
			combined, len(findings), activeCategories)
	case combined >= cfg.alertThreshold:
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("possible jailbreak attempt (confidence=%.2f); %d finding(s)",
			combined, len(findings))
	default:
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no jailbreak detected (confidence=%.2f)", combined)
	}

	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "block_threshold" (float64): score above which to block [0,1].
//   - "alert_threshold" (float64): score above which to alert [0,1].
//   - "check_encoding" (bool): enable/disable encoding bypass checks.
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["block_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("jailbreak: block_threshold must be between 0 and 1")
			}
			d.cfg.blockThreshold = f
		}
	}
	if v, ok := cfg["alert_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 1 {
				return fmt.Errorf("jailbreak: alert_threshold must be between 0 and 1")
			}
			d.cfg.alertThreshold = f
		}
	}
	if v, ok := cfg["check_encoding"]; ok {
		if b, ok := v.(bool); ok {
			d.cfg.checkEncoding = b
		}
	}

	if d.cfg.alertThreshold > d.cfg.blockThreshold {
		return fmt.Errorf("jailbreak: alert_threshold (%.2f) must not exceed block_threshold (%.2f)",
			d.cfg.alertThreshold, d.cfg.blockThreshold)
	}

	return nil
}

// ---------------------------------------------------------------------------
// Encoding bypass detection
// ---------------------------------------------------------------------------

// base64Re matches plausible base64-encoded blocks (minimum 20 chars).
var base64Re = regexp.MustCompile(`[A-Za-z0-9+/]{20,}={0,2}`)

// detectEncodingBypass checks for base64-encoded payloads and unicode
// obfuscation tricks (homoglyphs, excessive combining chars, etc.).
func detectEncodingBypass(text string) ([]models.Finding, float64) {
	var findings []models.Finding
	maxScore := 0.0

	// --- Base64 detection ---
	b64Matches := base64Re.FindAllStringIndex(text, -1)
	for _, loc := range b64Matches {
		candidate := text[loc[0]:loc[1]]
		decoded, err := base64.StdEncoding.DecodeString(candidate)
		if err != nil {
			// Try with padding adjustment.
			padded := candidate
			if rem := len(padded) % 4; rem != 0 {
				padded += strings.Repeat("=", 4-rem)
			}
			decoded, err = base64.StdEncoding.DecodeString(padded)
			if err != nil {
				continue
			}
		}
		// Only flag if the decoded content is valid UTF-8 and looks like
		// natural language or commands (high ratio of printable chars).
		if !utf8.Valid(decoded) {
			continue
		}
		printableRatio := printableCharRatio(string(decoded))
		if printableRatio < 0.8 {
			continue
		}
		score := 0.65
		findings = append(findings, models.Finding{
			Type:       "encoding_bypass:base64",
			Value:      truncate(candidate, 60) + " -> " + truncate(string(decoded), 60),
			Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
			Severity:   "high",
			Confidence: score,
			StartPos:   loc[0],
			EndPos:     loc[1],
		})
		if score > maxScore {
			maxScore = score
		}
	}

	// --- Unicode tricks detection ---
	unicodeScore, unicodeFindings := detectUnicodeTricks(text)
	findings = append(findings, unicodeFindings...)
	if unicodeScore > maxScore {
		maxScore = unicodeScore
	}

	return findings, maxScore
}

// detectUnicodeTricks checks for suspicious unicode usage: homoglyphs that
// replace ASCII characters, excessive combining marks, and right-to-left
// override characters.
func detectUnicodeTricks(text string) (float64, []models.Finding) {
	var findings []models.Finding
	score := 0.0

	// Check for directional override characters.
	directionalChars := []rune{
		'\u202A', // LRE
		'\u202B', // RLE
		'\u202C', // PDF
		'\u202D', // LRO
		'\u202E', // RLO
		'\u2066', // LRI
		'\u2067', // RLI
		'\u2068', // FSI
		'\u2069', // PDI
	}
	for _, dc := range directionalChars {
		if strings.ContainsRune(text, dc) {
			findings = append(findings, models.Finding{
				Type:       "encoding_bypass:bidi_override",
				Value:      fmt.Sprintf("U+%04X directional override character", dc),
				Severity:   "high",
				Confidence: 0.75,
			})
			if score < 0.75 {
				score = 0.75
			}
		}
	}

	// Check for homoglyph density: count non-ASCII characters that look
	// like ASCII letters (Cyrillic а/е/о, etc.).
	homoglyphCount := 0
	totalLetters := 0
	for _, r := range text {
		if unicode.IsLetter(r) {
			totalLetters++
			if r > 127 && isLatinHomoglyph(r) {
				homoglyphCount++
			}
		}
	}
	if totalLetters > 10 && homoglyphCount > 0 {
		ratio := float64(homoglyphCount) / float64(totalLetters)
		if ratio > 0.05 {
			hScore := math.Min(0.5+ratio*2, 0.85)
			findings = append(findings, models.Finding{
				Type:       "encoding_bypass:homoglyph",
				Value:      fmt.Sprintf("%d homoglyph(s) in %d letters (%.1f%%)", homoglyphCount, totalLetters, ratio*100),
				Severity:   "high",
				Confidence: hScore,
			})
			if hScore > score {
				score = hScore
			}
		}
	}

	// Check for excessive combining characters (used to visually hide text).
	combiningCount := 0
	for _, r := range text {
		if unicode.Is(unicode.Mn, r) { // Mn = Mark, Nonspacing
			combiningCount++
		}
	}
	if combiningCount > 10 {
		cScore := math.Min(0.5+float64(combiningCount)/100.0, 0.80)
		findings = append(findings, models.Finding{
			Type:       "encoding_bypass:combining_chars",
			Value:      fmt.Sprintf("%d combining characters detected", combiningCount),
			Severity:   "medium",
			Confidence: cScore,
		})
		if cScore > score {
			score = cScore
		}
	}

	return score, findings
}

// isLatinHomoglyph returns true if r is a non-ASCII character commonly used
// to visually mimic a basic Latin letter (e.g., Cyrillic а, о, е, с, etc.).
func isLatinHomoglyph(r rune) bool {
	homoglyphs := map[rune]bool{
		'\u0430': true, // Cyrillic а -> a
		'\u0435': true, // Cyrillic е -> e
		'\u043E': true, // Cyrillic о -> o
		'\u0440': true, // Cyrillic р -> p
		'\u0441': true, // Cyrillic с -> c
		'\u0445': true, // Cyrillic х -> x
		'\u0443': true, // Cyrillic у -> y
		'\u0456': true, // Cyrillic і -> i
		'\u0455': true, // Cyrillic ѕ -> s
		'\u04BB': true, // Cyrillic һ -> h
		'\u0261': true, // Latin Small Letter Script G
		'\u01C3': true, // Latin Letter Retroflex Click
		'\uFF41': true, // Fullwidth a
		'\uFF45': true, // Fullwidth e
		'\uFF49': true, // Fullwidth i
		'\uFF4F': true, // Fullwidth o
	}
	return homoglyphs[r]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func stripZeroWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch r {
		case '\u200b', '\u200c', '\u200d', '\ufeff', '\u00ad':
			continue
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func printableCharRatio(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	printable := 0
	total := 0
	for _, r := range s {
		total++
		if unicode.IsPrint(r) || unicode.IsSpace(r) {
			printable++
		}
	}
	return float64(printable) / float64(total)
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

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
