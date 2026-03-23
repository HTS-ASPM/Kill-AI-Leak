// Package encoding provides a guardrail rule (GR-019) that detects attempts
// to bypass content filters using base64 encoding, ROT13, Unicode homoglyphs,
// hex encoding, and other evasion techniques.
package encoding

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Detection patterns for encoded content.
var (
	// base64Re matches base64-encoded strings of at least 20 chars.
	base64Re = regexp.MustCompile(`(?:^|[\s:=])([A-Za-z0-9+/]{20,}={0,2})(?:$|[\s,;])`)

	// hexRe matches hex-encoded byte sequences.
	hexRe = regexp.MustCompile(`(?i)(?:\\x[0-9a-f]{2}){4,}`)

	// unicodeEscRe matches Unicode escape sequences.
	unicodeEscRe = regexp.MustCompile(`(?i)(?:\\u[0-9a-f]{4}){3,}`)

	// rot13Pattern detects ROT13 references.
	rot13Re = regexp.MustCompile(`(?i)\brot13\b`)

	// Suspicious decoded content keywords (things people try to hide).
	suspiciousKeywords = []string{
		"ignore previous", "ignore above", "system prompt",
		"admin access", "sudo", "password", "api key",
		"drop table", "delete from", "exec(",
		"<script", "javascript:", "onerror",
	}
)

// Common Unicode homoglyphs that may be used to bypass filters.
var homoglyphMap = map[rune]rune{
	'\u0410': 'A', '\u0412': 'B', '\u0421': 'C', '\u0415': 'E',
	'\u041d': 'H', '\u041a': 'K', '\u041c': 'M', '\u041e': 'O',
	'\u0420': 'P', '\u0422': 'T', '\u0425': 'X',
	'\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
	'\u0441': 'c', '\u0443': 'y', '\u0445': 'x',
	'\u0391': 'A', '\u0392': 'B', '\u0395': 'E', '\u0397': 'H',
	'\u0399': 'I', '\u039a': 'K', '\u039c': 'M', '\u039d': 'N',
	'\u039f': 'O', '\u03a1': 'P', '\u03a4': 'T', '\u03a7': 'X',
	'\u03b1': 'a', '\u03bf': 'o',
	'\uff21': 'A', '\uff22': 'B', '\uff23': 'C', // fullwidth Latin
}

// Rule implements guardrails.Rule for GR-019 Encoding Evasion Detection.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	detectBase64    bool
	detectROT13     bool
	detectHomoglyphs bool
	decodeAndRescan bool
}

// New creates a new encoding evasion detector.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			detectBase64:     true,
			detectROT13:      true,
			detectHomoglyphs: true,
			decodeAndRescan:  true,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-019" }
func (r *Rule) Name() string                  { return "Encoding Evasion Detection" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryInjection }

// Evaluate scans the prompt for encoding-based filter evasion.
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
		eval.Reason = "no prompt text to scan"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	maxConfidence := 0.0

	// --- Base64 detection ---
	if cfg.detectBase64 {
		matches := base64Re.FindAllStringSubmatch(text, 10)
		for _, m := range matches {
			if len(m) < 2 {
				continue
			}
			encoded := m[1]
			decoded, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				continue
			}
			decodedStr := string(decoded)
			// Check if decoded content is printable text.
			if !isPrintableText(decodedStr) {
				continue
			}
			confidence := 0.6
			if cfg.decodeAndRescan && containsSuspicious(decodedStr) {
				confidence = 0.9
			}
			findings = append(findings, models.Finding{
				Type:       "base64_encoded",
				Value:      truncate(encoded, 60),
				Severity:   severityFromConfidence(confidence),
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	// --- ROT13 detection ---
	if cfg.detectROT13 {
		if rot13Re.MatchString(text) {
			// The prompt explicitly mentions ROT13, likely trying to use it.
			rotText := applyROT13(text)
			confidence := 0.5
			if cfg.decodeAndRescan && containsSuspicious(rotText) {
				confidence = 0.85
			}
			findings = append(findings, models.Finding{
				Type:       "rot13_reference",
				Severity:   severityFromConfidence(confidence),
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	// --- Homoglyph detection ---
	if cfg.detectHomoglyphs {
		homoglyphCount := 0
		for _, ch := range text {
			if _, isHomoglyph := homoglyphMap[ch]; isHomoglyph {
				homoglyphCount++
			}
		}
		if homoglyphCount > 3 {
			confidence := 0.7
			if homoglyphCount > 10 {
				confidence = 0.9
			}
			findings = append(findings, models.Finding{
				Type:       "unicode_homoglyphs",
				Value:      fmt.Sprintf("%d homoglyph characters detected", homoglyphCount),
				Severity:   severityFromConfidence(confidence),
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	// --- Hex encoding detection ---
	hexMatches := hexRe.FindAllString(text, 5)
	for _, hm := range hexMatches {
		confidence := 0.6
		findings = append(findings, models.Finding{
			Type:       "hex_encoding",
			Value:      truncate(hm, 60),
			Severity:   "medium",
			Confidence: confidence,
		})
		if confidence > maxConfidence {
			maxConfidence = confidence
		}
	}

	// --- Unicode escape detection ---
	uniMatches := unicodeEscRe.FindAllString(text, 5)
	for _, um := range uniMatches {
		confidence := 0.6
		findings = append(findings, models.Finding{
			Type:       "unicode_escape",
			Value:      truncate(um, 60),
			Severity:   "medium",
			Confidence: confidence,
		})
		if confidence > maxConfidence {
			maxConfidence = confidence
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if maxConfidence >= 0.8 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("encoding evasion detected (confidence=%.2f); %d finding(s)", maxConfidence, len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("possible encoding evasion (confidence=%.2f); %d finding(s)", maxConfidence, len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no encoding evasion detected"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["detect_base64"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.detectBase64 = b
		}
	}
	if v, ok := cfg["detect_rot13"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.detectROT13 = b
		}
	}
	if v, ok := cfg["detect_homoglyphs"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.detectHomoglyphs = b
		}
	}
	if v, ok := cfg["decode_and_rescan"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.decodeAndRescan = b
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func isPrintableText(s string) bool {
	if len(s) == 0 {
		return false
	}
	printable := 0
	for _, ch := range s {
		if unicode.IsPrint(ch) || ch == '\n' || ch == '\r' || ch == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len([]rune(s))) > 0.8
}

func containsSuspicious(text string) bool {
	lower := strings.ToLower(text)
	for _, kw := range suspiciousKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func applyROT13(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return 'a' + (r-'a'+13)%26
		case r >= 'A' && r <= 'Z':
			return 'A' + (r-'A'+13)%26
		}
		return r
	}, s)
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}

func severityFromConfidence(c float64) string {
	switch {
	case c >= 0.85:
		return "high"
	case c >= 0.6:
		return "medium"
	default:
		return "low"
	}
}
