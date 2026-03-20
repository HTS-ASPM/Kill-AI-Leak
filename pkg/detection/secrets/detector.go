// Package secrets provides a guardrail rule that detects secrets, API keys,
// tokens, and other credentials in prompt text. It combines pattern matching
// with Shannon-entropy analysis for unknown secret formats. Secrets always
// produce a block decision because they cannot be safely anonymized.
package secrets

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
// Secret pattern definitions
// ---------------------------------------------------------------------------

type secretPattern struct {
	label    string
	severity string // "critical", "high", "medium"
	re       *regexp.Regexp
}

var (
	secretPatterns     []secretPattern
	secretPatternsOnce sync.Once
)

func initSecretPatterns() {
	secretPatternsOnce.Do(func() {
		secretPatterns = []secretPattern{
			// AWS Access Key ID
			{
				label:    "aws_access_key",
				severity: "critical",
				re:       regexp.MustCompile(`\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`),
			},
			// AWS Secret Access Key (40-char base64 following common assignment patterns)
			{
				label:    "aws_secret_key",
				severity: "critical",
				re:       regexp.MustCompile(`(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?`),
			},
			// GitHub personal access tokens (classic & fine-grained)
			{
				label:    "github_token",
				severity: "critical",
				re:       regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}\b`),
			},
			// OpenAI API keys
			{
				label:    "openai_key",
				severity: "critical",
				re:       regexp.MustCompile(`\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`),
			},
			// OpenAI project keys (newer format)
			{
				label:    "openai_key",
				severity: "critical",
				re:       regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_-]{40,200}\b`),
			},
			// Anthropic API keys
			{
				label:    "anthropic_key",
				severity: "critical",
				re:       regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{40,200}\b`),
			},
			// Slack bot tokens
			{
				label:    "slack_token",
				severity: "high",
				re:       regexp.MustCompile(`\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,34}\b`),
			},
			// Slack user tokens
			{
				label:    "slack_token",
				severity: "high",
				re:       regexp.MustCompile(`\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b`),
			},
			// Slack webhook URLs
			{
				label:    "slack_token",
				severity: "high",
				re:       regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}`),
			},
			// PEM-encoded private keys
			{
				label:    "private_key",
				severity: "critical",
				re:       regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`),
			},
			// Generic password assignments in config/code
			{
				label:    "password",
				severity: "high",
				re:       regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[=:]\s*["']([^"'\s]{8,})["']`),
			},
			// Password in URLs
			{
				label:    "password",
				severity: "high",
				re:       regexp.MustCompile(`(?i)://[^:]+:([^@\s]{8,})@`),
			},
			// Connection strings (database URIs with credentials)
			{
				label:    "connection_string",
				severity: "critical",
				re:       regexp.MustCompile(`(?i)(?:mongodb|postgres(?:ql)?|mysql|redis|amqp|mssql)://[^\s]+:[^\s]+@[^\s]+`),
			},
			// JDBC connection strings
			{
				label:    "connection_string",
				severity: "critical",
				re:       regexp.MustCompile(`(?i)jdbc:[a-z]+://[^\s]+;(?:user|password)=[^\s;]+`),
			},
			// Bearer tokens in auth headers
			{
				label:    "bearer_token",
				severity: "high",
				re:       regexp.MustCompile(`(?i)(?:authorization|bearer)\s*[:=]\s*["']?Bearer\s+[A-Za-z0-9_\-.~+/]+=*["']?`),
			},
			// Generic API key assignments
			{
				label:    "api_key",
				severity: "high",
				re:       regexp.MustCompile(`(?i)(?:api_key|apikey|api[-_]secret)\s*[=:]\s*["']?([A-Za-z0-9_\-]{20,})["']?`),
			},
		}
	})
}

// ---------------------------------------------------------------------------
// Detector implements guardrails.Rule
// ---------------------------------------------------------------------------

// Detector scans prompt text for secrets and high-entropy strings.
type Detector struct {
	mu  sync.RWMutex
	cfg detectorConfig
}

type detectorConfig struct {
	// entropyThreshold is the minimum Shannon entropy (in bits per
	// character) for a string to be flagged as a potential secret.
	entropyThreshold float64
	// minEntropyLength is the minimum length for entropy analysis to apply.
	minEntropyLength int
	// disableEntropy turns off entropy-based scanning.
	disableEntropy bool
}

// New creates a new secrets Detector with sensible defaults.
func New() *Detector {
	return &Detector{
		cfg: detectorConfig{
			entropyThreshold: 4.5,
			minEntropyLength: 20,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (d *Detector) ID() string                    { return "GR-012" }
func (d *Detector) Name() string                  { return "Secrets Detection" }
func (d *Detector) Stage() models.GuardrailStage  { return models.StageInput }
func (d *Detector) Category() models.RuleCategory { return models.CategorySecrets }

// Evaluate scans the prompt text for known secret patterns and high-entropy
// strings. Any match results in a block decision.
func (d *Detector) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	initSecretPatterns()

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

	// --- Layer 1: pattern-based detection ---
	seen := make(map[string]bool) // dedup by "label:start:end"
	for _, sp := range secretPatterns {
		matches := sp.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			key := fmt.Sprintf("%s:%d:%d", sp.label, loc[0], loc[1])
			if seen[key] {
				continue
			}
			seen[key] = true
			findings = append(findings, models.Finding{
				Type:       sp.label,
				Value:      redactSecret(text[loc[0]:loc[1]]),
				Location:   fmt.Sprintf("position %d-%d", loc[0], loc[1]),
				Severity:   sp.severity,
				Confidence: 0.97,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
		}
	}

	// --- Layer 2: entropy-based detection for unknown formats ---
	if !cfg.disableEntropy {
		entropyFindings := d.scanEntropy(text, cfg, seen)
		findings = append(findings, entropyFindings...)
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
		eval.Reason = "no secrets detected"
	} else {
		// Secrets always block -- they cannot be safely anonymized.
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("detected %d secret(s) in input", len(findings))
	}

	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration from the rule config map.
// Supported keys:
//   - "entropy_threshold" (float64): minimum Shannon entropy.
//   - "min_entropy_length" (int/float64): minimum token length for entropy scan.
//   - "disable_entropy" (bool): turn off entropy scanning entirely.
func (d *Detector) Configure(cfg map[string]any) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if v, ok := cfg["entropy_threshold"]; ok {
		if f, ok := v.(float64); ok {
			if f < 0 || f > 8 {
				return fmt.Errorf("secrets: entropy_threshold must be between 0 and 8, got %f", f)
			}
			d.cfg.entropyThreshold = f
		}
	}

	if v, ok := cfg["min_entropy_length"]; ok {
		switch n := v.(type) {
		case float64:
			d.cfg.minEntropyLength = int(n)
		case int:
			d.cfg.minEntropyLength = n
		}
	}

	if v, ok := cfg["disable_entropy"]; ok {
		if b, ok := v.(bool); ok {
			d.cfg.disableEntropy = b
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Entropy analysis
// ---------------------------------------------------------------------------

// scanEntropy tokenizes the text and checks each word-like token for
// Shannon entropy above the configured threshold. Tokens that overlap
// with pattern-based findings (via the seen map) are skipped.
func (d *Detector) scanEntropy(text string, cfg detectorConfig, seen map[string]bool) []models.Finding {
	var findings []models.Finding
	tokens := tokenize(text)

	for _, tok := range tokens {
		if len(tok.value) < cfg.minEntropyLength {
			continue
		}
		// Skip if this region was already matched by a pattern.
		if isOverlapping(tok.start, tok.end, seen) {
			continue
		}
		entropy := shannonEntropy(tok.value)
		if entropy > cfg.entropyThreshold {
			findings = append(findings, models.Finding{
				Type:       "high_entropy_string",
				Value:      redactSecret(tok.value),
				Location:   fmt.Sprintf("position %d-%d", tok.start, tok.end),
				Severity:   "medium",
				Confidence: normalizeEntropy(entropy),
				StartPos:   tok.start,
				EndPos:     tok.end,
			})
		}
	}
	return findings
}

type token struct {
	value string
	start int
	end   int
}

// tokenize splits text into contiguous runs of non-whitespace characters,
// preserving their positions. This is intentionally simple: we want tokens
// that look like keys, hashes, and encoded blobs.
func tokenize(text string) []token {
	var tokens []token
	inToken := false
	start := 0

	for i, r := range text {
		isWS := unicode.IsSpace(r)
		if !isWS && !inToken {
			inToken = true
			start = i
		} else if isWS && inToken {
			inToken = false
			tokens = append(tokens, token{
				value: text[start:i],
				start: start,
				end:   i,
			})
		}
	}
	if inToken {
		tokens = append(tokens, token{
			value: text[start:],
			start: start,
			end:   len(text),
		})
	}
	return tokens
}

// shannonEntropy computes the Shannon entropy of s in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))
	var entropy float64
	for _, count := range freq {
		p := count / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// normalizeEntropy maps entropy to a 0-1 confidence score. An entropy of
// 4.5 maps to ~0.7; 6.0+ maps to ~0.95.
func normalizeEntropy(e float64) float64 {
	// Sigmoid-like mapping centred around 5.0
	c := 1.0 / (1.0 + math.Exp(-2*(e-5.0)))
	if c > 0.99 {
		c = 0.99
	}
	return c
}

// isOverlapping checks whether the range [start, end) overlaps with any
// finding already recorded in the seen map. The seen map stores keys in
// the format "label:start:end".
func isOverlapping(start, end int, seen map[string]bool) bool {
	for key := range seen {
		// parse start and end from key
		var label string
		var s, e int
		if _, err := fmt.Sscanf(key, "%s", &label); err != nil {
			continue
		}
		parts := strings.SplitN(key, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if _, err := fmt.Sscan(parts[1], &s); err != nil {
			continue
		}
		if _, err := fmt.Sscan(parts[2], &e); err != nil {
			continue
		}
		if start < e && end > s {
			return true
		}
	}
	return false
}

// redactSecret shows only the first 4 and last 2 characters of a secret,
// replacing the middle with asterisks. Values shorter than 8 characters
// are fully masked.
func redactSecret(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-6) + s[len(s)-2:]
}
