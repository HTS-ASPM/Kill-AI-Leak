// Package watermark provides a guardrail rule (GR-045) that injects invisible
// watermarks into LLM responses using Unicode zero-width characters for
// provenance tracking and leak detection.
package watermark

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Zero-width Unicode characters for steganography.
const (
	zwsp = '\u200B' // zero-width space (bit 0)
	zwnj = '\u200C' // zero-width non-joiner (bit 1)
	zwj  = '\u200D' // zero-width joiner (separator)
)

// Rule implements guardrails.Rule for GR-045 Watermark Injection.
type Rule struct {
	mu  sync.RWMutex
	cfg ruleConfig
}

type ruleConfig struct {
	method           string
	includeTimestamp bool
	includeActorID  bool
}

// New creates a new watermark injection rule.
func New() *Rule {
	return &Rule{
		cfg: ruleConfig{
			method:           "unicode_steganography",
			includeTimestamp: true,
			includeActorID:  true,
		},
	}
}

func (r *Rule) ID() string                    { return "GR-045" }
func (r *Rule) Name() string                  { return "Watermark Injection" }
func (r *Rule) Stage() models.GuardrailStage  { return models.StageOutput }
func (r *Rule) Category() models.RuleCategory { return models.CategoryCompliance }

// Evaluate generates a watermark payload and stores it in metadata for
// downstream injection into the response.
func (r *Rule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID: r.ID(), RuleName: r.Name(), Stage: r.Stage(),
	}

	if ctx.ResponseText == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no response text to watermark"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Build watermark payload.
	var payload strings.Builder
	if cfg.includeTimestamp {
		payload.WriteString(fmt.Sprintf("t=%d;", time.Now().Unix()))
	}
	if cfg.includeActorID && ctx.Actor != nil {
		payload.WriteString(fmt.Sprintf("a=%s;", ctx.Actor.ID))
	}
	if ctx.SessionID != "" {
		payload.WriteString(fmt.Sprintf("s=%s;", ctx.SessionID))
	}

	payloadStr := payload.String()
	if payloadStr == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "empty watermark payload"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	// Create a short hash for compact encoding.
	hash := sha256.Sum256([]byte(payloadStr))
	hashHex := fmt.Sprintf("%x", hash[:8])

	// Encode the hash as zero-width characters.
	encoded := encodeZeroWidth(hashHex)

	// Store watermark in metadata for the response modifier to inject.
	ctx.SetMetadata("watermark_encoded", encoded)
	ctx.SetMetadata("watermark_hash", hashHex)

	eval.Decision = models.DecisionModify
	eval.Confidence = 1.0
	eval.Reason = fmt.Sprintf("watermark generated (method=%s, hash=%s)", cfg.method, hashHex)
	eval.Findings = []models.Finding{{
		Type: "watermark", Value: hashHex,
		Severity: "info", Confidence: 1.0,
	}}
	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *Rule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["method"]; ok {
		if s, ok := v.(string); ok {
			r.cfg.method = s
		}
	}
	if v, ok := cfg["include_timestamp"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.includeTimestamp = b
		}
	}
	if v, ok := cfg["include_actor_id"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.includeActorID = b
		}
	}
	return nil
}

// encodeZeroWidth encodes a hex string as zero-width Unicode characters.
// Each hex digit is encoded as 4 zero-width characters (bits), separated
// by ZWJ characters between digits.
func encodeZeroWidth(hex string) string {
	var sb strings.Builder
	for i, ch := range hex {
		if i > 0 {
			sb.WriteRune(zwj)
		}
		var nibble int
		switch {
		case ch >= '0' && ch <= '9':
			nibble = int(ch - '0')
		case ch >= 'a' && ch <= 'f':
			nibble = int(ch-'a') + 10
		default:
			continue
		}
		for bit := 3; bit >= 0; bit-- {
			if nibble&(1<<uint(bit)) != 0 {
				sb.WriteRune(zwnj)
			} else {
				sb.WriteRune(zwsp)
			}
		}
	}
	return sb.String()
}
