// Package codeleak provides a guardrail rule (GR-021) that detects and blocks
// proprietary source code from being sent as prompt context, and a system prompt
// protection rule (GR-020) that detects attempts to extract the system prompt.
package codeleak

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
// GR-020: System Prompt Protection
// ---------------------------------------------------------------------------

// Patterns for system prompt extraction attempts.
var extractionPatterns = []struct {
	label  string
	weight float64
	re     *regexp.Regexp
}{
	{"repeat_instructions", 0.90, regexp.MustCompile(`(?i)repeat\s+(?:your|the|all)\s+(?:instructions?|system\s*prompt|initial\s*prompt|rules)`)},
	{"reveal_instructions", 0.90, regexp.MustCompile(`(?i)(?:reveal|show|display|print|output|tell\s+me)\s+(?:your|the)\s+(?:system\s*prompt|instructions?|rules|guidelines)`)},
	{"ignore_instructions", 0.85, regexp.MustCompile(`(?i)ignore\s+(?:all\s+)?(?:previous|above|prior)\s+(?:instructions?|rules|guidelines)`)},
	{"what_instructions", 0.80, regexp.MustCompile(`(?i)what\s+(?:are|were)\s+(?:your|the)\s+(?:instructions?|system\s*prompt|guidelines|rules)`)},
	{"copy_prompt", 0.85, regexp.MustCompile(`(?i)(?:copy|paste|dump|leak|extract)\s+(?:your|the|system)\s+(?:prompt|instructions?)`)},
	{"override_system", 0.90, regexp.MustCompile(`(?i)(?:override|bypass|disable|turn\s+off)\s+(?:your|the|system)\s+(?:prompt|instructions?|restrictions?)`)},
	{"new_system_prompt", 0.85, regexp.MustCompile(`(?i)(?:new|updated?)\s+system\s*prompt\s*:`)},
	{"developer_mode", 0.80, regexp.MustCompile(`(?i)(?:developer|maintenance|debug|admin)\s+mode`)},
}

// SystemPromptRule implements guardrails.Rule for GR-020 System Prompt Protection.
type SystemPromptRule struct {
	mu  sync.RWMutex
	cfg systemPromptConfig
}

type systemPromptConfig struct {
	protectSystemPrompt       bool
	detectExtractionAttempts  bool
	blockThreshold            float64
}

// NewSystemPrompt creates a new system prompt protection rule.
func NewSystemPrompt() *SystemPromptRule {
	return &SystemPromptRule{
		cfg: systemPromptConfig{
			protectSystemPrompt:      true,
			detectExtractionAttempts: true,
			blockThreshold:           0.80,
		},
	}
}

func (r *SystemPromptRule) ID() string                    { return "GR-020" }
func (r *SystemPromptRule) Name() string                  { return "System Prompt Protection" }
func (r *SystemPromptRule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *SystemPromptRule) Category() models.RuleCategory { return models.CategoryInjection }

// Evaluate detects attempts to extract or override the system prompt.
func (r *SystemPromptRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()

	r.mu.RLock()
	cfg := r.cfg
	r.mu.RUnlock()

	eval := &models.GuardrailEvaluation{
		RuleID:   r.ID(),
		RuleName: r.Name(),
		Stage:    r.Stage(),
	}

	if !cfg.protectSystemPrompt || !cfg.detectExtractionAttempts {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "system prompt protection disabled"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	text := ctx.PromptText
	if text == "" {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no prompt text"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	maxConfidence := 0.0

	for _, pat := range extractionPatterns {
		matches := pat.re.FindAllStringIndex(text, -1)
		for _, loc := range matches {
			findings = append(findings, models.Finding{
				Type:       "extraction_attempt:" + pat.label,
				Value:      truncate(text[loc[0]:loc[1]], 100),
				Severity:   severityFromWeight(pat.weight),
				Confidence: pat.weight,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if pat.weight > maxConfidence {
				maxConfidence = pat.weight
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if maxConfidence >= cfg.blockThreshold {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("system prompt extraction attempt detected (confidence=%.2f)", maxConfidence)
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("possible system prompt extraction (confidence=%.2f)", maxConfidence)
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no extraction attempts detected"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *SystemPromptRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["protect_system_prompt"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.protectSystemPrompt = b
		}
	}
	if v, ok := cfg["detect_extraction_attempts"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.detectExtractionAttempts = b
		}
	}
	if v, ok := cfg["block_threshold"]; ok {
		if f, ok := v.(float64); ok {
			r.cfg.blockThreshold = f
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-021: Source Code Leak Prevention
// ---------------------------------------------------------------------------

// Indicators of proprietary/internal source code.
var (
	// Internal repo patterns (paths, import statements).
	internalRepoRe = regexp.MustCompile(`(?i)(?:` +
		`(?:import|from|require)\s+["'](?:@internal|@company|@private)/` +
		`|(?:git@|https?://)(?:gitlab\.internal|bitbucket\.corp|github\.enterprise)` +
		`|(?:package\s+com\.(?:internal|corp|company))` +
		`|(?://\s*Copyright\s+\d{4}\s+(?:Internal|Confidential|Proprietary))` +
		`)`)

	// Code block detection for counting lines.
	fencedBlockRe = regexp.MustCompile("(?s)(?:```|~~~)[a-zA-Z0-9_+-]*\\n(.*?)(?:```|~~~)")

	// Proprietary file markers.
	proprietaryMarkers = []string{
		"confidential", "proprietary", "internal use only",
		"do not distribute", "trade secret", "company confidential",
		"all rights reserved", "not for public release",
	}
)

// SourceCodeRule implements guardrails.Rule for GR-021 Source Code Leak Prevention.
type SourceCodeRule struct {
	mu  sync.RWMutex
	cfg sourceCodeConfig
}

type sourceCodeConfig struct {
	detectCodeBlocks    bool
	maxCodeLines        int
	blockIfInternalRepo bool
}

// NewSourceCode creates a new source code leak prevention rule.
func NewSourceCode() *SourceCodeRule {
	return &SourceCodeRule{
		cfg: sourceCodeConfig{
			detectCodeBlocks:    true,
			maxCodeLines:        500,
			blockIfInternalRepo: true,
		},
	}
}

func (r *SourceCodeRule) ID() string                    { return "GR-021" }
func (r *SourceCodeRule) Name() string                  { return "Source Code Leak Prevention" }
func (r *SourceCodeRule) Stage() models.GuardrailStage  { return models.StageInput }
func (r *SourceCodeRule) Category() models.RuleCategory { return models.CategoryExfiltration }

// Evaluate detects proprietary source code in prompts.
func (r *SourceCodeRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
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
		eval.Reason = "no prompt text"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	maxConfidence := 0.0

	// Check for internal repo references.
	if cfg.blockIfInternalRepo {
		matches := internalRepoRe.FindAllStringIndex(text, 5)
		for _, loc := range matches {
			confidence := 0.9
			findings = append(findings, models.Finding{
				Type:       "internal_repo_reference",
				Value:      truncate(text[loc[0]:loc[1]], 100),
				Severity:   "high",
				Confidence: confidence,
				StartPos:   loc[0],
				EndPos:     loc[1],
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	// Check for proprietary markers.
	lower := strings.ToLower(text)
	for _, marker := range proprietaryMarkers {
		if strings.Contains(lower, marker) {
			confidence := 0.8
			findings = append(findings, models.Finding{
				Type:       "proprietary_marker",
				Value:      marker,
				Severity:   "high",
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	// Count code lines in fenced blocks.
	if cfg.detectCodeBlocks {
		totalCodeLines := 0
		blockMatches := fencedBlockRe.FindAllStringSubmatch(text, -1)
		for _, m := range blockMatches {
			if len(m) > 1 {
				lines := strings.Count(m[1], "\n") + 1
				totalCodeLines += lines
			}
		}
		if totalCodeLines > cfg.maxCodeLines {
			confidence := 0.85
			findings = append(findings, models.Finding{
				Type:       "excessive_code",
				Value:      fmt.Sprintf("%d lines (limit %d)", totalCodeLines, cfg.maxCodeLines),
				Severity:   "high",
				Confidence: confidence,
			})
			if confidence > maxConfidence {
				maxConfidence = confidence
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = maxConfidence

	if maxConfidence >= 0.8 {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("potential source code leak detected (confidence=%.2f); %d finding(s)",
			maxConfidence, len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("possible source code in prompt (confidence=%.2f); %d finding(s)",
			maxConfidence, len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = "no source code leak indicators detected"
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

// Configure applies dynamic configuration.
func (r *SourceCodeRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["detect_code_blocks"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.detectCodeBlocks = b
		}
	}
	if v, ok := cfg["max_code_lines"]; ok {
		switch n := v.(type) {
		case float64:
			r.cfg.maxCodeLines = int(n)
		case int:
			r.cfg.maxCodeLines = n
		}
	}
	if v, ok := cfg["block_if_internal_repo"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.blockIfInternalRepo = b
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
