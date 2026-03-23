// Package insecurecode provides guardrail rules for output code safety:
// GR-037 Generated Code Vulnerability Scan and GR-038 Insecure Code Pattern Detection.
package insecurecode

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/guardrails"
	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// Fenced code block extraction.
var fencedBlockRe = regexp.MustCompile("(?s)(?:```|~~~)([a-zA-Z0-9_+-]*)\\n(.*?)(?:```|~~~)")

// ---------------------------------------------------------------------------
// GR-037: Generated Code Vulnerability Scan
// ---------------------------------------------------------------------------

type vulnPattern struct {
	category string
	label    string
	severity string
	re       *regexp.Regexp
}

var vulnPatterns = []vulnPattern{
	{"sql_injection", "string_concat_sql", "critical", regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*["']\s*\+\s*\w+`)},
	{"sql_injection", "format_sql", "critical", regexp.MustCompile(`(?i)(?:f["'](?:SELECT|INSERT|UPDATE|DELETE)\s|\.format\s*\(.*(?:SELECT|INSERT))`)},
	{"xss", "inner_html", "high", regexp.MustCompile(`(?i)\.innerHTML\s*=`)},
	{"xss", "document_write", "high", regexp.MustCompile(`(?i)document\.write(?:ln)?\s*\(`)},
	{"path_traversal", "unsanitized_path", "high", regexp.MustCompile(`(?i)(?:open|readFile)\s*\(\s*(?:req\.|request\.|params\.)`)},
	{"command_injection", "os_exec", "critical", regexp.MustCompile(`(?i)(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|exec\.Command)\s*\(`)},
	{"insecure_deserialization", "pickle", "critical", regexp.MustCompile(`(?i)pickle\.(?:loads?|Unpickler)\s*\(`)},
}

// VulnScanRule implements guardrails.Rule for GR-037.
type VulnScanRule struct {
	mu  sync.RWMutex
	cfg vulnScanConfig
}

type vulnScanConfig struct {
	blockOnCritical bool
}

// NewVulnScan creates a GR-037 rule.
func NewVulnScan() *VulnScanRule {
	return &VulnScanRule{cfg: vulnScanConfig{blockOnCritical: false}}
}

func (r *VulnScanRule) ID() string                    { return "GR-037" }
func (r *VulnScanRule) Name() string                  { return "Generated Code Vulnerability Scan" }
func (r *VulnScanRule) Stage() models.GuardrailStage  { return models.StageOutput }
func (r *VulnScanRule) Category() models.RuleCategory { return models.CategoryCodeSafety }

func (r *VulnScanRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
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

	blocks := extractCodeBlocks(text)
	if len(blocks) == 0 {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no code blocks in response"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	hasCritical := false

	for _, block := range blocks {
		for _, vp := range vulnPatterns {
			if vp.re.MatchString(block.code) {
				findings = append(findings, models.Finding{
					Type:       vp.category + ":" + vp.label,
					Value:      truncate(vp.re.FindString(block.code), 120),
					Severity:   vp.severity,
					Confidence: confidenceForSeverity(vp.severity),
				})
				if vp.severity == "critical" {
					hasCritical = true
				}
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = highestConfidence(findings)

	if hasCritical && cfg.blockOnCritical {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("critical vulnerabilities in generated code; %d finding(s)", len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("vulnerabilities detected in generated code; %d finding(s)", len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no vulnerabilities in %d code block(s)", len(blocks))
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *VulnScanRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["block_on_critical"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.blockOnCritical = b
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// GR-038: Insecure Code Pattern Detection
// ---------------------------------------------------------------------------

type insecurePattern struct {
	label    string
	severity string
	re       *regexp.Regexp
}

var insecurePatterns = []insecurePattern{
	{"hardcoded_credentials", "critical", regexp.MustCompile(`(?i)(?:password|passwd|secret|api_?key)\s*[:=]\s*["'][^"'\s]{8,}["']`)},
	{"weak_crypto_md5", "medium", regexp.MustCompile(`(?i)(?:md5|MD5)\s*[\.(]`)},
	{"weak_crypto_sha1", "medium", regexp.MustCompile(`(?i)(?:sha1|SHA1)\s*[\.(]`)},
	{"disabled_tls", "high", regexp.MustCompile(`(?i)(?:InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|VERIFY_NONE|NODE_TLS_REJECT_UNAUTHORIZED.*0)`)},
	{"eval_usage", "high", regexp.MustCompile(`(?i)\beval\s*\(\s*(?:req\.|request\.|input|user|data)`)},
	{"unsafe_deserialization", "critical", regexp.MustCompile(`(?i)(?:pickle\.loads?|yaml\.unsafe_load|ObjectInputStream)\s*\(`)},
	{"weak_random", "medium", regexp.MustCompile(`(?i)(?:math\.random|Math\.random\(\)|random\.random\(\)|rand\.Intn)\s*`)},
	{"hardcoded_private_key", "critical", regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----`)},
}

// InsecurePatternRule implements guardrails.Rule for GR-038.
type InsecurePatternRule struct {
	mu  sync.RWMutex
	cfg insecurePatternConfig
}

type insecurePatternConfig struct {
	blockOnCritical bool
}

// NewInsecurePattern creates a GR-038 rule.
func NewInsecurePattern() *InsecurePatternRule {
	return &InsecurePatternRule{cfg: insecurePatternConfig{blockOnCritical: false}}
}

func (r *InsecurePatternRule) ID() string                    { return "GR-038" }
func (r *InsecurePatternRule) Name() string                  { return "Insecure Code Pattern Detection" }
func (r *InsecurePatternRule) Stage() models.GuardrailStage  { return models.StageOutput }
func (r *InsecurePatternRule) Category() models.RuleCategory { return models.CategoryCodeSafety }

func (r *InsecurePatternRule) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
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

	blocks := extractCodeBlocks(text)
	if len(blocks) == 0 {
		eval.Decision = models.DecisionAllow
		eval.Confidence = 0
		eval.Reason = "no code blocks in response"
		eval.LatencyMs = time.Since(start).Milliseconds()
		return eval, nil
	}

	var findings []models.Finding
	hasCritical := false

	for _, block := range blocks {
		for _, ip := range insecurePatterns {
			if ip.re.MatchString(block.code) {
				findings = append(findings, models.Finding{
					Type:       "insecure:" + ip.label,
					Value:      truncate(ip.re.FindString(block.code), 120),
					Severity:   ip.severity,
					Confidence: confidenceForSeverity(ip.severity),
				})
				if ip.severity == "critical" {
					hasCritical = true
				}
			}
		}
	}

	eval.Findings = findings
	eval.Confidence = highestConfidence(findings)

	if hasCritical && cfg.blockOnCritical {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("critical insecure patterns in generated code; %d finding(s)", len(findings))
	} else if len(findings) > 0 {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("insecure code patterns detected; %d finding(s)", len(findings))
	} else {
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("no insecure patterns in %d code block(s)", len(blocks))
	}

	eval.LatencyMs = time.Since(start).Milliseconds()
	return eval, nil
}

func (r *InsecurePatternRule) Configure(cfg map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if v, ok := cfg["block_on_critical"]; ok {
		if b, ok := v.(bool); ok {
			r.cfg.blockOnCritical = b
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type codeBlock struct {
	lang string
	code string
}

func extractCodeBlocks(text string) []codeBlock {
	var blocks []codeBlock
	matches := fencedBlockRe.FindAllStringSubmatch(text, -1)
	for _, m := range matches {
		if len(m) < 3 {
			continue
		}
		blocks = append(blocks, codeBlock{
			lang: strings.ToLower(m[1]),
			code: m[2],
		})
	}
	return blocks
}

func confidenceForSeverity(severity string) float64 {
	switch severity {
	case "critical":
		return 0.95
	case "high":
		return 0.85
	case "medium":
		return 0.70
	default:
		return 0.50
	}
}

func highestConfidence(findings []models.Finding) float64 {
	m := 0.0
	for _, f := range findings {
		if f.Confidence > m {
			m = f.Confidence
		}
	}
	return m
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
