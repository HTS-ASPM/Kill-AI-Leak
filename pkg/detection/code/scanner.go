// Package code provides a guardrail rule that scans LLM-generated code in
// responses for common vulnerability patterns: SQL injection, command
// injection, path traversal, XSS, hardcoded secrets, insecure cryptography,
// and unsafe deserialization.
package code

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
// Code block extraction
// ---------------------------------------------------------------------------

// codeBlockRe matches fenced code blocks (```lang ... ```) or indented
// blocks (four-space / tab prefix). The lang group is optional.
var (
	fencedBlockRe *regexp.Regexp
	fencedOnce    sync.Once
)

func initFenced() {
	fencedOnce.Do(func() {
		// Matches ```<optional lang>\n...\n``` including ~~~ variant.
		fencedBlockRe = regexp.MustCompile("(?s)(?:```|~~~)([a-zA-Z0-9_+-]*)\\n(.*?)(?:```|~~~)")
	})
}

type codeBlock struct {
	lang     string
	code     string
	startPos int
	endPos   int
}

// extractCodeBlocks finds fenced code blocks in the text.
func extractCodeBlocks(text string) []codeBlock {
	initFenced()
	var blocks []codeBlock

	matches := fencedBlockRe.FindAllStringSubmatchIndex(text, -1)
	for _, m := range matches {
		if len(m) < 6 {
			continue
		}
		lang := ""
		if m[2] >= 0 && m[3] >= 0 {
			lang = text[m[2]:m[3]]
		}
		code := ""
		if m[4] >= 0 && m[5] >= 0 {
			code = text[m[4]:m[5]]
		}
		blocks = append(blocks, codeBlock{
			lang:     strings.ToLower(lang),
			code:     code,
			startPos: m[0],
			endPos:   m[1],
		})
	}

	return blocks
}

// ---------------------------------------------------------------------------
// Vulnerability patterns
// ---------------------------------------------------------------------------

// vulnCategory groups vulnerability types.
type vulnCategory string

const (
	vulnSQLInjection    vulnCategory = "sql_injection"
	vulnCommandInjection vulnCategory = "command_injection"
	vulnPathTraversal    vulnCategory = "path_traversal"
	vulnXSS             vulnCategory = "xss"
	vulnHardcodedSecret  vulnCategory = "hardcoded_secret"
	vulnInsecureCrypto   vulnCategory = "insecure_crypto"
	vulnDeserialization  vulnCategory = "deserialization"
)

type vulnPattern struct {
	category    vulnCategory
	label       string
	severity    string // "critical", "high", "medium"
	description string
	re          *regexp.Regexp
	// languages restricts matching to specific code block languages.
	// Empty means match any.
	languages []string
}

var (
	vulnPatterns     []vulnPattern
	vulnPatternsOnce sync.Once
)

func initVulnPatterns() {
	vulnPatternsOnce.Do(func() {
		vulnPatterns = []vulnPattern{
			// ---- SQL Injection ----
			{
				category:    vulnSQLInjection,
				label:       "string_concat_sql",
				severity:    "critical",
				description: "SQL query built via string concatenation with user input",
				re:          regexp.MustCompile(`(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|EXEC)\s+.*[+"']\s*\+\s*\w+`),
			},
			{
				category:    vulnSQLInjection,
				label:       "format_string_sql",
				severity:    "critical",
				description: "SQL query built via format string with user input",
				re:          regexp.MustCompile(`(?i)(?:f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s|\.format\s*\(.*(?:SELECT|INSERT|UPDATE|DELETE|DROP))`),
			},
			{
				category:    vulnSQLInjection,
				label:       "sprintf_sql",
				severity:    "critical",
				description: "SQL query built via sprintf/Sprintf",
				re:          regexp.MustCompile(`(?i)(?:fmt\.Sprintf|sprintf|String\.format)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)`),
			},
			{
				category:    vulnSQLInjection,
				label:       "raw_query_interpolation",
				severity:    "high",
				description: "Raw SQL with variable interpolation",
				re:          regexp.MustCompile(`(?i)(?:execute|query|exec)\s*\(\s*["'](?:SELECT|INSERT|UPDATE|DELETE)\s.*\$\{?\w+`),
			},

			// ---- Command Injection ----
			{
				category:    vulnCommandInjection,
				label:       "os_system_call",
				severity:    "critical",
				description: "Command execution with user-controlled input",
				re:          regexp.MustCompile(`(?i)(?:os\.system|os\.popen|subprocess\.(?:call|run|Popen)|exec\.Command|Runtime\.(?:getRuntime\(\)\.)?exec)\s*\(`),
			},
			{
				category:    vulnCommandInjection,
				label:       "shell_exec",
				severity:    "critical",
				description: "Shell command execution via eval/exec/backtick",
				re:          regexp.MustCompile("(?i)(?:eval|exec)\\s*\\(|`[^`]*\\$(?:\\{|\\()"),
			},
			{
				category:    vulnCommandInjection,
				label:       "child_process",
				severity:    "high",
				description: "Node.js child process execution",
				re:          regexp.MustCompile(`(?i)(?:child_process|shelljs).*(?:exec|spawn)\s*\(`),
				languages:   []string{"javascript", "js", "typescript", "ts"},
			},

			// ---- Path Traversal ----
			{
				category:    vulnPathTraversal,
				label:       "path_traversal_input",
				severity:    "high",
				description: "File path built from user input without sanitization",
				re:          regexp.MustCompile(`(?i)(?:open|readFile|writeFile|readFileSync|writeFileSync|os\.(?:Open|Create|ReadFile|WriteFile))\s*\(\s*(?:req\.|request\.|params\.|user_?input|filename)`),
			},
			{
				category:    vulnPathTraversal,
				label:       "path_join_unsanitized",
				severity:    "high",
				description: "Path join with unsanitized user input",
				re:          regexp.MustCompile(`(?i)(?:path\.(?:join|resolve)|os\.path\.join|Path\.Combine)\s*\(.*(?:req\.|request\.|params\.|user|input)`),
			},
			{
				category:    vulnPathTraversal,
				label:       "dot_dot_pattern",
				severity:    "medium",
				description: "Literal ../ path traversal pattern in code",
				re:          regexp.MustCompile(`(?:\.\.\/|\.\.\\\\)`),
			},

			// ---- XSS ----
			{
				category:    vulnXSS,
				label:       "inner_html",
				severity:    "high",
				description: "Setting innerHTML with potentially unsanitized content",
				re:          regexp.MustCompile(`(?i)\.innerHTML\s*=`),
			},
			{
				category:    vulnXSS,
				label:       "document_write",
				severity:    "high",
				description: "document.write with potentially unsanitized content",
				re:          regexp.MustCompile(`(?i)document\.write(?:ln)?\s*\(`),
			},
			{
				category:    vulnXSS,
				label:       "dangerously_set_html",
				severity:    "high",
				description: "React dangerouslySetInnerHTML usage",
				re:          regexp.MustCompile(`(?i)dangerouslySetInnerHTML\s*=\s*\{`),
				languages:   []string{"javascript", "js", "jsx", "typescript", "ts", "tsx"},
			},
			{
				category:    vulnXSS,
				label:       "template_unescaped",
				severity:    "high",
				description: "Unescaped template variable output",
				re:          regexp.MustCompile(`\{\{!?\{.*?\}\}?\}|<%=\s*.*?\s*%>|v-html\s*=`),
			},
			{
				category:    vulnXSS,
				label:       "jquery_html",
				severity:    "high",
				description: "jQuery .html() with potentially unsanitized content",
				re:          regexp.MustCompile(`(?i)\$\s*\(.*?\)\s*\.html\s*\(`),
			},

			// ---- Hardcoded Secrets ----
			{
				category:    vulnHardcodedSecret,
				label:       "hardcoded_password",
				severity:    "critical",
				description: "Hardcoded password in source code",
				re:          regexp.MustCompile(`(?i)(?:password|passwd|pwd|secret|api_?key|token|auth)\s*[:=]\s*["'][^"'\s]{8,}["']`),
			},
			{
				category:    vulnHardcodedSecret,
				label:       "hardcoded_aws_key",
				severity:    "critical",
				description: "Hardcoded AWS access key",
				re:          regexp.MustCompile(`\b(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`),
			},
			{
				category:    vulnHardcodedSecret,
				label:       "hardcoded_private_key",
				severity:    "critical",
				description: "Private key embedded in code",
				re:          regexp.MustCompile(`-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----`),
			},
			{
				category:    vulnHardcodedSecret,
				label:       "hardcoded_connection_string",
				severity:    "critical",
				description: "Database connection string with credentials",
				re:          regexp.MustCompile(`(?i)(?:mongodb|postgres(?:ql)?|mysql|redis|amqp)://\w+:\w+@`),
			},

			// ---- Insecure Cryptography ----
			{
				category:    vulnInsecureCrypto,
				label:       "weak_hash_md5",
				severity:    "medium",
				description: "MD5 used for hashing (cryptographically broken)",
				re:          regexp.MustCompile(`(?i)(?:md5|MD5)\s*[\.(]`),
			},
			{
				category:    vulnInsecureCrypto,
				label:       "weak_hash_sha1",
				severity:    "medium",
				description: "SHA1 used for hashing (deprecated for security)",
				re:          regexp.MustCompile(`(?i)(?:sha1|SHA1)\s*[\.(]`),
			},
			{
				category:    vulnInsecureCrypto,
				label:       "ecb_mode",
				severity:    "high",
				description: "ECB cipher mode (insecure, lacks diffusion)",
				re:          regexp.MustCompile(`(?i)(?:ECB|MODE_ECB|AES\.ECB|cipher\.NewECB)`),
			},
			{
				category:    vulnInsecureCrypto,
				label:       "weak_random",
				severity:    "medium",
				description: "Non-cryptographic random used for security purposes",
				re:          regexp.MustCompile(`(?i)(?:math\.random|Math\.random\(\)|random\.random\(\)|rand\.Intn|rand\.Int\(\))\s*`),
			},
			{
				category:    vulnInsecureCrypto,
				label:       "disabled_tls_verify",
				severity:    "high",
				description: "TLS certificate verification disabled",
				re:          regexp.MustCompile(`(?i)(?:InsecureSkipVerify\s*:\s*true|verify\s*=\s*False|VERIFY_NONE|SSL_VERIFY_NONE|NODE_TLS_REJECT_UNAUTHORIZED.*0)`),
			},

			// ---- Deserialization ----
			{
				category:    vulnDeserialization,
				label:       "pickle_load",
				severity:    "critical",
				description: "Python pickle deserialization (arbitrary code execution)",
				re:          regexp.MustCompile(`(?i)pickle\.(?:loads?|Unpickler)\s*\(`),
				languages:   []string{"python", "py"},
			},
			{
				category:    vulnDeserialization,
				label:       "yaml_unsafe_load",
				severity:    "critical",
				description: "YAML unsafe load (arbitrary code execution)",
				re:          regexp.MustCompile(`(?i)yaml\.(?:unsafe_)?load\s*\(`),
				languages:   []string{"python", "py"},
			},
			{
				category:    vulnDeserialization,
				label:       "java_deserialization",
				severity:    "critical",
				description: "Java ObjectInputStream deserialization",
				re:          regexp.MustCompile(`(?i)(?:ObjectInputStream|readObject|XMLDecoder)\s*\(`),
				languages:   []string{"java"},
			},
			{
				category:    vulnDeserialization,
				label:       "json_parse_eval",
				severity:    "high",
				description: "Using eval for JSON parsing instead of JSON.parse",
				re:          regexp.MustCompile(`(?i)eval\s*\(\s*(?:req\.|request\.|body|data|input|response)`),
			},
			{
				category:    vulnDeserialization,
				label:       "unserialize_php",
				severity:    "critical",
				description: "PHP unserialize on user input",
				re:          regexp.MustCompile(`(?i)unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)`),
				languages:   []string{"php"},
			},
		}
	})
}

// ---------------------------------------------------------------------------
// Scanner implements guardrails.Rule
// ---------------------------------------------------------------------------

// Scanner detects code blocks in LLM responses and scans them for known
// vulnerability patterns.
type Scanner struct {
	mu  sync.RWMutex
	cfg scannerConfig
}

type scannerConfig struct {
	// blockOnCritical, if true, blocks the response when a critical
	// finding is detected. Otherwise alerts. Default: true.
	blockOnCritical bool
	// blockOnHigh blocks on high-severity findings too.
	blockOnHigh bool
	// maxFindings caps reported findings. Zero = unlimited.
	maxFindings int
}

// New creates a code Scanner with sensible defaults.
func New() *Scanner {
	return &Scanner{
		cfg: scannerConfig{
			blockOnCritical: true,
			blockOnHigh:     false,
		},
	}
}

// ---------------------------------------------------------------------------
// guardrails.Rule interface
// ---------------------------------------------------------------------------

func (s *Scanner) ID() string                    { return "GR-033" }
func (s *Scanner) Name() string                  { return "Code Vulnerability Scanner" }
func (s *Scanner) Stage() models.GuardrailStage  { return models.StageOutput }
func (s *Scanner) Category() models.RuleCategory { return models.CategoryCodeSafety }

// Evaluate extracts code blocks from the response and scans each block for
// vulnerability patterns.
func (s *Scanner) Evaluate(ctx *guardrails.EvalContext) (*models.GuardrailEvaluation, error) {
	start := time.Now()
	initVulnPatterns()

	text := ctx.ResponseText
	if text == "" {
		return &models.GuardrailEvaluation{
			RuleID:     s.ID(),
			RuleName:   s.Name(),
			Stage:      s.Stage(),
			Decision:   models.DecisionAllow,
			Confidence: 1.0,
			Reason:     "no output text to scan",
			LatencyMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	s.mu.RLock()
	cfg := s.cfg
	s.mu.RUnlock()

	blocks := extractCodeBlocks(text)
	if len(blocks) == 0 {
		return &models.GuardrailEvaluation{
			RuleID:     s.ID(),
			RuleName:   s.Name(),
			Stage:      s.Stage(),
			Decision:   models.DecisionAllow,
			Confidence: 1.0,
			Reason:     "no code blocks detected in output",
			LatencyMs:  time.Since(start).Milliseconds(),
		}, nil
	}

	var findings []models.Finding
	hasCritical := false
	hasHigh := false

	for blockIdx, block := range blocks {
		for _, vp := range vulnPatterns {
			// Apply language filter.
			if len(vp.languages) > 0 && !languageMatch(block.lang, vp.languages) {
				continue
			}

			matches := vp.re.FindAllStringIndex(block.code, -1)
			for _, loc := range matches {
				snippet := truncate(block.code[loc[0]:loc[1]], 120)
				// Translate the position to be relative to the overall
				// response text.
				absStart := block.startPos + loc[0]
				absEnd := block.startPos + loc[1]

				findings = append(findings, models.Finding{
					Type:       string(vp.category) + ":" + vp.label,
					Value:      snippet,
					Location:   fmt.Sprintf("code_block[%d] position %d-%d", blockIdx, absStart, absEnd),
					Severity:   vp.severity,
					Confidence: confidenceForSeverity(vp.severity),
					StartPos:   absStart,
					EndPos:     absEnd,
				})

				switch vp.severity {
				case "critical":
					hasCritical = true
				case "high":
					hasHigh = true
				}

				if cfg.maxFindings > 0 && len(findings) >= cfg.maxFindings {
					break
				}
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
		RuleID:     s.ID(),
		RuleName:   s.Name(),
		Stage:      s.Stage(),
		Findings:   findings,
		Confidence: highestConfidence(findings),
		LatencyMs:  time.Since(start).Milliseconds(),
	}

	if len(findings) == 0 {
		eval.Decision = models.DecisionAllow
		eval.Reason = fmt.Sprintf("scanned %d code block(s), no vulnerabilities found", len(blocks))
	} else if (hasCritical && cfg.blockOnCritical) || (hasHigh && cfg.blockOnHigh) {
		eval.Decision = models.DecisionBlock
		eval.Reason = fmt.Sprintf("detected %d vulnerability/vulnerabilities in generated code (%d code block(s) scanned)",
			len(findings), len(blocks))
	} else {
		eval.Decision = models.DecisionAlert
		eval.Reason = fmt.Sprintf("detected %d potential vulnerability/vulnerabilities in generated code (%d code block(s) scanned)",
			len(findings), len(blocks))
	}

	return eval, nil
}

// ---------------------------------------------------------------------------
// guardrails.ConfigurableRule interface
// ---------------------------------------------------------------------------

// Configure applies dynamic configuration.
// Supported keys:
//   - "block_on_critical" (bool): block when critical findings exist.
//   - "block_on_high" (bool): block when high-severity findings exist.
//   - "max_findings" (int/float64): cap the number of reported findings.
func (s *Scanner) Configure(cfg map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if v, ok := cfg["block_on_critical"]; ok {
		if b, ok := v.(bool); ok {
			s.cfg.blockOnCritical = b
		}
	}
	if v, ok := cfg["block_on_high"]; ok {
		if b, ok := v.(bool); ok {
			s.cfg.blockOnHigh = b
		}
	}
	if v, ok := cfg["max_findings"]; ok {
		switch n := v.(type) {
		case float64:
			s.cfg.maxFindings = int(n)
		case int:
			s.cfg.maxFindings = n
		}
	}

	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// languageMatch checks whether the code block language matches any of the
// allowed languages for a pattern. If blockLang is empty, it matches
// everything (the block's language is unknown).
func languageMatch(blockLang string, allowed []string) bool {
	if blockLang == "" {
		// Unknown language -- be conservative and scan.
		return true
	}
	for _, a := range allowed {
		if blockLang == a {
			return true
		}
	}
	return false
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
	max := 0.0
	for _, f := range findings {
		if f.Confidence > max {
			max = f.Confidence
		}
	}
	return max
}

func truncate(s string, maxLen int) string {
	runes := []rune(s)
	if len(runes) <= maxLen {
		return s
	}
	return string(runes[:maxLen]) + "..."
}
