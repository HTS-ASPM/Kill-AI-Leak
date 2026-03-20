// Package scanner provides security scanning for repositories and
// dependencies, detecting prompt injection payloads, hidden instructions,
// exfiltration URLs, and supply-chain attacks.
package scanner

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/kill-ai-leak/kill-ai-leak/pkg/models"
)

// ScanFinding represents a single security issue found by the scanner.
type ScanFinding struct {
	File       string          `json:"file"`
	Line       int             `json:"line"`
	Column     int             `json:"column,omitempty"`
	Type       string          `json:"type"`
	Severity   models.Severity `json:"severity"`
	Message    string          `json:"message"`
	Snippet    string          `json:"snippet,omitempty"`
	Confidence float64         `json:"confidence"`
}

// ScanResult aggregates findings from scanning a file or repository.
type ScanResult struct {
	Path     string        `json:"path"`
	Findings []ScanFinding `json:"findings"`
	Errors   []string      `json:"errors,omitempty"`
}

// HasFindings returns true if any findings were produced.
func (r *ScanResult) HasFindings() bool {
	return len(r.Findings) > 0
}

// MaxSeverity returns the highest severity among all findings.
func (r *ScanResult) MaxSeverity() models.Severity {
	priority := map[models.Severity]int{
		models.SeverityInfo:     0,
		models.SeverityLow:      1,
		models.SeverityMedium:   2,
		models.SeverityHigh:     3,
		models.SeverityCritical: 4,
	}

	max := models.SeverityInfo
	for _, f := range r.Findings {
		if priority[f.Severity] > priority[max] {
			max = f.Severity
		}
	}
	return max
}

// Known agent instruction files that could contain prompt injection.
var agentInstructionFiles = map[string]bool{
	".cursorrules":                   true,
	".cursorrc":                      true,
	"agents.md":                      true,
	"claude.md":                      true,
	".claude":                        true,
	"copilot-instructions.md":        true,
	".aider.conf.yml":               true,
	".aider.input.history":          true,
	".github/copilot-instructions.md": true,
}

// Patterns for detecting prompt injection in code and config files.
var (
	// Exfiltration URL patterns.
	reExfilURL = regexp.MustCompile(`(?i)(https?://[^\s"'` + "`" + `]+\.(ngrok|burpcollaborator|oastify|requestbin|hookbin|pipedream|webhook\.site|canarytokens)\.[^\s"'` + "`" + `]*)`)

	// Suspicious URL patterns (data exfiltration via query params).
	reDataExfilURL = regexp.MustCompile(`(?i)https?://[^\s"'` + "`" + `]*\?[^\s"'` + "`" + `]*(password|secret|token|key|api_key|apikey|credentials|ssn|credit_card)=`)

	// Base64 encoded payloads in comments or strings.
	reBase64Block = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)

	// Injection markers commonly used in prompt injection payloads.
	reInjectionMarkers = regexp.MustCompile(`(?i)(ignore\s+(previous|above|all)\s+(instructions?|prompts?|rules?)|you\s+are\s+now|system\s*:\s*you|new\s+instructions?\s*:|forget\s+(everything|previous|all)|disregard\s+(previous|above|all)|override\s+(previous|system)|act\s+as\s+(if|a|an)\b|pretend\s+you\s+are|do\s+not\s+follow|bypass\s+(safety|security|filter)|jailbreak|DAN\s+mode)`)

	// Hidden instruction patterns in markdown/comments.
	reHiddenInstruction = regexp.MustCompile(`(?i)(<!--\s*(system|instruction|prompt|hidden|secret)[^>]*-->|/\*\s*(system|instruction|prompt|hidden|secret)[^*]*\*/|#\s*(HIDDEN|SECRET|SYSTEM)\s*:)`)

	// Secret patterns in code.
	reSecrets = regexp.MustCompile(`(?i)(AKIA[0-9A-Z]{16}|ghp_[0-9a-zA-Z]{36}|sk-[a-zA-Z0-9]{20,}|AIza[0-9A-Za-z\-_]{35}|xox[bpsa]-[0-9a-zA-Z\-]+|-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----)`)

	// Encoded command injection patterns.
	reEncodedCmd = regexp.MustCompile(`(?i)(eval\s*\(\s*atob|eval\s*\(\s*Buffer\.from|exec\s*\(\s*decode|\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){3,}|\\u[0-9a-fA-F]{4}(\\u[0-9a-fA-F]{4}){3,})`)

	// Tool abuse patterns specific to coding agents.
	reToolAbuse = regexp.MustCompile(`(?i)(run_terminal_cmd|execute_command|write_to_file|read_file)\s*[:(].*?(curl|wget|nc\s|bash\s|sh\s|python\s+-c|eval\s)`)
)

// ScanFile scans a single file for prompt injection payloads, secrets,
// exfiltration URLs, hidden unicode, and encoded instructions.
func ScanFile(path string) (*ScanResult, error) {
	result := &ScanResult{
		Path: path,
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", path, err)
	}

	// Skip directories and very large files.
	if info.IsDir() {
		return nil, fmt.Errorf("%q is a directory", path)
	}
	if info.Size() > 10<<20 { // 10 MiB
		result.Errors = append(result.Errors, "file too large, skipping")
		return result, nil
	}

	// Check if this is a known agent instruction file.
	baseName := strings.ToLower(filepath.Base(path))
	relPath := strings.ToLower(path)
	isAgentFile := agentInstructionFiles[baseName]
	if !isAgentFile {
		for pattern := range agentInstructionFiles {
			if strings.HasSuffix(relPath, strings.ToLower(pattern)) {
				isAgentFile = true
				break
			}
		}
	}

	if isAgentFile {
		result.Findings = append(result.Findings, ScanFinding{
			File:       path,
			Line:       0,
			Type:       "agent_instruction_file",
			Severity:   models.SeverityMedium,
			Message:    fmt.Sprintf("Agent instruction file detected: %s. Review for injected instructions.", baseName),
			Confidence: 1.0,
		})
	}

	// Open and scan line by line.
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 256*1024), 1<<20) // up to 1 MiB lines
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		// Check for hidden unicode characters.
		if findings := checkHiddenUnicode(path, lineNum, line); len(findings) > 0 {
			result.Findings = append(result.Findings, findings...)
		}

		// Check for prompt injection markers.
		if loc := reInjectionMarkers.FindStringIndex(line); loc != nil {
			result.Findings = append(result.Findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "prompt_injection",
				Severity:   models.SeverityCritical,
				Message:    "Prompt injection pattern detected",
				Snippet:    truncateSnippet(line, loc[0], 120),
				Confidence: 0.85,
			})
		}

		// Check for hidden instructions in comments.
		if loc := reHiddenInstruction.FindStringIndex(line); loc != nil {
			result.Findings = append(result.Findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "hidden_instruction",
				Severity:   models.SeverityHigh,
				Message:    "Hidden instruction in comment detected",
				Snippet:    truncateSnippet(line, loc[0], 120),
				Confidence: 0.80,
			})
		}

		// Check for exfiltration URLs.
		if loc := reExfilURL.FindStringIndex(line); loc != nil {
			result.Findings = append(result.Findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "exfiltration_url",
				Severity:   models.SeverityCritical,
				Message:    "Potential data exfiltration URL detected",
				Snippet:    truncateSnippet(line, loc[0], 120),
				Confidence: 0.90,
			})
		}

		// Check for data exfil via query params.
		if loc := reDataExfilURL.FindStringIndex(line); loc != nil {
			result.Findings = append(result.Findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "data_exfiltration",
				Severity:   models.SeverityHigh,
				Message:    "URL with sensitive parameter names detected (potential data exfiltration)",
				Snippet:    truncateSnippet(line, loc[0], 120),
				Confidence: 0.75,
			})
		}

		// Check for secrets.
		if loc := reSecrets.FindStringIndex(line); loc != nil {
			result.Findings = append(result.Findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "secret_detected",
				Severity:   models.SeverityHigh,
				Message:    "Potential secret or API key detected",
				Snippet:    redactSnippet(line, loc[0], loc[1]),
				Confidence: 0.85,
			})
		}

		// Check for encoded command injection.
		if loc := reEncodedCmd.FindStringIndex(line); loc != nil {
			result.Findings = append(result.Findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "encoded_injection",
				Severity:   models.SeverityHigh,
				Message:    "Encoded command injection pattern detected",
				Snippet:    truncateSnippet(line, loc[0], 120),
				Confidence: 0.80,
			})
		}

		// Check for tool abuse patterns.
		if loc := reToolAbuse.FindStringIndex(line); loc != nil {
			result.Findings = append(result.Findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "tool_abuse",
				Severity:   models.SeverityCritical,
				Message:    "Agent tool abuse pattern detected (tool call with shell command)",
				Snippet:    truncateSnippet(line, loc[0], 120),
				Confidence: 0.90,
			})
		}

		// Check for suspicious base64 blocks (only in agent instruction files
		// or markdown to reduce false positives).
		if isAgentFile || isMarkdownOrConfig(path) {
			if findings := checkBase64Payloads(path, lineNum, line); len(findings) > 0 {
				result.Findings = append(result.Findings, findings...)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("scan error: %v", err))
	}

	return result, nil
}

// ScanRepo scans an entire repository directory for injection vectors.
// It prioritizes known agent instruction files and then scans source files.
func ScanRepo(dir string) (*ScanResult, error) {
	result := &ScanResult{
		Path: dir,
	}

	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat %q: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%q is not a directory", dir)
	}

	// Walk the directory tree.
	err = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
			return nil // continue walking
		}

		// Skip hidden directories (except specific ones we care about).
		if fi.IsDir() {
			base := filepath.Base(path)
			if strings.HasPrefix(base, ".") && base != ".github" && base != ".cursor" && path != dir {
				return filepath.SkipDir
			}
			// Skip common non-source directories.
			switch base {
			case "node_modules", "vendor", "__pycache__", ".git", "dist", "build":
				return filepath.SkipDir
			}
			return nil
		}

		// Skip binary files and very large files.
		if fi.Size() > 10<<20 {
			return nil
		}
		if isBinaryExtension(path) {
			return nil
		}

		// Scan the file.
		fileResult, err := ScanFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", path, err))
			return nil
		}

		result.Findings = append(result.Findings, fileResult.Findings...)
		result.Errors = append(result.Errors, fileResult.Errors...)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walk %q: %w", dir, err)
	}

	return result, nil
}

// checkHiddenUnicode detects invisible Unicode characters that could be used
// to hide instructions from human reviewers while being visible to LLMs.
func checkHiddenUnicode(path string, lineNum int, line string) []ScanFinding {
	var findings []ScanFinding

	for i, r := range line {
		if isHiddenUnicode(r) {
			findings = append(findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     i + 1,
				Type:       "hidden_unicode",
				Severity:   models.SeverityHigh,
				Message:    fmt.Sprintf("Hidden Unicode character U+%04X detected (may hide instructions from human review)", r),
				Snippet:    truncateSnippet(line, i, 80),
				Confidence: 0.95,
			})
		}
	}

	return findings
}

// isHiddenUnicode returns true for Unicode characters that are invisible or
// misleading in typical code editors.
func isHiddenUnicode(r rune) bool {
	// Zero-width characters.
	switch r {
	case '\u200B', // zero-width space
		'\u200C', // zero-width non-joiner
		'\u200D', // zero-width joiner
		'\u200E', // left-to-right mark
		'\u200F', // right-to-left mark
		'\u2060', // word joiner
		'\u2061', // function application
		'\u2062', // invisible times
		'\u2063', // invisible separator
		'\u2064', // invisible plus
		'\uFEFF', // byte order mark (when not at start)
		'\u00AD', // soft hyphen
		'\u034F', // combining grapheme joiner
		'\u061C', // arabic letter mark
		'\u115F', // hangul choseong filler
		'\u1160', // hangul jungseong filler
		'\u17B4', // khmer vowel inherent aq
		'\u17B5': // khmer vowel inherent aa
		return true
	}

	// Bidirectional control characters (can reorder text display).
	if r >= '\u202A' && r <= '\u202E' {
		return true
	}
	if r >= '\u2066' && r <= '\u2069' {
		return true
	}

	// Tag characters (used in Unicode tag sequences).
	if r >= '\U000E0001' && r <= '\U000E007F' {
		return true
	}

	// Variation selectors (can modify appearance of preceding characters).
	if r >= '\uFE00' && r <= '\uFE0F' {
		return true
	}

	// Other invisible formatting characters.
	if unicode.Is(unicode.Cf, r) && !unicode.IsPrint(r) && r != '\t' && r != '\n' && r != '\r' {
		return true
	}

	return false
}

// checkBase64Payloads looks for base64-encoded strings that decode to
// suspicious content.
func checkBase64Payloads(path string, lineNum int, line string) []ScanFinding {
	var findings []ScanFinding

	matches := reBase64Block.FindAllStringIndex(line, 5) // limit to 5 per line
	for _, loc := range matches {
		encoded := line[loc[0]:loc[1]]

		// Try to decode.
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			// Try URL-safe encoding.
			decoded, err = base64.URLEncoding.DecodeString(encoded)
			if err != nil {
				continue
			}
		}

		// Check if decoded content is valid UTF-8 text.
		if !utf8.Valid(decoded) {
			continue
		}

		decodedStr := string(decoded)

		// Check decoded content for injection patterns.
		if reInjectionMarkers.MatchString(decodedStr) {
			findings = append(findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "base64_injection",
				Severity:   models.SeverityCritical,
				Message:    "Base64-encoded prompt injection payload detected",
				Snippet:    truncateSnippet(decodedStr, 0, 120),
				Confidence: 0.95,
			})
		}

		// Check for exfiltration URLs in decoded content.
		if reExfilURL.MatchString(decodedStr) {
			findings = append(findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "base64_exfil_url",
				Severity:   models.SeverityCritical,
				Message:    "Base64-encoded exfiltration URL detected",
				Snippet:    truncateSnippet(decodedStr, 0, 120),
				Confidence: 0.90,
			})
		}

		// Check for shell commands in decoded content.
		if reToolAbuse.MatchString(decodedStr) {
			findings = append(findings, ScanFinding{
				File:       path,
				Line:       lineNum,
				Column:     loc[0] + 1,
				Type:       "base64_command",
				Severity:   models.SeverityHigh,
				Message:    "Base64-encoded command payload detected",
				Snippet:    truncateSnippet(decodedStr, 0, 120),
				Confidence: 0.85,
			})
		}
	}

	return findings
}

// isMarkdownOrConfig checks if a file is a markdown or configuration file
// that might contain agent instructions.
func isMarkdownOrConfig(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".md", ".markdown", ".yml", ".yaml", ".toml", ".json", ".txt", ".cfg", ".ini", ".conf":
		return true
	}
	return false
}

// isBinaryExtension returns true for file extensions that are known binary formats.
func isBinaryExtension(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".exe", ".dll", ".so", ".dylib", ".bin", ".obj", ".o", ".a",
		".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
		".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac",
		".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar",
		".wasm", ".pyc", ".class", ".jar", ".war",
		".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
		".ttf", ".otf", ".woff", ".woff2", ".eot",
		".db", ".sqlite", ".sqlite3":
		return true
	}
	return false
}

// truncateSnippet extracts a snippet around a match position.
func truncateSnippet(line string, pos int, maxLen int) string {
	if len(line) <= maxLen {
		return line
	}

	start := pos - maxLen/4
	if start < 0 {
		start = 0
	}

	end := start + maxLen
	if end > len(line) {
		end = len(line)
	}

	snippet := line[start:end]
	if start > 0 {
		snippet = "..." + snippet
	}
	if end < len(line) {
		snippet = snippet + "..."
	}

	return snippet
}

// redactSnippet shows context around a secret but redacts the actual value.
func redactSnippet(line string, matchStart, matchEnd int) string {
	if matchEnd > len(line) {
		matchEnd = len(line)
	}

	// Show a few characters of the match then redact.
	prefixLen := 4
	if matchEnd-matchStart < prefixLen {
		prefixLen = matchEnd - matchStart
	}

	prefix := line[matchStart : matchStart+prefixLen]
	redacted := prefix + "****"

	// Context before match.
	ctxStart := matchStart - 20
	if ctxStart < 0 {
		ctxStart = 0
	}
	before := line[ctxStart:matchStart]

	// Context after match.
	ctxEnd := matchEnd + 20
	if ctxEnd > len(line) {
		ctxEnd = len(line)
	}
	after := line[matchEnd:ctxEnd]

	return before + redacted + after
}
